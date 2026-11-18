# 브라우저 SSO 로그인·로그아웃

후속: [암호화 공유 browser state](SHARED-BROWSER-STATE.md)는 같은 호스트의 worker 간 transaction/session·logout 기록과 재시작 재개를 추가한다. 아래 실제 브라우저 검증은 기본 memory 모드의 기존 수용이며 분모를 유지한다.

2026-11-08: Keycloak Authorization Code/S256 PKCE를 업무 앱의 기존 세션 DB와 연결했다. 로그인된 브라우저의 읽기는 BFF → private Go edge → SDK → 기존 앱 세션·객체 ACL 순서로 처리한다. 재사용 모듈은 `sdk/python/reverse_artex_guard/browser_sso.py`, ID/logout 토큰 검증은 `browser_tokens.py`다. 실행 예제 `sdk/python/examples/browser_sso_gateway.py`는 한국어 로그인·객체 읽기·로그아웃 화면을 제공한다.

## 연결 계약

- `/auth/login`: 256-bit state·nonce·PKCE verifier와 별도 브라우저 transaction cookie를 만든다. 콜백 URL은 설정 origin의 `/auth/callback` 하나로 고정한다. transaction은 5분·1회이고 기본 1,024개로 제한한다.
- `/auth/callback`: state와 HttpOnly cookie의 결합, code 교환, issuer·RS256 공개키·client audience·nonce·sub·sid·발급/만료 시각을 검사한다. 존재하는 `at_hash`/`c_hash`도 대조한다. API access token은 기존 OIDC verifier의 audience·tenant·stable sub 매핑을 별도로 통과해야 한다. 잘못된 ID token을 API token으로 쓰지 않는다.
- 검증 후 lifecycle이 `SHA256(access_token), principal, tenant, exp`를 앱의 현재 세션 저장소에 기록한다. 성공한 다음에만 무작위 browser cookie를 발급하고 기존 cookie/session은 교체한다. 브라우저 API에는 principal·tenant·만료·CSRF만 반환한다. access token과 PKCE verifier는 브라우저 저장소에 전달하지 않는다.
- `/auth/session`: 현재 cookie와 앱 DB의 세션·신원·만료를 확인한다. 앱에서 digest를 폐기하면 다음 읽기부터 거부한다. 인증되지 않은 객체 읽기는 401, DB/IdP 통신 등 처리 불가 상태는 503이다.
- `/auth/logout`: POST + 정확한 Origin + session CSRF가 필요하다. 앱 digest를 먼저 삭제하고 cookie를 지운 다음, Keycloak logout endpoint로 POST한다. `id_token_hint`는 이 제한된 logout form에서만 사용하며 URL query에 넣지 않는다. `/auth/logged-out`의 1회 state·cookie 검증 후 루트로 복귀한다.
- `/auth/backchannel-logout`: issuer·RS256·client audience·60초 이내 iat·jti·logout event·nonce 부재와 sub/sid를 검증한다. 일치하는 현재 세션의 digest를 DB에서 삭제한다. 재전송 jti는 거부하고, 제한된 tombstone으로 진행 중인 callback이 같은 IdP session을 다시 설치하지 못하게 한다. DB 폐기가 실패하면 성공 응답을 보내지 않는다.

기존 세션/ACL resolver는 그대로 유지한다. lifecycle은 `create(digest, principal, tenant, expires)`, `active(digest, principal, tenant, now)`, `revoke(digests)`를 구현해야 한다. 예제 `sqlite_browser_sessions.py`는 검증한 기존 lab의 `sessions(digest,principal,tenant,expires)` schema에만 적용하며 객체·ACL을 변경하지 않는다. 실제 앱에는 그 앱의 신뢰할 수 있는 DB transaction 어댑터를 제공한다.


추가 backend: [SQLite native ACL profile](SQLITE-NATIVE-ACL.md)의 `SQLiteApplicationStore`도 이 lifecycle을 구현한다. 이미 준비한 native DB는 예제의 `--database-profile sqlite-native-acl/1`로 선택한다. 기본은 기존 `legacy-session-v1`이며 자동 schema 변경은 하지 않는다. 객체 handler에는 해당 profile의 `SQLiteApplicationResolver`를 별도로 연결한다.

## 실행

[OIDC 신뢰 설정](OIDC-COVERAGE.md)과 동일한 public config를 BFF·edge·SDK에 고정한다. edge의 registry는 `oidc-jwt-rs256-v1` + `session-snapshot-v1`, modern/legacy 전체 enforce와 정확한 coverage로 준비한다. 브라우저의 공개 진입점은 BFF이며 앱·edge·management listener는 private으로 둔다. BFF는 브라우저가 주는 Authorization·RA/ingress 헤더를 거부하고 고정된 private edge에 서버 소유 access token만 전달한다. upstream redirect·cookie·proof 헤더는 브라우저로 전달하지 않는다.

Keycloak client에 다음을 정확히 등록한다.

| 설정 | 값 |
| --- | --- |
| Standard flow | 활성화, PKCE method S256 |
| Direct access grants | 비활성화 |
| Valid redirect URI | `https://app.example/auth/callback` |
| Valid post logout redirect URI | `https://app.example/auth/logged-out` |
| Backchannel logout URL | `https://app.example/auth/backchannel-logout` |
| Backchannel logout session required | 활성화 |
| API custom audience | OIDC config의 `audience` |
| tenant claim / stable sub | 동일한 OIDC pin·매핑 |

SDK의 `pyproject.toml`에 고정한 의존성을 설치한 Python 환경에서 제품 폴더를 기준으로 실행한다. DB는 기존 앱의 schema가 이미 있어야 한다. 예제는 loopback listener와 명시적으로 허용한 객체 GET/HEAD·검색 GET/HEAD 전달만 제공한다. edge coverage에 method가 없으면 해당 요청은 edge에서 거부된다.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'sdk/python'
python -B sdk/python/examples/browser_sso_gateway.py --identity-config config.oidc.local.json --public-origin https://app.example --edge-origin http://127.0.0.1:9082 --database data/app.db --listen 127.0.0.1:9083
```

confidential client는 별도 환경 변수에 주입한 client secret을 `--client-secret-env RA_SSO_CLIENT_SECRET`으로 참조한다. 코드 교환의 client 인증 방식은 `client_secret_post`다. CLI 인자·공개 config에 비밀값을 넣지 않는다. literal loopback 개발 환경에서만 HTTP origin을 허용하며 이때 public origin의 port와 listener가 일치해야 한다. HTTPS 공개 origin은 TLS reverse proxy를 거쳐 정확한 Host를 유지하도록 연결한다. forwarded Host/Origin으로 신뢰 설정을 추정하지 않는다.

HTTPS browser cookie는 `__Host-` prefix, Secure·HttpOnly·SameSite=Lax·Path=/를 사용한다. callback·auth 응답은 no-store·no-referrer다. 루트 화면은 same-origin Referrer 정책으로 같은 출처 POST의 Origin을 보존한다. logout form CSP는 고정한 IdP origin과 등록한 앱 복귀 origin만 허용한다. IdP 로그아웃 실패 여부와 별개로 먼저 성공한 로컬 DB 폐기는 유지된다.


## 적용 범위

기본 모드는 단일 프로세스·메모리 browser session이며 API token 만료(최대 600초)를 넘어 session을 연장하지 않는다. refresh token은 보관하거나 사용하지 않는다. 만료 후에는 로그인 흐름으로 재진입한다. 재시작하면 모든 browser cookie가 무효가 되고 기존 앱 digest는 token 만료까지 남을 수 있다. private ingress를 공개하거나 이 계층을 우회해 browser bearer를 받는 구조로 배치하지 않는다.

동일 호스트의 표준 native SQLite worker는 후속 [공유 저장소](SHARED-BROWSER-STATE.md)를 선택할 수 있다. 다른 호스트/다른 lifecycle의 replica에는 별도 공유 backend와 원자적 연동이 필요하다. backchannel은 등록한 현재 프로세스와 매핑된 sub/sid에 적용하며 모든 앱의 전역 session 폐기를 추정하지 않는다. 제공자 접근 불가·키 회전은 기존 bounded offline verifier의 제한을 따른다. 실제 배포 TLS/네트워크·운영 계정·다중 브라우저/replica 수용은 별도 환경에서 검증한다.

이것은 업무 앱의 선택 browser SSO SDK다. 제품 운영 콘솔·관리 API는 기존 로컬 접속 키를 사용하고, 일반 앱 사용자에게 운영자 권한을 부여하지 않는다. 예제의 임의 쓰기·기존 앱 login/refresh·관리 경로를 자동 proxy하지 않는다.

구현 기준은 [OIDC ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation), [S256 PKCE](https://www.rfc-editor.org/rfc/rfc7636), [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)다. 선택한 Keycloak profile과 위에서 확인한 수용 범위를 구분한다.
