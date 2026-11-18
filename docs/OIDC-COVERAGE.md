# Keycloak OIDC 신원과 미등록 경로 통제

2026-11-08. 선택 `oidc-jwt-rs256-v1`은 실제 OIDC access token을 Go edge와 Python SDK가 각각 검증하고, 기존 `session-snapshot-v1`의 앱 세션·ACL snapshot에 연결한다. 선택 route coverage는 SDK 등록 또는 명시한 앱 예외에 없는 요청을 upstream 이전에 거부한다. 기본 lab 설정과 실행 중인 서비스를 자동 전환하지 않는다.

## 고정한 신원 계약

Keycloak을 기준으로 RS256 access token만 받는다. issuer, API audience, authorized client(`azp`), public RSA keys와 안정적인 `sub` → 앱 principal/tenant 매핑을 운영자가 고정한다. JWT의 서명된 tenant claim도 이 매핑과 같아야 한다. 사용자명·email·JWT role을 앱 권한으로 자동 변환하지 않는다.

- JWT는8192bytes, header768bytes/payload6144bytes/JSON32단계, 공개키1–8개(RSA2048–4096bits), 매핑1–256개로 제한한다.
- `alg=RS256`, header `typ=JWT`, payload `typ=Bearer`, `iss/aud/azp/sub/tenant/iat/exp/jti/sid`를 확인한다. 유효기간 상한은 설정한1–600초다. `exp`·`nbf`의 유효기간을 늘리는 leeway는 없고 `iat`의 미래 오차만 최대5초다.
- `jti/sid`는 Keycloak의 `onrtac:` 형식을 포함한128자 이내의 제한된 opaque ID다. 서명 검증에는 [golang-jwt v5.3.1](https://github.com/golang-jwt/jwt/releases/tag/v5.3.1)과 [PyJWT2.15.1](https://pypi.org/project/PyJWT/2.15.1/)을 사용한다.
- 동적 `jku/x5u/crit`·추가 header, 미등록 kid, HMAC/unsigned token, ID token, 중복 JSON/잘못된 타입·과도한 깊이는 거부한다. 요청 처리 중 discovery/JWKS/사용자 조회를 호출하지 않는다.
- HTTP issuer는 명시적 literal loopback 개발 주소만 지원하고, 그 밖에는 HTTPS를 요구한다. 키 갱신은 준비 도구와 운영자 검토 후 재시작으로 적용한다.

공개 설정의 canonical SHA-256을 registry의 `identity_config_sha256`에 넣는다. SDK도 같은 pin을 요구한다. registry 한 개에 lab/OIDC adapter를 혼합하거나 OIDC를 세션 없는 `snapshot-v1`에 연결할 수 없다. OIDC 설정이 없거나 pin이 다르면 기동/요청을 거부하며 lab HMAC으로 fallback하지 않는다. 기존 lab manifest에는 새 필드가 없으므로 원래 digest와 원장을 읽는다. 새 OIDC 명세는 이를 지원하는 최신 edge·SDK를 함께 사용해야 한다.

## 공개 설정 준비

Keycloak의 API audience와 `ra_tenant` mapper, 앱 client를 설정하고, 승인한 사용자 UUID를 앱 principal/tenant에 연결한 `subjects.json`을 준비한다. [Keycloak 서버 관리 문서](https://www.keycloak.org/docs/latest/server_admin/)를 참고한다.

```json
{
  "KEYCLOAK_USER_UUID": {"principal":"alice","tenant":"tenant-one"}
}
```

준비 도구는 discovery의 issuer와 동일 origin/issuer 경로 아래 JWKS만 한 번 읽는다. redirect·private JWK를 거부하고, 결과를 새 파일로만 쓴다. private key·client secret·token은 요구하지 않는다.

```powershell
python -B tools/prepare_oidc.py `
  --issuer https://login.example.com/realms/my-realm `
  --audience reverse-artex --client-id reverse-artex-console `
  --subjects subjects.json --out config.oidc.local.json
```

출력 SHA를 [OIDC registry 예제](../config.oidc.protection.example.json)에 넣고 asset·tenant·SDK Ed25519 공개키와 실제 객체 경로를 설정한다. 각 객체 경로의 resolver는 `session-snapshot-v1`이다. [공개 신원 예제](../config.oidc.example.json)의 placeholder를 그대로 운영 설정으로 사용할 수 없다.

```powershell
.\bin\policy-edge.exe -asset my-app `
  -protection-registry config.oidc.protection.local.json `
  -oidc-config config.oidc.local.json -protection-check
```

SDK의 `Guard`에는 기존 asset/registry/route/키 설정에 아래 항목을 추가한다. 준비한 파일을 `OIDCVerifier.from_json`으로 읽으면 중복 JSON도 검산한다.

```python
import json
from reverse_artex_guard import Guard
from reverse_artex_guard.oidc import OIDCVerifier

raw = oidc_config_path.read_bytes()
identity = OIDCVerifier.from_json(raw)
# Guard(...,
#     identity_key=b"", oidc_config=json.loads(raw),
#     identity_config_sha256=identity.digest,
#     resolver_version="session-snapshot-v1")
```

SDK HTTP 진입점은 기존 `serve_application_read`다. resolver에 전달하는 credential SHA는 원래 access token의 SHA-256이고, principal/tenant는 고정한 sub 매핑 결과다. 앱의 기존 OIDC 로그인/refresh callback이 현재 세션을 관리하고, resolver는 같은 DB snapshot에서 폐기·만료·주체 일치 후 ACL/payload를 읽는다. [세션 계약](SESSION-ADAPTER.md)을 따른다. OIDC profile에서는 `LAB_IDENTITY_KEY`를 요구하지 않으며 `LAB_HMAC_KEY`(주체/객체 가명화)와 private ingress credential은 계속 필요하다.

이 기능은 API access-token 검증 adapter다. 브라우저 callback/PKCE와 앱 session·IdP logout/backchannel 연결은 별도 [브라우저 SSO SDK](BROWSER-SSO.md)를 사용한다. console·관리 API SSO와 token introspection은 제공하지 않는다. 앱 세션 폐기는 즉시 반영하며, IdP의 access-token 폐기를 offline 검증만으로 즉시 알아내지 않는다. 키 변경·tenant/subject 매핑 변경은 registry digest를 바꾸므로 SDK pin과 trust epoch·전용 v2 state를 함께 검토한다. 이전 원장을 다른 권한 계약으로 자동 변환하지 않는다.

## 미등록 경로 통제

[coverage 예제](../config.route-coverage.example.json)의 `registry_digest`를 위 검사에서 얻은 정확한 값으로 고정한다. 이 profile은 registry의 모든 객체 경로가 enforce일 때만 받는다. 객체 경로는 registry에서 가져오며, `unprotected_routes`에는 앱이 직접 처리할 **정확한 경로·method·query 정책·근거**만 둔다. 예외는 최대64개이며 wildcard·중복·SDK 경로 family와의 겹침을 거부한다. query 정책은 `allow` 또는 `deny`이고 후자는 빈 `?`도 거부한다. 예외에 GET을 적는 것으로 HEAD가 자동 허용되지 않는다.

```powershell
.\bin\policy-edge.exe -asset my-app `
  -protection-registry config.oidc.protection.local.json `
  -oidc-config config.oidc.local.json `
  -route-coverage config.coverage.local.json -protection-check
```

검사 인자를 빼고 기존 운영용 endpoint·credential·저장 옵션을 지정하면 실행한다. 명시한 coverage가 있을 때 SDK/앱 예외 밖은404, malformed protected family/URI는400이다. `/healthz`는 query 없는 GET/HEAD의 로컬 liveness로 분류한다. 경로 정책의 동기 감사가 실패하면503이고 SDK나 앱에 전달하지 않는다. coverage 감사·신원 검증 시간도 원래5초 요청 예산에 포함하며, 기한이 지난 뒤 SDK로 전달하지 않는다. 동기 디스크 작업 자체를 물리적으로 취소한다는 보장은 아니다.

`-route-coverage`가 없으면 기존 일반 proxy 경로를 유지한다. 새 profile을 켤 때 실제 앱의 정상 경로를 모두 검토해야 한다. 미등록 경로를 거부하는 것으로 그 경로의 정상 업무까지 지원하게 되는 것은 아니다. 앱 예외는 SDK proof로 보호되지 않으며 기존 앱의 인증·권한·검색/쓰기 계약이 계속 담당한다.

private `/v1/status`의 `route_coverage`는 등록 SDK 경로·명시적 앱 예외·기본 deny·현재 프로세스의 분류 counter·마지막 감사 상태를 보여준다. `sdk_route_admitted` 등은 경로 정책 분류이며 후속 인증/기한/증명·실제200 수신을 뜻하지 않는다. counter는 재시작하면0부터 시작한다. 실제 path·query·credential은 저장하지 않고 trusted request ID·method·path HMAC·query 유무·고정 route ID만 별도 회전 감사에 기록한다. 감사 저장 예산은64MiB/파일8MiB이며 기존 다른 저장 예산과 독립이다. 동적 route discovery나 앱 전체의 보호율을 자동 계산하지 않는다.


## 검증

소스에서 SDK 의존성을 설치한 뒤 공개 합성 단위 테스트를 실행할 수 있습니다. 실제 배포의 신원 공급자와 저장소, 서비스 종료 동작은 해당 환경에서 확인하세요. [테스트 안내](../CONTRIBUTING.md)
