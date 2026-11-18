# 공유·영속 브라우저 SSO 상태

후속: [워커 준비 상태·종료 drain](BROWSER-WORKER-RUNTIME.md)은 로컬 health/readiness와 진행 중 요청 대기·timeout 구분을 추가한다. 운영 LB/TLS·부하 수용은 별도다.
후속: [명시적인 키 회전·상태 이관](BROWSER-STATE-MIGRATION.md)은 준비된 신·구 키의 epoch 전환과 원자적인 context 이관을 추가한다. 아래 초기 수용 기록의 분모는 그대로 유지한다.
2026-11-08. `sqlite-browser-state/1`은 같은 호스트에서 실행되는 BFF worker들이 로그인 transaction·browser session·backchannel tombstone·jti 중복 기록을 공유하는 선택 backend다. 성공한 cookie session과 아직 소비되지 않은 로그인 transaction은 worker 종료·재시작 뒤에도 기존 만료 시각까지 이어진다. refresh나 token lifetime 연장은 추가하지 않았다.

구현은 [`sqlite_browser_state.py`](../sdk/python/reverse_artex_guard/sqlite_browser_state.py)와 `BrowserSSO(..., state_store=...)`다. 기본 메모리 모드는 유지한다. 공유 모드는 [native SQLite 앱 profile](SQLITE-NATIVE-ACL.md)의 표준 `SQLiteApplicationStore`와 **동일한 DB 파일**을 사용한다. 임의 lifecycle/subclass를 받아 그 앱의 추가 session 검사를 우회하지 않는다. 다른 ORM·schema나 여러 DB 사이의 원자 연동은 별도 adapter 계약이다.

## 영속화와 원자성

| 상태 | 처리 |
| --- | --- |
| 로그인 transaction | state·binding·nonce·PKCE verifier를 암호화, 5분 TTL, code 교환 전에 단회 소비 commit |
| browser session | cookie lookup, 검증된 identity·access/ID token·CSRF·만료를 암호화, 앱 credential digest와 연결 |
| logout return transaction | 어느 worker에서도 state/cookie를 한 번 검증·소비 |
| backchannel jti | DB에서 중복 검사·폐기와 함께 commit, 다른 worker/재시작에도 유지 |
| sub/sid tombstone | 진행 중 callback의 재설치를 막으며 공유 session read에서도 확인 |

`BEGIN IMMEDIATE`가 worker 간 상태 변경을 직렬화한다. callback의 이전 session 폐기·새 앱 digest·암호화 browser row는 한 transaction이다. logout의 반환 state·앱 digest 삭제·browser row 삭제, backchannel의 session 폐기·jti·tombstone도 각각 한 transaction이다. DB/암호화/제약 오류는 전체 rollback하며 nested 처리의 오류를 잡았더라도 바깥 unit을 commit하지 않는다.

code 교환 HTTP는 DB transaction 밖에서 수행한다. 그 전에 state 소비는 commit되므로 동시에 요청한 두 worker가 같은 code를 교환하지 않는다. 소비 후 token 교환이나 worker가 실패한 경우에는 그 state를 재사용하지 않고 새 로그인으로 시작한다. 다른 worker의 backchannel이 교환 중 commit되면 callback의 설치 단계에서 tombstone을 확인해 거부한다.

공유 모드의 `close()`는 해당 worker만 닫으며 다른 worker의 session을 폐기하지 않는다. 메모리 모드의 종료 폐기 동작은 기존 그대로다. 매 session 조회는 같은 unit 안에서 앱의 현재 digest·principal·tenant·만료도 읽으므로 앱에서 폐기한 세션을 캐시로 되살리지 않는다.

## 저장 보호와 수용 한도

32-byte 외부 master key와 DB별 무작위 salt를 HKDF-SHA256에 넣어 AES-256-GCM과 lookup HMAC용 키를 분리한다. 각 row의 종류·lookup key·expiry·credential digest·신뢰 context를 AAD에 묶는다. cookie/state/jti/revocation lookup key는 HMAC이고 원문 key와 값은 암호문 안에 둔다. DB에는 master key를 저장하지 않는다. 암호문·row 바꾸기·expiry 조작은 해당 row를 인증할 때 거부한다. 앱 DB의 기존 credential SHA·principal·tenant나 expiry metadata를 숨기는 프로필은 아니다.

12-byte 암호화 nonce는 CSPRNG로 만들고 현재 row/key-check와의 중복을 거부한다. 한 state epoch의 암호화 write는 10억 회로 제한한다. 기본 전역 수용 한도는 session 1,024개·transaction 1,024개·tombstone/jti 각각 2,048개이며 constructor capacity 1–4,096을 모든 worker에서 같게 고정한다. 인증 경로에서는 만료 인덱스로 필요한 row만 정리하며, tombstone은 해당 sub/sid의 고정 lookup으로 확인한다.

신뢰 context에는 canonical OIDC config SHA·공개 origin·capacity가 포함된다. 잘못된 key·context·다른 native DB는 기동을 거부하고, 실행 중 DB busy·손상·metadata 불일치는 503이다. 메모리로 조용히 대체하거나 기존 상태를 다시 초기화하지 않는다.

설계의 암호화 API는 PyCA의 [AES-GCM](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)과 [HKDF](https://cryptography.io/en/50.0.0/hazmat/primitives/key-derivation-functions/#hkdf)를 사용한다. 키가 유출되거나 DB 전체가 과거 상태로 복원되는 공격, 프로세스 메모리 침해를 이 at-rest 암호화로 방지한다고 주장하지 않는다.

## 필수 SQLite runtime

native WAL profile은 **SQLite 3.51.3 이상 또는 수정 backport 3.50.7/3.44.6 이상인 해당 branch**를 요구한다. 초기화 전에 검사해 불일치면 DB를 생성하지 않는다. SQLite 공식 문서가 여러 connection의 write/checkpoint 경쟁에서 드물게 손상될 수 있는 WAL-reset 버그와 수정 버전을 명시한다. [공식 공지](https://www.sqlite.org/wal.html#walreset)를 따른다.

최초 기능 검증은 전역 Python3.14.7/SQLite3.50.4에서 통과했으나 이 운영 조건 대조에서 제외했다. 해당 실행 기록은 보존하고, 최종 수용은 제품 전용 managed CPython3.14.7/SQLite3.53.1에서 다시 수행했다. 전역 Python/DLL·PATH·레지스트리를 변경하거나 DLL을 교체하지 않았다. runtime provenance에 전용 설치·버전·DLL SHA와 전역 원본 SHA를 기록했다.

WAL은 동일 호스트의 로컬 파일을 사용해야 한다. 네트워크 파일시스템이나 다른 호스트의 replica용 backend가 아니다. [SQLite WAL 요구 조건](https://www.sqlite.org/wal.html)을 따른다. 모든 BFF·SDK·앱 writer가 수정된 runtime을 사용해야 한다.

## 실행과 초기화

먼저 native 앱 DB를 명시적으로 준비하고, OIDC pin·public origin·외부 key·capacity를 고정한다. 외부 key는 CSPRNG 32 bytes의 canonical standard base64 값으로 운영 비밀 주입 경로에서 `RA_SSO_STATE_KEY` 환경 변수에 공급한다. config JSON·CLI 인자·DB·log에 원문 key를 넣지 않는다.

gateway의 `--initialize-browser-state`는 지정한 native DB에 두 전용 테이블만 **한 번** 추가한 뒤 종료한다. 기존 object/ACL schema를 자동 migration하지 않는다. 이미 초기화된 DB는 덮어쓰지 않는다. 이후 worker는 같은 key로 open한다.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'sdk/python'
# RA_SSO_STATE_KEY에는 외부 비밀 관리 경로가 생성·주입한 key가 있어야 한다.
$ssoArgs = @('--identity-config', 'config.oidc.local.json', '--public-origin', 'https://app.example', '--edge-origin', 'http://127.0.0.1:9082', '--database', 'data/application-native.db', '--database-profile', 'sqlite-native-acl/1', '--browser-state-key-env', 'RA_SSO_STATE_KEY')
python -B sdk/python/examples/browser_sso_gateway.py @ssoArgs --listen 127.0.0.1:9083 --initialize-browser-state
# 초기화 뒤 각 worker를 별도 프로세스로 실행:
python -B sdk/python/examples/browser_sso_gateway.py @ssoArgs --listen 127.0.0.1:9083
python -B sdk/python/examples/browser_sso_gateway.py @ssoArgs --listen 127.0.0.1:9084
```

공개 HTTPS reverse proxy는 같은 origin을 유지해 두 private listener로 연결하고 정확한 Host를 보존한다. 임의 forwarded Host/Origin으로 신뢰를 추정하지 않는다. 원래 Origin/CSRF·Secure/HttpOnly/SameSite cookie·라우트 allowlist·private edge/SDK 계약을 유지한다. `--browser-state-key-env`가 없으면 원래 메모리 모드이고, 해당 옵션은 native profile에서만 허용한다.

직접 연결하는 앱은 다음과 같이 구성한다. `initialize` 호출은 초기 설치에만 쓰고, worker 재시작은 일반 constructor를 쓴다.

```python
from reverse_artex_guard.oidc import OIDCVerifier
from reverse_artex_guard.browser_sso import BrowserSSO
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState

app = SQLiteApplicationStore(database)
options = dict(identity_digest=OIDCVerifier(oidc).digest, public_origin=public_origin)
# 1회 provisioning: SQLiteBrowserState.initialize(app, external_key_bytes, **options)
state = SQLiteBrowserState(app, external_key_bytes, **options)
sso = BrowserSSO(oidc, public_origin=public_origin, lifecycle=app, state_store=state)
```


## 남은 운영 수용

이 backend는 동일 호스트의 표준 native SQLite lifecycle에 한정된다. 모든 상태 동작이 짧은 write transaction을 사용하며 lock 대기0.1초 뒤503으로 닫힌다. 진행 중 요청의 로컬 drain은 후속 런타임을 따른다. 부하·장기 가용성·실제 LB/TLS·다른 호스트 replica 수용은 별도다.

기존 token 만료를 연장하거나 refresh하지 않는다. 모든 worker가 내려간 동안 수신하지 못한 IdP 폐기를 offline 검증만으로 알아내지 않으며, 다음 만료나 실제 backchannel/앱 폐기가 적용된다. snapshot 뒤 commit된 폐기를 이미 진행 중인 응답에 소급하는 fencing도 추가하지 않았다.

키·OIDC pin·origin·capacity 변경은 자동 state 이관이나 reset을 하지 않는다. 후속 [관리 API/CLI](BROWSER-STATE-MIGRATION.md)가 CAS·작업 ID로 명시적인 키 회전/문맥 이관과 외부 최소 generation을 지원한다. 자동 회전 예약·다중 호스트 저장소와 운영 console SSO는 별도다. 아래 이전 수용은 암호화된 browser 상태 재개와 동일 DB 안의 원자적 session lifecycle 범위다.
