# 공유 SSO 저장소 키 회전·상태 이관

후속: [워커 준비 상태·종료 drain](BROWSER-WORKER-RUNTIME.md)을 사용해 준비된 keyring의 worker만 수용하고 진행 중 요청을 마친 뒤 교체할 수 있다.

같은 호스트의 `sqlite-native-acl/1` 앱 DB에서 암호화된 browser state를 **명시적인 관리 작업**으로 전환한다. 키 회전은 새 master·salt로 AES-GCM 키와 lookup HMAC 키를 모두 바꾸고 모든 레코드를 다시 암호화한다. 상태 이관은 같은 DB의 capacity·OIDC pin·public origin 문맥을 변경한다. DB 파일 복사·다중 호스트 전송·기존 앱 schema 자동 변환은 이 기능의 범위에 포함하지 않는다.

기존 [공유 저장소](SHARED-BROWSER-STATE.md)의 session/transaction/revocation/seen 레코드 형식은 유지한다. 첫 관리 작업은 선택한 DB에 `ra_browser_state_operations` 이력을 명시적으로 추가한다. 기존 generation 0 저장소는 새 SDK로 그대로 열 수 있다. 전환된 key-check 형식을 모르는 이전 SDK는 기동/요청을 거부하므로, 먼저 모든 worker의 SDK를 업데이트한다.

## 원자적 전환 계약

관리 API `reverse_artex_guard.browser_state_migration.transition_browser_state`는 `BEGIN IMMEDIATE` 한 번으로 다음을 수행한다.

1. 현재 key-check·인증된 작업 이력·외부 최소 generation과 `expected_epoch`를 확인한다.
2. 용량 한도 안의 모든 행을 기존 키로 인증·복호화한다. 만료된 행이나 폐기할 행도 먼저 인증하며, 손상된 행을 건너뛰지 않는다.
3. 만료·외부 앱 폐기·현재 tombstone에 해당하는 browser session을 제외하고 그 앱 digest를 폐기한다. 대상 용량에 live state가 들어가지 않으면 실패한다.
4. 새 salt·AES/HMAC 키·행별 nonce로 유지할 상태를 재암호화하고 lookup index를 다시 계산한다. 현재 epoch·작업 이력·필요한 native session 폐기와 함께 commit한다.

어느 단계에서든 실패하면 레코드·metadata·작업 이력·앱 폐기가 함께 rollback한다. 같은 DB의 object/content/ACL/grant/revision과 browser와 무관한 앱 session은 변경하지 않는다. 전환은 유한한 전체 scan이므로 그동안 다른 browser write가 기존 0.1초 lock 한도를 넘으면 503을 반환할 수 있다. 진행 중 SDK 읽기의 이전 snapshot에 이미 허용된 응답을 소급 취소하지 않는다.

`describe()` 또는 `--describe-browser-state`는 인증된 `epoch`·generation·key ID·context·용량·레코드 수만 반환한다. key ID는 domain을 붙인 master SHA-256 식별자이며 키 원문은 아니다. 키·token·cookie·PKCE·CSRF·행의 논리 키를 receipt에 기록하지 않는다. 공개 HTTP 관리 경로는 추가하지 않았다.

## 신·구 키를 준비한 순차 교체

모든 키는 외부 비밀 관리 경로가 생성한 **32바이트 난수**를 canonical base64로 환경변수에 주입한다. CLI에는 환경변수 이름만 넘긴다. 아래 `$python`은 WAL-reset 수정이 포함된 SQLite 런타임을 사용하는 Python이다. 배포에서는 패치 및 버전을 검증한 런타임을 준비한다.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'sdk/python'
$python = (Get-Command python -ErrorAction Stop).Source
$gateway = 'sdk/python/examples/browser_sso_gateway.py'
$ssoArgs = @('--identity-config', 'config.oidc.local.json',
  '--public-origin', 'https://app.example', '--edge-origin', 'http://127.0.0.1:9082',
  '--database', 'data/application-native.db', '--database-profile', 'sqlite-native-acl/1',
  '--browser-state-key-env', 'RA_SSO_STATE_KEY', '--listen', '127.0.0.1:9083')

# 먼저 모든 worker를 새 SDK + 기존 키/다음 키로 순차 재기동한다.
& $python -B $gateway @ssoArgs --browser-state-additional-key-env RA_SSO_STATE_NEXT
# 위 명령은 서버를 실행한다. 관리 명령은 별도 터미널에서 실행한다.
$status = (& $python -B $gateway @ssoArgs --describe-browser-state) | ConvertFrom-Json
$operation = @('--rotate-browser-state', '--browser-state-target-key-env', 'RA_SSO_STATE_NEXT',
  '--expected-state-epoch', $status.epoch, '--state-operation-id', 'rotate-20261108-01')
& $python -B $gateway @ssoArgs @operation
```

서로 다른 private listen port의 worker를 같은 공개 origin의 proxy가 연결해야 한다. 각 worker는 기본 키와 추가 키 최대 3개, 총 4개의 서로 다른 키를 허용한다. 요청마다 현재 epoch를 인증하고 준비한 키로만 전환한다. **기존 키만 가진 worker는 commit 후 503, 새로 기동할 때는 listener 이전 실패**가 된다. 이전 키로 쓰는 경로는 열지 않는다.

동일 context의 기본 `preserve` 회전은 cookie·CSRF·토큰·expiry·소비 전 login/logout transaction·nonce/PKCE·tombstone·jti를 그대로 보존한다. code exchange가 SQL 밖에서 진행 중이어도 준비된 worker는 새 epoch로 설치를 마칠 수 있다. 만료 시간이나 토큰 수명은 연장하지 않는다.

성공 receipt의 generation/epoch를 확인한 뒤 모든 worker를 **새 키만** 사용하도록 다시 기동한다. `--browser-state-key-env RA_SSO_STATE_NEXT --browser-state-minimum-generation <성공 generation>`을 적용하고 추가 구키 환경변수를 제거한다. 예시 `$ssoArgs`에도 기본 키 환경변수 이름을 반영해야 한다. 새 generation을 최소값으로 고정하는 설정은 DB 밖에서 보관한다. 코드가 외부 비밀 관리 서비스의 키를 자동 삭제하지 않는다.

보존 회전은 과거 DB page·WAL·backup의 암호문을 안전 삭제하거나 기존 token을 교체하는 작업이 아니다. 구키 유출에 대응해 현재 browser session까지 폐기할 때는 동일한 회전에 `--state-session-policy revoke`를 지정한다. 이 경우 native browser digest와 진행 중 login/logout transaction을 함께 폐기하고 같은 namespace의 logout 이력은 보존한다.

## 용량·신뢰 문맥 이관

용량 변경은 동일 pin/origin에서 `preserve`를 사용할 수 있다. 현재 master를 유지해도 새 salt와 파생 키로 재암호화한다.

```powershell
# $ssoArgs는 현재 키·현재 capacity·현재 identity/origin을 가리켜야 한다.
$status = (& $python -B $gateway @ssoArgs --describe-browser-state) | ConvertFrom-Json
& $python -B $gateway @ssoArgs --migrate-browser-state `
  --browser-state-target-key-env RA_SSO_STATE_NEXT `
  --expected-state-epoch $status.epoch --state-operation-id capacity-20261108-01 `
  --target-state-capacity 2048
# 이후 모든 worker에 --browser-state-capacity 2048와 새 최소 generation을 적용한다.
```

live session/transaction은 capacity까지, revocation/seen은 각각 capacity의 2배까지 허용한다. 축소 시 이 한도를 초과하면 전체 작업을 거부하며, 오래되지 않은 jti/tombstone을 임의로 버리지 않는다. 정확한 현재 capacity는 `--browser-state-capacity`로 관리 명령에도 전달한다.

OIDC 설정 digest 또는 public origin이 바뀌면 **`--state-session-policy revoke`가 필수**다. `--target-identity-config <JSON>`·`--target-public-origin <origin>`으로 대상을 명시한다. 이관은 browser-owned native session과 진행 중 login/logout transaction을 전부 폐기한다. issuer와 client ID가 같으면 아직 유효한 tombstone/jti를 보존하고, 다른 namespace이면 이전 logout ledger도 명시적으로 버리며 receipt에 수를 남긴다.

문맥 변경 뒤 기존 pin/origin/capacity의 worker는 새 키를 알아도 처리하지 못한다. worker를 대상 설정으로 교체하는 배포 구간을 마련한다. 유지한 소비 전 transaction은 새 문맥 worker가 재개할 수 있지만, 이전 문맥 worker에서 이미 소비하고 외부 교환 중이던 로그인은 다시 시작해야 할 수 있다. 대상 OIDC 설정은 관련 edge/SDK·IdP·proxy에도 별도로 일치시켜야 하며, 이 API가 그 설정이나 앱 ACL을 자동 수정하지 않는다.

## 재시도·충돌·복원

작업 ID는 1..64자 application identifier이고 전체 요청의 digest·source/target epoch·key ID·레코드 수를 이력에 저장한다. 최신 작업의 **같은 ID·같은 요청** 재시도는 인증된 기존 receipt에 `replayed: true`만 붙이며 DB를 다시 쓰지 않는다. 성공 후 구키를 제거했다면 현재 target key를 source keyring에도 사용할 수 있다. 이미 다음 epoch로 넘어간 작업의 재실행, 같은 ID의 다른 요청, stale expected epoch는 거부한다.

관리 프로세스가 commit 이전에 종료되면 SQLite가 전체 작업을 rollback한다. commit은 끝났으나 응답을 잃었을 때는 같은 작업 ID·원래 expected epoch·같은 대상/정책으로 재시도해 결과를 확인한다. 원인을 확인하지 않고 새 작업 ID로 반복 실행하지 않는다. 작업 이력은 최대 128회이며 자동 삭제/초기화하지 않는다. 이전에 사용한 master key ID를 새 회전 대상으로 재활성화하지 않는다.

key-check는 generation·이력 hash·현재 key ID를 암호화 인증하고, 현재 파생 키의 HMAC이 hash chain의 마지막 항목을 인증한다. 작업 이력 행 삭제·이력 변조·동일 generation의 epoch 교체를 거부한다. 일반 상태 행의 삭제까지 탐지하는 전체 DB 무결성 원장은 아니므로 DB 쓰기 권한은 계속 신뢰 경계다. 실행 중 worker는 자신이 본 generation보다 낮은 복원을 거부하며, `minimum_generation`은 재시작 후에도 외부 기준을 적용한다.

전체 DB의 과거 snapshot과 과거 master를 함께 복원하고 모든 worker를 재시작하면서 외부 최소 generation까지 낮추면 이 DB만으로 이전 폐기를 알아낼 수 없다. 복원 정책은 외부 generation 기준·키 폐기·DB 전체의 일관된 backup을 함께 관리해야 한다. 다중 호스트 저장소, 자동 회전 예약, 장기 가용성·운영 IdP/TLS/LB 수용은 별도다.


## 검증

소스에서 SDK 의존성을 설치한 뒤 공개 합성 단위 테스트를 실행할 수 있습니다. 실제 배포의 신원 공급자와 저장소, 서비스 종료 동작은 해당 환경에서 확인하세요. [테스트 안내](../CONTRIBUTING.md)
