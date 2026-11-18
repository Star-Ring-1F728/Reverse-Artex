# SQLite 앱의 ACL·revision 저장소

후속: [공유 browser state](SHARED-BROWSER-STATE.md)는 이 DB의 원자적 session lifecycle과 암호화 상태를 연결한다. native WAL runtime은 SQLite3.51.3+ 또는 수정 backport3.50.7/3.44.6을 요구하며 불일치는 초기화 전에 거부한다.

2026-11-08. 선택 프로필 `sqlite-native-acl/1`은 앱이 직접 사용하는 세션·객체·명시적 grant와 ACL/content revision을 같은 SQLite DB에 저장한다. SDK의 기존 `session-snapshot-v1` 계약·권한 판정·서명 형식은 유지한다. 구현은 [`sqlite_application.py`](../sdk/python/reverse_artex_guard/sqlite_application.py)다.

이 프로필은 기존 앱의 권한을 덮는 별도 권한 DB가 아니다. 앱이 이 명시적 schema와 쓰기 transaction을 채택한 경우에 사용한다. 다른 schema를 사용하는 앱은 그 앱의 세션·ACL 저장소에서 같은 snapshot 계약을 구현해야 한다. 기존 lab DB와 Tester 원본을 자동 이관하거나 변경하지 않는다.

## 저장과 읽기

| 테이블 | 내용 |
| --- | --- |
| `ra_application_schema` | 정확한 프로필 marker |
| `sessions` | credential SHA-256, 검증된 principal·tenant, 만료 |
| `objects` | 전역으로 고유한 opaque ID, tenant·owner, ACL/content revision, JSON payload |
| `object_grants` | 객체 ID·객체 tenant·명시적인 principal grant, 복합 foreign key |

`SQLiteApplicationResolver(database)`는 읽기 전용 URI와 `query_only`, 명시적 transaction으로 세션→객체→grant·revision·payload를 같은 committed snapshot에서 읽는다. 세션 폐기·만료·주체 불일치 때 객체 테이블을 조회하지 않는다. SDK가 같은 tenant의 owner 또는 명시된 principal grant인지 판정하고, 원래 JSON payload만 직렬화·서명한다. 동일한 principal 이름이라도 다른 tenant의 객체를 허용하지 않는다.

객체 ID·주체 ID는 ASCII opaque 1–64자다. grant는 중복 없이 최대 256개이며 정렬해 저장한다. payload는 JSON 1MiB·중첩 32단계·유한한 숫자와 최대 425-bit 정수로 제한한다. resolver는 oversized payload를 SQLite에서 걸러 Python에 materialize하지 않고, 잘못된 revision·tenant가 다른 grant·잘못된 JSON·지원하지 않는 schema나 DB 오류는 SDK 503으로 닫힌다. 객체 없음은 signed404, 무효 세션은 signed401이다.

## 앱의 쓰기 계약

`SQLiteApplicationStore`는 신뢰된 앱 쓰기 코드와 SSO session lifecycle에서 호출한다. 공개 HTTP 쓰기 endpoint나 사용자의 쓰기 권한을 추가하지 않는다. 앱은 호출자의 쓰기를 승인하는 기존 절차를 소유한다.

| 메서드 | 비교하는 현재 상태 | 바꾸는 것 |
| --- | --- | --- |
| `current_revisions` | 신뢰된 writer의 현재 두 revision 조회 | 없음 |
| `create_object` | 같은 ID가 없어야 함 | 객체·grant·두 revision |
| `replace_acl` | `expected_authz_revision` | tenant·owner·전체 grant, ACL revision |
| `replace_content` | `expected_content_revision` | JSON payload, content revision |
| `replace_object` | 두 expected revision | ACL·본문을 한 transaction에서 교체 |
| `delete_object` | 두 expected revision | 객체와 연관 grant 삭제 |

모든 변경은 `BEGIN IMMEDIATE`와 parameterized SQL로 처리하고 commit 또는 전체 rollback한다. 오래된 expected revision·삭제된 객체·중복 create는 `Conflict`다. 두 writer가 같은 revision을 갱신하면 하나만 성공한다. ACL과 본문을 동시에 바꿔야 하는 앱 동작은 `replace_object`를 사용한다. 두 필드를 별도의 호출로 갱신하는 것을 원자적인 하나의 업무 변경으로 해석하지 않는다.

ACL과 본문의 revision은 각각 `a_`·`c_`에 새 128-bit 난수를 붙인 opaque token이다. 실제로 바뀐 부분만 새 token을 받고, 의미가 같은 grant 순서·JSON object key 순서와 no-op은 유지한다. 예전 ACL이나 본문으로 돌아가거나 객체를 삭제·재생성해도 과거 token을 재사용하지 않는다. 정렬·시간 순서나 감사 이력을 뜻하는 번호는 아니다. 현재 token은 DB에서 영속된다.

DB 연결마다 foreign key를 활성화하고, tenant 이동 시 이전 grant를 제거한 뒤 새 tenant의 grant를 같은 transaction에서 기록한다. 앱의 모든 객체 writer는 이 계약을 사용해야 한다. 외부 SQL로 ACL을 바꾸면서 revision을 유지하는 동작은 지원하지 않는다.

## 초기화와 연결

초기화는 새 파일에 한 번만 수행한다. 어떤 기존 파일이든 있으면 `initialize`는 실패하고 덮어쓰거나 migration하지 않는다. 로컬 WAL DB와 full synchronous commit을 사용한다. 기존 상태로 재시작할 때는 일반 constructor를 사용한다.

```python
from pathlib import Path
from reverse_artex_guard.sqlite_application import (
    SQLiteApplicationStore, SQLiteApplicationResolver, Conflict,
)

path = Path('data/application-native.db')
# 최초 설치 시에만:
store = SQLiteApplicationStore.initialize(path)
revisions = store.create_object(
    '1', tenant='alpha', owner='alice', grants=('carol',),
    payload={'value': 'application data'},
)

# 이후 실행 시:
store = SQLiteApplicationStore(path)
revisions = store.current_revisions('1')  # restart 뒤 writer의 CAS metadata
resolver = SQLiteApplicationResolver(path)
# serve_application_read(handler, configured_guard, resolver)
# configured_guard는 동일 registry/OIDC pin과 session-snapshot-v1을 사용한다.
```

```python
next_revision = store.replace_acl(
    '1', expected_authz_revision=revisions.authz_revision,
    tenant='alpha', owner='alice', grants=(),
)
# 다른 writer가 먼저 바꿨으면 Conflict를 처리하고 현재 상태를 다시 읽는다.
```

store의 `create`, `active`, `revoke`는 [BrowserSSO](BROWSER-SSO.md)의 lifecycle 계약도 구현한다. 서명 검증 뒤 access-token digest를 기록하며, 만료·중복 digest·잘못된 주체를 거부한다. 세션 폐기는 grant나 객체를 바꾸지 않는다.

기존 SSO 예제에서 명시적으로 프로필을 선택할 수 있다. 이 옵션은 DB를 초기화하거나 객체 SDK handler를 자동으로 설치하지 않는다. 앱은 위 resolver를 자신의 private SDK read handler에 연결한다.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'sdk/python'
python -B sdk/python/examples/browser_sso_gateway.py --database-profile sqlite-native-acl/1 --identity-config config.oidc.local.json --public-origin https://app.example --edge-origin http://127.0.0.1:9082 --database data/application-native.db --listen 127.0.0.1:9083
```

기존 `legacy-session-v1`이 기본값이다. 예제 포털의 숫자 객체 ID allowlist와 private edge·coverage는 유지한다. 프로필의 다른 opaque ID를 노출하려면 앱의 명시적 router·shell·registry를 함께 연결한다.


## 범위와 다음 수용

이 프로필은 명시적으로 채택한 로컬 SQLite 앱 schema다. PostgreSQL·다른 ORM schema나 실제 운영 앱을 자동 통합하지 않는다. 현재 ACL 판정은 같은 tenant의 owner/direct principal grants이며 그룹·role·deny precedence·쓰기/search/export의 권한 모델은 앱의 별도 계약이다.

읽기 snapshot 이후 commit된 폐기를 진행 중 응답에 소급하는 분산 fencing은 추가하지 않았다. 기존 proof·nonce·5초 edge deadline은 유지한다. 이 ACL 검증 당시 BFF의 browser state는 단일 프로세스 메모리였으며, 같은 호스트의 browser cookie 재개·worker 공유는 별도 [후속 저장소](SHARED-BROWSER-STATE.md)의 수용을 따른다.

다음 수용은 대상 앱의 실제 schema·ACL 모델에 대한 resolver/쓰기 경로 대조, 운영 TLS/네트워크·계정 연결과 공유 browser session 저장소다. 원격·장기·독립 모델 효과나 실제 배포 완료를 주장하지 않는다.

읽기/쓰기 snapshot 설계는 SQLite의 [Isolation](https://www.sqlite.org/isolation.html), [foreign key 활성화](https://www.sqlite.org/foreignkeys.html#fk_enable), Python의 [SQLite transaction 제어](https://docs.python.org/3/library/sqlite3.html#transaction-control)를 기준으로 한다.
