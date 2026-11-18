# 앱 세션 DB와 객체 권한을 보존하는 SDK 연결

2026-11-08 추가: [SQLite native ACL 저장소](SQLITE-NATIVE-ACL.md)는 명시적으로 채택한 앱 schema의 실제 grants·영속 ACL/content revision·CAS writer를 이 snapshot 계약에 연결한다. 아래 기존 lab schema와 검증 분모는 유지한다.

추가 후속: [Keycloak OIDC·미등록 경로 통제](OIDC-COVERAGE.md)는 이 세션 snapshot 계약에 OIDC access token과 explicit ingress 목록을 연결한다. 아래11/08 이전 세션 검증 결과와 분모를 별도로 유지한다.

2026-11-08. `session-snapshot-v1`은 서명 토큰 검증 뒤 앱의 현재 세션 DB와 객체 ACL·payload를 한 snapshot에서 읽는 선택 계약이다. 기존 `snapshot-v1` 경로도 계속 지원한다. 기본 설정이나 실행 중인 서비스에 자동 적용하지 않는다.

## 처리와 반환

`Guard(..., resolver_version="session-snapshot-v1")`와 `serve_application_read(handler, guard, resolver)`를 함께 사용한다. registry의 해당 GET/HEAD 경로에도 `resolver_version`을 `session-snapshot-v1`로 지정한다. 인증 adapter는 기존 `lab-hmac-v1`이다. manifest 변경으로 registry digest가 바뀌므로 SDK의 digest pin과 별도 v2 state 구성을 함께 검토한다. 기존 registry의 state 파일을 다른 digest로 자동 변환하지 않는다.

resolver는 `(object_id, ReadIdentity)`를 받는다. identity는 SDK가 서명 검증한 `principal`, `tenant`, 원래 credential의 SHA-256만 포함하며 bearer token을 전달하지 않는다. resolver는 다음 순서를 지켜야 한다.

1. 같은 DB transaction에서 credential digest의 현재 세션을 조회한다. 폐기·만료·principal/tenant 불일치는 `ApplicationSnapshot(False)`를 반환하고 객체를 읽지 않는다.
2. 유효한 세션이면 같은 snapshot에서 객체·ACL·payload를 읽는다. 객체가 없으면 `ApplicationSnapshot(True)`를 반환한다.
3. 객체가 있으면 `ApplicationSnapshot(True, ObjectSnapshot(...))`를 반환한다. 객체의 canonical ID와 tenant·owner·grants·ACL/content revision을 검증하고 실제 권한을 판정·직렬화·서명하는 주체는 SDK다. 앱은 allow 결정이나 임의 응답 bytes를 제공하지 않는다.

| 결과 | 서명 decision / HTTP |
| --- | --- |
| 세션 폐기·만료·DB 신원 불일치 | `unauthenticated` / 401 |
| 유효 세션, 객체 없음 | `not_found` / 404 |
| 다른 tenant·owner이며 grant 없음 | `deny` / 403 |
| 현재 권한 허용 | `allow` / 200 |
| DB 오류·잘못된 snapshot·직렬화 오류 | `unknown` / 503 |

401/404는 새 resolver로 명시 등록한 경로에서만 edge가 수용한다. 두 상태의 ACL/content revision은 `unknown`이어야 한다. HEAD도 같은 검사를 거치며 서명 본문은 비어 있다. 잘못된 서명·scope·본문은 기존처럼 반환 전에 503으로 닫힌다. 토큰 자체가 유효하지 않으면 DB resolver를 호출하지 않는다.

v2는 새 상태를 `authentication_rejected`, `object_not_found`로 보존하며 객체 권한 위반이나 native 대응 후보로 집계하지 않는다. 401/404/503은 기존 정책의 429로 가리지 않는다. 서명·요청 binding·본문 hash를 검산하는 journal 재시작 경로도 유지한다.

## 기존 SQLite 앱에 적용하는 예제

[`sdk/python/examples/sqlite_session_adapter.py`](../sdk/python/examples/sqlite_session_adapter.py)의 `SQLiteSessionResolver`는 기존 lab schema에 맞춘 읽기 전용 예제다. `sessions(digest, principal, tenant, expires)`와 `objects(id, owner, tenant, value)`를 사용한다. 새 connection마다 `mode=ro`, `query_only`, 명시적 `BEGIN`을 사용하고 세션→객체를 순서대로 읽은 뒤 connection을 닫는다. DB를 생성하거나 schema를 바꾸지 않고 세션을 cache하지 않는다. canonical 정수 ID만 허용하며 owner/tenant와 payload의 SHA로 각각 ACL/content revision을 만든다. 다른 앱의 schema·grants·OIDC/SSO는 그 앱의 trusted resolver가 구현해야 한다.

```python
from reverse_artex_guard import ApplicationSnapshot, ObjectSnapshot
from reverse_artex_guard.http_server import serve_application_read

# guard는 운영자가 고정한 digest·키·경로 설정과
# resolver_version="session-snapshot-v1"로 생성한다.
def resolver(object_id, identity):
    with application_read_snapshot() as db:
        session = db.current_session(identity.credential_sha256)
        if not session_matches_and_is_live(session, identity):
            return ApplicationSnapshot(False)
        row = db.object_with_acl(object_id)
        if row is None:
            return ApplicationSnapshot(True)
        return ApplicationSnapshot(True, ObjectSnapshot(
            row.id, row.tenant, row.owner, tuple(row.grants),
            row.acl_revision, row.content_revision, row.payload))

# BaseHTTPRequestHandler의 do_GET/do_HEAD에서 호출:
# serve_application_read(self, guard, resolver)
```

snapshot 이후 commit된 세션/ACL 변경을 이미 진행 중인 응답에 소급하는 분산 fencing은 제공하지 않는다. 기존 5초 응답 기한과 proof 검증을 유지한다. 배포 대상은 계속 명시 등록한 단일 객체 GET/HEAD다.


## 검증

소스에서 SDK 의존성을 설치한 뒤 공개 합성 단위 테스트를 실행할 수 있습니다. 실제 배포의 신원 공급자와 저장소, 서비스 종료 동작은 해당 환경에서 확인하세요. [테스트 안내](../CONTRIBUTING.md)
