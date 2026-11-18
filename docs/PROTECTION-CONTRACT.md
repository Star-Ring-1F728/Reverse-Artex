# 객체 조회 보호 계약 — 구현 1차, 2026-11-01

2026-11-08 추가 후속: [Keycloak OIDC·미등록 경로 통제](OIDC-COVERAGE.md)에 선택 OIDC adapter·identity pin과 explicit ingress inventory를 연결했다. 아래 lab 기반의 최초 계약 및 세션 후속과 구분하며 최신 범위는 해당 문서를 따른다.

후속 v2 사건·정책·Decisions 구현은 [V2-DECISIONS.md](V2-DECISIONS.md)를 따른다. 아래 1차 기록의 후속 표기는 당시 기준이다.

2026-11-08 후속: [앱 세션·객체 권한 연결](SESSION-ADAPTER.md)은 선택 `session-snapshot-v1` resolver와 서명된 세션 거부401/객체 없음404를 추가한다. 아래 `snapshot-v1`의 최초 계약과 구분하며, 새 명세는 해당 버전을 지원하는 SDK·edge를 함께 사용한다.

2026-11-06 후속: legacy 객체 보호·v2 방어 비교에서 등록 legacy 경로의 SDK 연동 조건을 실제 Windows HTTP로 검증했다. 무보호 노출24/24 대비 SDK·SDK+native 각각0/24, 조건별 정상240/240이다. 원래 ARTEX 세션 전체나 modern 경로를 재실행한 결과는 아니며 SDK 미연동 앱에 v2만 켜는 것으로 해결되지 않는다.

이 문서는 구현된 P0/P1 기반과 기존 자동 보조 알고리즘 보완의 사용 범위를 설명한다. 전체 개발 계획의 P2~P9, 실제 Decisions API provider, resource-aware v2 정책·소유권과 독립 ARTEX 평가는 후속이다. 기본 실행은 보호 registry 미설정 상태다.

## 구현한 반환 경로

운영자가 등록한 단일 객체 GET/HEAD에 한해, Python SDK가 신뢰된 resolver의 객체/ACL snapshot을 한 번 읽고 권한을 확인한 뒤 그 payload만 JSON으로 직렬화한다. SDK가 Ed25519로 서명한 proof와 실제 본문을 Go edge가 모두 검증한 후 응답한다. SDK는 임의 handler body를 서명하는 공개 API를 제공하지 않는다.

지원하는 인증 adapter는 현재 기존 테스트 신원 형식인 **lab-hmac-v1**이다. 운영 OIDC/SSO 연결을 완료한 기능이 아니다. resolver는 **snapshot-v1**이며, 실제 DB transaction/revision 비교와 snapshot의 정확성은 앱의 trusted resolver가 구현해야 한다.

- 신원: 서버가 검증한 tenant/principal/session. client의 X-RA·주체·forwarded 헤더를 신뢰하지 않는다.
- 권한: 같은 tenant의 owner 또는 명시적인 principal grant. 다른 tenant의 객체는 거부한다.
- snapshot: canonical ID, tenant, owner, grants, ACL revision, content revision과 payload가 같은 DB snapshot에 속해야 한다. 조회한 snapshot이 요청 객체와 다르면 unknown/503이다.
- 응답: JSON, identity encoding, 최대 1MiB. HEAD도 같은 ACL을 판정하며 proof의 본문은 빈 bytes다.
- 증명: asset/registry/trust epoch, 요청 ID/난수 nonce, method/route, tenant/principal/session, 객체 HMAC/action, ACL/content revision, decision/status, 실제 body length/SHA-256, 5초 유효기간.
- 제한: edge 요청 전체 5초, 보호 응답 동시 32개, 고정 본문 버퍼 합계 최대32MiB. header/proof/감사 metadata와 런타임 메모리는 별도다. 기본 upstream response header는32KiB로 제한한다.
- 실패: 누락/변조/재사용/시각·scope·body 불일치/크기 초과/압축·range/기한/감사 실패는 upstream 본문을 보내기 전에503. 확인된 무권한은403, 미인증은401. 보호 오류503은 가용성 실패다.
- 감사: 검증된 pre-release metadata를 동기 저장한 후 반환한다. client 수신·정책 효과의 증명은 아니다. 본문·원래 객체 ID·token·grant 목록은 기록하지 않는다.

ACL 판정 시점 이전에 commit된 revoke는 resolver snapshot에 반영돼야 한다. 그 시점 이후 revoke를 진행 중 응답에 소급하는 강한 fencing은 구현하지 않았다. edge는 원래 요청의 5초 deadline을 넘겨 반환하지 않는다.

## 등록 파일과 설정 검사

기본 설정 파일은 그대로 사용한다. 별도 config.protection.example.json을 복사하고 asset/tenant/route와 실제 SDK 공개키를 설정한다. 예제의 공개키 placeholder를 실제 **unpadded base64url Ed25519 32-byte 공개키**로 교체해야 검사를 통과한다. private key는 registry에 넣지 않는다.

빌드 후 서비스와 자격 증명을 시작하기 전에 검사할 수 있다.

~~~powershell
.\bin\policy-edge.exe -asset my-app -protection-registry .\config.protection.json -protection-check
~~~

성공 출력은 registry digest와 trust epoch/enforcer ID다. SDK에 이 digest와 같은 asset, route ID/template/namespace, trust epoch를 고정한다. 등록 파일은 중복 JSON key, 중복·중첩 경로, 미지원 adapter/mode와 잘못된 key/limit를 거부한다. ASCII opaque 객체 ID 한 segment만 지원하며, 해당 경로 family의 query·추가 segment·잘못된 method가 무보호 proxy로 우회하지 못한다.

실제 프록시는 기존 OPERATIONS.md의 controller/collector/신원·ingress 설정을 갖춘 뒤 같은 옵션으로 시작한다. 검사 옵션을 빼면 서비스가 시작된다. upstream은 운영자가 관리하는 private/loopback에 두고 public의 직접 접근을 차단해야 한다. 현재 작업은 운영 네트워크 ACL이나 다른 앱의 router를 자동 변경하지 않는다.

registry의 observe는 기존 통과 경로를 유지하며 **서명된 권한 판정·유출 관측 adapter를 구현한 모드가 아니다**. UI의 configured나 설정 검사 성공을 보호 효과 확인으로 해석하지 않는다. 이번 구현의 보호 검증은 enforce fixture에 한정한다.

enforce 등록 경로에는 v1 route-wide 임대를 적용하지 않는다. v1 정책을 resource-aware v2 집행으로 오인하지 않도록 분리하며, v2 정책 연결은 P4 후속이다. 첫 응답 보호는 SDK/edge의 결정적 ACL 판정이 담당한다.

## Python 앱 연결

sdk/python/pyproject.toml에 cryptography==50.0.2를 고정했다. 앱의 분리된 Python 환경에 sdk/python 패키지를 설치한다. SDK를 사용하는 앱만 이 의존성이 필요하며 Go 제품의 기본 수집 실행에는 추가 의존성이 없다.

~~~python
from reverse_artex_guard import Guard, ObjectSnapshot
from reverse_artex_guard.http_server import serve_object_read

# 운영자가 고정한 registry 설정과 server secret references를 전달한다.
guard = Guard(
    asset=asset,
    registry_digest=checked_digest,
    trust_epoch=trust_epoch,
    route_id=route_id,
    template="/legacy/objects/{id}",
    namespace="objects",
    tenants=allowed_tenants,
    key_id=app_key_id,
    private_key=app_private_seed,  # raw 32 bytes; 별도 보호된 key
    identity_key=identity_key,
    session_key=session_hmac_key,
    ingress_token=private_ingress_token,
)

def resolver(object_id):
    # 반드시 같은 transaction/snapshot의 ACL과 payload를 반환한다.
    # 객체 변경/권한 경쟁으로 일관성을 확보할 수 없으면 예외를 반환한다.
    row = read_one_consistent_snapshot(object_id)
    return ObjectSnapshot(
        canonical_id=row.id, tenant=row.tenant, owner=row.owner,
        grants=tuple(row.explicit_grants),
        authz_revision=row.acl_revision,
        content_revision=row.content_revision,
        payload=row.payload,
    )

# BaseHTTPRequestHandler의 do_GET/do_HEAD 내부:
# serve_object_read(self, guard, resolver)
~~~

SDK HTTP adapter는 중복된 신원/ingress/proof-binding 헤더를 거부하고 반환 representation의 status/body/header만 쓴다. 앱이 resolver 후 임의 bytes를 덧붙이거나 먼저 flush하면 edge proof 검사가 거부한다. 서비스 key의 발급·보관·폐기와 public upstream 우회 차단은 운영 설정이다.

SDK/키/권한 DB가 침해되지 않았다는 신뢰 경계가 있다. 임의 앱의 권한 버그, write/search/export/stream, RCE, 미등록 경로까지 보호한다고 주장하지 않는다. 1MiB JSON serialization 자체의 앱 메모리 비용은 resolver/payload의 관리 범위이며 edge의 고정 버퍼 상한과 다르다.

## 자동 보조·방어 알고리즘 변경

기존 v1 native 자동 정책은 정렬된 refs 집합의 hash가 바뀔 때 새 정책을 만들 수 있었다. 이제 같은 tenant/asset/principal/session/route의 자동 정책이 활성인 동안 추가 발급하지 않는다. 최초60초 임대 뒤60초 cooldown을 유지하며, revoke/restart/refs 변경/시계 rollback으로 이 억제를 초기화하지 않는다. 억제 이력은 기존 synced auto-deny WAL의 원래 발급 시각에서 재구성하며 새 journal 형식을 도입하지 않는다.

정상 요청은 과거 deny refs를 사용해 자동 정책을 새로 만들거나 갱신하는 trigger가 될 수 없다. 현재 독립 deny/WAF signal과 기존 threshold가 함께 충족돼야 한다. 미래 시각의 관측도 대응 근거 집계에서 제외한다. 기존 운영자 수동 승인과 자동 발급은 분리된 v1 계약을 유지한다. 이것은 P3/P4의 전체 resource-aware 캠페인·owner claim 구현을 대신하지 않는다.

로컬 Qwen 보조는 미래 근거, deny/200 불일치, 지원하지 않는 write method를 후보로 제시하지 않는다. 실행 시 최신 사건과 **현재 가장 최신인 적격 근거**를 다시 확인하므로 모델이 오래된 event ID를 선택해도 대응하지 않는다. 실제 operator contain 모드·기존60초 범위를 유지한다.

## 검증과 다음 단계

검증 결과와 정확한 source SHA는 IMPLEMENTATION-VALIDATION-20261101.json에 저장한다. 일반 Go 회귀의 opt-in skip과 실제로 실행한 Python interop을 구분한다. 서명 검사는 자체 crypto 구현 대신 [Go Ed25519](https://pkg.go.dev/crypto/ed25519)와 [PyCA Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)를 사용한다.

다음 단계는 P2의 별도 v2 서명 판정 ingest·replay·사건 pin이다. 현재 edge의 로컬 pre-release 감사나 일반403을 v2 verified violation·사건·정책 효과로 승격하지 않는다. 이후 P4/P5/P3, 실제 Decisions provider(P6), L3/UI와 독립 평가 순서로 이어간다.

서명 발급 시각 비교에는 같은 PC의 Python/Go clock 표본 정밀도 차이를 위한 최대5ms 오차만 허용한다. fresh nonce·서명 만료와 edge 원래 요청의 단조시계5초 hard deadline은 유지하며 이 오차로 반환 기한을 연장하지 않는다.
