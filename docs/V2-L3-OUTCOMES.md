# v2 Qwen/L3와 방어·해제·복구 관측

**2026-11-15 최신 검증:** 새 짧은 참조 Gemma 시험에서 실제 차단→평가→본인 claim 해제→평가와 이후 SDK403/정상200 복구까지 통과했다. 실제 HTTP30건의 서명·클라이언트 대응, 정상 Bob20건, 실행별 참조의 원본 ID 매핑을 재검산했다. `responsev2`·`edge` Windows race 검사도 통과했다. 검증 기록과 한계를 따른다. 아래의 실패 이력은 보존하며, 이번 결과를 자율 판단 품질이나 전체 ARTEX 방어 성능으로 확대하지 않는다.

**2026-11-15 후속:** tenant 재요청·실제 모델 해제 검증에서 영수증의 tenant 재검사 누락을 수정했다. 새 실제 Gemma 두 시험은 자신의 claim을 해제했지만 최종 평가 오류로 전체 복구 수용은 실패로 남겼다. 관측된 긴 ID 전사 오류를 바탕으로 선택형 실행별 짧은 참조를 추가했으며, 기본 off·정확한 서버 매핑·원본 인수 hash·기존 권한/기한 검사를 유지한다. 짧은 참조의 실제 모델 효과는 아직 미검증이다.

**2026-11-15 방어 경계 보강:** 재현·수정 기록에 따라 native `apply_containment`·`finish_assessment`는 정확한 필드명과 필수 필드를 검사하고, 대소문자 별칭·중복 의미 필드를 거부한다. 평가 요약은 제시한 schema와 같이 최대 1,400 Unicode 문자 및 기존 바이트 예산을 함께 적용한다. 서버 경계 회귀이며 실제 모델의 판단·해제 성공을 새로 입증하지 않는다.

**2026-11-12 후속:** 선택 [서버 사전 조회와 검증 오류 수정](VALIDATION.md#authorization-protection--2026-11-12)으로 분석 1회·제한/해제 2회 모델 호출을 확인했다. 서버 조회에는 `executor: server`를 기록하며 최종 완료는 같은 잠금 안에서 취소·epoch·기한·사건을 재검사한다. 큰 문맥은 개별 조회로 복귀하며 기본값은 false다. 실제 두 모델의 원본·검산 v2가 함께 통과했고 이전 실패도 보존했다.

**2026-11-12 제한 ACL 재검증:** 분리된 두 Sol low 역할의 고정 권한 회귀에서 후보 ID와 서명 근거·범위의 연결 정보 누락을 수정했다. 기본/묶음 조회에 정확한 세 식별자만 추가하며 기존 행동 권한은 유지한다. 실제 모델의 제한·해제와 별도 서명/서버 write 검산을 확인했다. 범위는 고정된 합성 로컬 요청이다.

**2026-11-12:** 정상 Sol low 분석·동시 요청 검증에서 live 시각 채취를 원장 잠금 안으로 옮기고 선택 `bundled_context` 읽기를 추가했다. 분석 4→2회·대응/해제 6→4회이며 16 KiB를 넘는 문맥은 기존 개별 조회로 돌아간다. 기본 disabled·묶음 조회 false이고 기존 행동 검증·기한은 유지한다. 요청했던 실제 두 모델 대결은 플랫폼 차단으로 미완료이며 정상 분석 결과와 구분한다.

**2026-11-02 후속:** 최신 policy-edge·defense-v2 Windows/Linux 빌드와 Linux 실행 파일·제품 Python SDK·모의 Ollama 배포 통합26항목을 통과했다. SDK 전체8개, Python/Go 상호운용, 관련 Go 회귀·race·vet도 통과했다. 재현·제한, 검증 기록을 따른다. 실제 모델/API 호출·Windows 실행·독립 품질/운영 수용은 미수행이다.

2026-11-01 소스 구현 후 보류했던 회귀·빌드·모의 배포 통합을2026-11-02 재개해 완료했다. 아래 CLI는 동일한 조작을 운영 대상에 적용할 때의 예시이며, 통합 시험에서는 임시 자격과 새 원장을 가진 소유 loopback 프로세스만 사용했다.

## L3 연결

기존 v1 조사 원장을 변환하지 않고, 동일 edge의 v2 단일 작성자 원장에 별도 L3 실행을 저장한다. config.l3.example.json의 기본값은 disabled이며 provider를 만들거나 Ollama에 접속하지 않는다. enabled로 바꿀 때는 운영자가 이미 설치한 도구 지원 로컬 모델의 정확한 이름과 SHA-256 digest를 지정해야 한다. 모델을 자동 시작·다운로드하지 않고 cloud alias/remote metadata를 거부한다. Ollama origin은 명시적 literal loopback HTTP만 허용하며 proxy와 redirect는 사용하지 않는다.

edge 실행 옵션은 -v2-state, -protection-registry, -l3-config다. 기존 SDK/private upstream/자격 설정도 필요하다. Decisions는 별도 설정이며 이번 요청에서는 계속 off로 둔다. L3 자동 enqueue 옵션은 없다. 운영자가 현재 사건 ID와 SHA를 지정해 명시적으로 요청한다.

L3 모드는 analyze, contain, release다. contain에는 서버 설정 allow_containment도 필요하다. 순서는 get_case → get_evidence → get_response → 선택적 apply_containment 또는 release_owned_claim → get_defense_outcome → finish_assessment다. analyze는 세 조회 후 평가를 끝낼 수 있고, contain도 조치 없이 끝낼 수 있다. 조치했다면 결과 관측을 읽어야 완료된다. 모델 평가는 기록되지만 검증된 효과 상태를 변경하지 않는다.

모델에는 근거 ID, 판정 종류, 객체 HMAC, scope ID, SDK status와 관측 시각 등 제한된 사실만 보낸다. raw proof, 신원 토큰, 객체 payload, grant 목록은 모델 입력에 포함하지 않는다. 모델이 사건·scope·임의 URL·shell·probe를 구성할 수 없으며, 최신 서버 후보의 ID만 선택한다. 현재 사건 SHA/cancel epoch/기한/취소 상태를 도구 실행 전에 다시 검사한다. 조치 후 추가 트래픽으로 사건이 바뀌면 읽기·평가만 허용하며 추가 조치는 하지 않는다.

실행 기한 30초, 모델 호출 시도 최대6회, 요청당48KiB와 누적256KiB, 관측 결과당16KiB로 제한한다. 모델 호출 전에 동일 전송 payload의 바이트 수와 시도 수를 영속 기록한다. 일일 실행 예산은 최대128이며 기본 예제32다. 원장 전체 L3 실행128개, 대기4개, tenant별 대기2개 한도를 적용한다. 한도 도달 시 조용히 오래된 원장을 삭제하거나 예산을 초기화하지 않는다.

조치 intent를 먼저 저장하고 claim 설치 결과와 episode binding은 원장에서 복원한다. 조치 직후 프로세스가 끊겨도 다음 실행 시 receipt를 조회할 수 있다. 중단된 실행은 interrupted_unknown이며 모델이나 조치를 자동 재실행하지 않는다. 동일 요청 ID의 다른 내용도 거부한다.

## claim 해제와 관리

L3는 owner=l3, run_id=원본 실행 ID인 claim만 갖는다. 모델의 release 모드나 별도 운영자 직접 해제는 지정한 원본 실행에서 policy/episode/scope를 도출하고 현재 사건 SHA/epoch/generation을 재검사한다. 다른 owner의 claim은 유지한다. 운영자 직접 해제에는 모델 추론이 필요하지 않다. 정책이 이미 만료됐으면 새 해제 성공을 만들어내지 않는다.

로컬 /v2/console과 defense-v2 CLI에서 실행·조회·취소·직접 해제·outcome 조회를 제공한다. 읽기 토큰은 조회만 가능하며 mutation에는 별도 RA_V2_OPERATOR_TOKEN이 필요하다. 콘솔 토큰은 메모리에만 보관하며 출력은 textContent를 쓴다. API 키 입력 기능은 추가하지 않았다.

CLI 예시:

~~~powershell
.\bin\defense-v2.exe -action run-l3 -tenant alpha -case CASE_ID -case-sha CURRENT_SHA -mode analyze -request-id operator-analysis-1
.\bin\defense-v2.exe -action l3-run -tenant alpha -id operator-analysis-1
.\bin\defense-v2.exe -action cancel-l3 -tenant alpha -id ACTIVE_RUN_ID
.\bin\defense-v2.exe -action run-l3 -tenant alpha -case CASE_ID -case-sha CURRENT_SHA -mode release -source-run SOURCE_CONTAIN_RUN -request-id operator-release-1
.\bin\defense-v2.exe -action release-l3 -tenant alpha -source-run SOURCE_CONTAIN_RUN -case-sha CURRENT_SHA -epoch CURRENT_EPOCH -generation CURRENT_POLICY_GENERATION -request-id direct-release-1
.\bin\defense-v2.exe -action outcome -tenant alpha -id POLICY_ID -episode EPISODE_ID
~~~

contain은 -mode contain을 명시하며 최신 서명 거부2건·서로 다른 객체2개의 적격 서버 후보가 있어야 한다. 현재 상태를 다시 읽고 정확한 값을 사용해야 한다. 전역 pause는 새 조치를 막고 현재 모델 실행의 취소를 요청하지만 기존 정책을 일괄 해제하거나 연장하지 않는다. 재개도 이전 L3 실행을 자동 재실행하지 않는다.

HTTP 경로: POST /v2/l3, GET /v2/l3-run, POST /v2/l3-cancel, POST /v2/l3-release, GET /v2/outcome. Command의 request_id는 새 L3 실행/해제 intent ID, run_id는 취소 대상, source_run은 해제할 원본 실행이다. outcome은 tenant/policy ID/episode로 묶이며 /v2/status에 l3 설정과 outcome_audit 상태를 포함한다.

## 방어 효과·해제·복구 판정

반환 전 SDK 서명/body 검사와 별개로, 현재 정책 snapshot에 묶인 response-attempt를 Sync한 후 반환하고, 서버가 실제 수락한 status/바이트 수/body hash와 완료·오류 상태를 response-observation으로 기록한다. HTTP HEAD의 빈 body, 부분 write, 연결 취소와 panic도 구분한다. 관측은 **서버 write**이며 원격 client 수신을 보증하지 않는다. client_receipt는 not_observed다. 실제 외부 공격 효과·remote 집행·분산 인과 효과도 이 관측에서 도출하지 않는다.

outcome의 축은 installation, target, policy_effect, benign_impact, release, recovery다.

- 설치 receipt만 있으면 installed_locally이며 target/effect는 unknown이다.
- SDK403에 정책429를 관측하면 target=observed_denied, policy_effect=masked_by_sdk다. SDK 자체 거부를 정책 기여로 계산하지 않는다.
- 서명된 정상200이 정책429로 바뀌면 observed_collateral로 기록하고 같은 원장 기록에서 pause와 cancel epoch를 갱신한다. 정상200 body의 불일치도 새 대응을 중지시킨다.
- 정책 작동 중 정상200을 원본 SDK body hash/길이와 동일하게 전송한 관측이 있으면 no_observed_collateral이다. 관측되지 않은 정상 경로까지 보증하지 않는다.
- 마지막 claim의 명시적 해제와 retained_by_other_owner, natural_expiry를 구분한다.
- 해제/만료 후 새로 준비된 동일 target의 무정책 응답이 SDK baseline과 일치하고 정상200 대조 요청도 무정책 상태에서 body까지 일치해야 observed_guard_baseline_restored다. target의 올바른 baseline은 SDK403일 수 있다.
- 해제 전에 준비하고 해제 후 완료한 요청, 부분/실패/미완료 응답, SDK 불확실 판정, 다른 tenant/episode/정책은 복구 성공으로 쓰지 않는다. 해제 후 트래픽이 없으면 unobserved다.

관측의 참조는 원장 sequence 순서로 결정적으로 산출하며, 새로운 정책 episode를 이전 episode의 복구 검증으로 사용하지 않는다. 원본 관측은 보존하고 표시용 근거 참조는 축마다8개로 제한한다.

response 준비 Sync 실패는 반환을 차단한다. 반환 후 관측 저장 실패·서로 충돌한 완료 보고는 상태를 degraded로 남기고 다음 보호 응답/조치를 차단한다. 재시작 시 완료가 없는 준비 기록은 unknown이며 동일하게 차단한다. 이전 boot의 완료 보고를 새 성공으로 채우지 않는다. 원장을 보존하고 원인을 조사해야 하며, 자동 삭제·새 원장 교체·정책 연장은 하지 않는다.

## 저장 및 검증 재개 지점

`policy-edge -v2-combined-prepare`는 선택 설정이며 기본값은 false다. SDK 관측·사건 갱신과 응답 준비를 같은 잠금 안에서 하나의 `adjudicate-and-prepare` commit으로 Sync한다. 실제 서버 write는 기존처럼 별도 `response-observed` commit이다. `-v2-state`가 필요하며, `-v2-native` 또는 `-decisions-auto`가 켜진 SDK403은 기존 관측→native/enqueue→응답 준비 순서를 유지한다. 선택 설정은 권한·서명·기한·본문·동시 요청 한도와 저장 실패 시 응답 차단 조건을 변경하지 않는다.

V2 원장은 수명 전체에서 사건512개·SDK event8,192개·응답 attempt8,192개·파일64MiB로 제한된다. 이 원장에는 checkpoint/보관 회전이 구현되어 있지 않다. 새 보호 응답100RPS라면 event 한도만으로 약81.92초에 도달한다. 관리 기록이나 새 세션에 따른 사건 증가로 더 일찍 한도에 도달할 수도 있다. 매 구간 새 원장으로 측정한 성능을 지속 운영 용량으로 해석하지 않는다. 운영 용량 확장에는 미완료 write·활성 정책과 owner·예산·epoch 및 증거 보관 연결을 보존하는 별도 설계가 필요하며, 실행 중 원장 삭제나 교체로 우회하지 않는다.

새 optional 원장 필드는 비어 있으면 생략하므로 이전 v2 기록은 읽을 수 있다. 새 operation/필드를 기록한 원장은 이전 실행 파일의 strict reader에서 읽을 수 없으므로 이전 바이너리로 되돌아가 새 원장을 열지 않는다. v1·remote 원장에 자동 적용하지 않는다.

보류 지시 전 responsev2/edge/localassistant 관련 단위·모의 HTTP 테스트를 수행했다. 최초 새 테스트의 과거 시각 fixture가 시계 역행 검사를 건드려 실패했고, fixture의 관측 시각을 현재로 고친 후 해당 패키지 테스트는 통과했다. 실패를 제품에서 시계 검사를 완화하는 근거로 쓰지 않았다.

2026-11-02 G09-D의 전체 Go 회귀1480 pass/8 skip·vet 이후 Go 소스 변경 없이 최신 edge/CLI를 빌드했다. 이번에는 관련3개 패키지의47개 상위 테스트(하위 포함110 pass)를 Python 상호운용 opt-in과 함께 다시 실행했고 race도 통과했다. cmd2개 패키지는 테스트 파일이 없으며 실제 CLI/edge 동작은 별도 배포 통합에서 확인했다. vet는 관련5개 패키지에서 통과했다. 최신 바이너리·SDK·모의 Ollama의26항목과 정확한 SHA는 새 검증 기록에 저장했다.

L3-OUTCOME-PROGRESS-20261101.json과 L3-OUTCOME-VALIDATION-20261101.json은 보류 당시 이력으로 보존한다. 최신 상태는 L3-OUTCOME-VALIDATION-20261102.json을 따른다. SDK가 이미 거부한 target의 정책 기여는 masked_by_sdk이며 모델의 독립 차단 성과가 아니다. 실제 API/모델 실행은 계속 보류한다.
