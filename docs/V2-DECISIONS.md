# v2 사건·정책·Decisions 연결

**2026-11-12 가상 통합 검토:** 실제 client·관리 API·정책 원장을 연결한 26개 시나리오를 검증했다. 혼합 SDK 401/404의 입력 계약 불일치를 수정했고, 해당 상태만으로 정책 후보가 생기지 않음을 확인했다. 로컬 TLS 모의 서버만 사용했으며 실제 키·API 호출과 운영 calibration은 계속 별도다.

2026-11-01 구현. 사용자의 요청에 따라 **실제 API 호출·키 입력은 미뤘으며 기본 API mode는 off**다. 새 profile은 edge와 같은 프로세스의 단일 작성자다. 기존 v1 collector/casememory, PostgreSQL case API, Qwen 및 remote policy-control을 자동 변환하지 않는다.

추가된 v2 Qwen/L3와 서버 응답 관측은 [별도 사용법](V2-L3-OUTCOMES.md)을 따른다. 기본 disabled다. 2026-11-02 최신 edge/CLI의 Windows/Linux 빌드와 Linux 실행 파일·Python SDK·모의 Ollama 연결을 검증했다. 검증 범위를 따르며 실제 API·모델 호출은 계속 보류한다.

## 연결된 경로

SDK 서명과 실제 body 검증 → authorization-adjudication/2 → 한 synced record에서 case-evidence-view/2 revision 공개 → 서버가 만든 exact-resource 후보 → policy-lease/2/owner claim → 같은 edge의 반환 전 집행이다.

allow/200은 정상 representation이며 위반이 아니다. SDK deny/403은 prevented_unauthorized_access, 불확실한 판정은 unknown이다. 이 경로는 반환 전 관측이므로 실제 유출·client 수신·독립적인 정책 효과를 주장하지 않는다. 같은 request 재전달은 사건 revision이나 독립 근거 수를 늘리지 않고 다른 내용의 재사용은 거부한다.

원본 SDK 서명·request/nonce·scope·ACL revision·body digest를 저장한다. payload/token/grant 목록은 저장하지 않는다. 원본과 현재 사건 SHA는 같은 journal record의 Sync 후 공개한다. registry/key 변경은 기존 journal pin과 충돌하며 자동 migration하지 않는다.

## 정책·알고리즘

native 대응은 기본 off다. -v2-native를 설정하면60초 안의 독립 요청2개·서로 다른 resource2개의 검증된 거부로 후보를 만든다. scope는 tenant/asset/principal/session/route/method/resource/ACL revision/registry/enforcer 전체다. wildcard, 다른 객체와 새 session으로 확대하지 않는다.

scope당 effective policy1개, owner claim 최대4개다. native/Decisions/operator/l3를 구분한다. 초기 만료는 선택된 위반 시각+60초이고, 소비하지 않은 더 늦은 독립 request만 갱신에 쓴다. episode 시작+120초 hard-end와 그 후60초 cooldown을 보존한다. 먼저 만료되거나 전부 해제해도 해당 episode의 cooldown을 없애지 않는다.

정상200은 native mutation을 촉발하지 않는다. 같은 owner가 소비한 근거를 다른 intent로 보내면 receipt만 기록하며 generation·만료를 바꾸지 않는다. 현재 case SHA/candidate/cancel epoch를 commit 직전 검증한다. 재시작·시계 rollback·모호한 응답으로 자동 재전송하지 않는다.

operator 해제는 정확한 policy generation과 operator run만 제거한다. 다른 owner가 남으면 유지한다. native/Decisions claim은 이 endpoint로 제거하지 않고 원래 TTL에 만료된다. 새 대응 중지는 기존 정책을 전역 해제하거나 연장하지 않는다.

installed_locally receipt는 이 프로세스의 설치다. remote signed ack, 목표 차단 효과나 실제 복구의 증명이 아니다. SDK403이 먼저 막은 경우 정책 기여는 masked/unknown이다. 서버 write 기반 관측은 V2-L3-OUTCOMES.md에 설명하며, 독립 client·remote 인과 효과와 분산 수용은 후속이다.

## 실행·관리

PROTECTION-CONTRACT.md의 SDK/registry/private upstream 설정과 기존 edge 자격이 필요하다. v2에는 별도의 최소32자 RA_V2_OPERATOR_TOKEN도 필요하며 RA_EDGE_STATUS_TOKEN과 달라야 한다. 관리 listener는 literal loopback만 허용한다.

config.decisions.example.json을 별도 config.decisions.json으로 복사한다. 예제 off는 provider 초기화·키 조회·API 전송을 하지 않는다.

~~~powershell
.\bin\policy-edge.exe -asset my-app -protection-registry .\config.protection.json -v2-state .\data\v2\response.jsonl -decisions-config .\config.decisions.json
~~~

설정만 검사하려면 -protection-check를 추가한다. 자동 native는 -v2-native, 새 거부 사건마다 자동 분류 enqueue는 -decisions-auto를 별도로 설정해야 한다. API off이면 enqueue 요청도 실제 호출하지 않는다.

서비스 실행 후 http://127.0.0.1:9086/v2/console 에서 상태, tenant별 사건/근거/후보, 정책, 분류 실행/결과, 화면 소유 operator claim 해제와 새 대응 중지/재개를 제공한다. 관리 토큰은 현재 화면 메모리에만 유지하고 API key를 보내지 않는다. same-origin/Host·bearer 역할·CSP·textContent/no-store를 적용했다.

~~~powershell
.\bin\defense-v2.exe -action status
.\bin\defense-v2.exe -action cases -tenant tenant-one
.\bin\defense-v2.exe -action case -tenant tenant-one -case c2-...
.\bin\defense-v2.exe -action run-decisions -tenant tenant-one -case c2-... -case-sha CURRENT_SHA -request-id analysis-unique-id
.\bin\defense-v2.exe -action job -tenant tenant-one -id analysis-unique-id
.\bin\defense-v2.exe -action policies -tenant tenant-one
~~~

CLI는 RA_V2_OPERATOR_TOKEN을 읽는다. 읽기만 할 경우 -token-env RA_EDGE_STATUS_TOKEN을 지정할 수 있다. apply는 현재 case SHA·server candidate ID·epoch·안정적인 intent ID·owner run을 요구한다. release는 policy ID/generation과 operator run을 요구한다. 결과가 불명확하면 먼저 exact case/job/policy를 조회한다. 같은 ID의 다른 명령은 거부한다.

## 실제 Decisions provider

고정 TLS 목적지는 [공식 POST /v1/decisions](https://developers.openai.com/api/reference/resources/decisions/methods/create), 모델은 gpt-6-luna다. [공식 guide](https://developers.openai.com/api/docs/guides/decisions)의 predicate/choice/score를 사용한다.

전송은 tenant/asset/route pseudonym, 검증 fact kind/age, resource HMAC, case SHA/revision, candidate IDs, coverage/truncation/필수 검토, 질문 hash와 기한의 allowlist8KiB다. raw body/log/token/이름/signed proof는 보내지 않는다. 크면 facts를 줄여 truncated로 표시하며 자동 대응에는 쓰지 않는다.

off는 호출0, fake는 명시 모의, shadow/advisory는 실제 API 기록·권고만 하고 정책을 바꾸지 않는다. enforce-gated는 운영자가 고정한 교정 gate SHA와 threshold, 완전한 typed 결과, 현재 case/epoch/기한, 미절단 입력과 서버 적격 후보가 모두 필요하다. gate SHA는 운영자의 교정 결과 pin이며 독립 평가를 자동 인증하지 않는다. 이번 작업의 실제 API 품질·holdout은 미수행이다.

질문별 refusal, 누락/중복/잘못된 enum·분포·score·usage·모델·과대 body·redirect/TLS/기한 오류는 자동 대응을 만들지 못한다. 모델 점수로 독립 위반의 pending review를 지우지 않는다. 제공되지 않은 model revision/decision ID를 실제 provenance로 발명하지 않는다.

동시2, queue16, tenant pending4, enqueue기준5초를 적용한다. 예제는 요청당8192 tokens·하루100 calls/1,000,000 reserved tokens다. 전송 전에 예약을 Sync하고 실패/미확인 예약을 임의 환급하지 않는다. 보고 usage가 예약을 넘으면 더 큰 값으로 계산하고 provider를 차단한다. 이는 provider 측 hard dollar billing cap이 아니다.

401/403과 usage 초과 차단은 같은 config의 재시작으로 풀리지 않는다. 수정 후 config_revision을 바꿔 명시 설정한다. 연속3 transport/provider/429 오류는60초 circuit과 단일 half-open probe를 적용하고 최근 결과에서 복원한다. 중단 job은 interrupted_unknown으로 보존하며 재호출하지 않는다. dispatch fence 뒤 이미 진행 중인 원격 요청의 비용0/중단은 보장하지 않고, 늦은 결과는 정책에 사용하지 않는다.

## 나중에 키 연결

서버 환경변수는 key_env=OPENAI_API_KEY와 key_file=""를 설정하고 그 프로세스가 변수를 상속해야 한다. Windows 영속 참조는 bin/decisions-connect.exe를 직접 실행한다. 네이티브 숨김 입력과 [현재 사용자 DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata) 암호화만 사용하며 PowerShell 정책을 변경하지 않는다. data/secrets ciphertext와 key_file 참조 shadow config를 만든 후 합성 데이터1건을 검사하는 명시 연결 도구다. 현재 작업에서는 사용자 요청으로 입력 도구를 종료했다.

Linux는 서버 환경변수를 사용한다. Windows 암호화 파일은 같은 사용자 환경을 필요로 한다. 현재 사용자/앱 호스트 침해까지 key를 보호하는 보장은 아니다.

이미 자격을 설정한 뒤 명시적 1회 점검:

~~~powershell
.\bin\decisions-check.exe -live -out .\data\decisions-smoke-new.json
.\bin\decisions-check.exe -live -key-file .\data\secrets\YOUR_FILE.dpapi -out .\data\decisions-smoke-another-new.json
~~~

새 결과 파일을 예약/Sync한 후1회 호출하며 같은 파일로 재호출하지 않는다. 출력/기록에 key는 없다. 과거 별도 PowerShell 연결 성공을 이번 제품의 실제 호출로 가져오지 않는다.

## 검증과 남은 범위

V2-IMPLEMENTATION-VALIDATION-20261101.json에 source/build pin과 검증 결과를 저장한다. 실제 API는 사용자 요청으로 보류다. 로컬 TLS provider와 실제 loopback HTTP, v2 case/epoch fence, owner 해제/멱등성/재시작,120초 cap/cooldown, Sync 실패, 영속 budget/circuit, UI/CLI를 검증한다.

journal64MiB,8192 requests,512 cases,1024 scopes/jobs,4096 intent IDs로 제한한다. view는32개 근거이고 더 큰 사건은 truncated다. 포화는 자동 삭제로 숨기지 않으며 새 보호 반환이 실패할 수 있다. 운영 규모·압축/보존 수용은 후속이다.

remote/분산 migration, 독립 release/effect/정상 영향/복구 observer, v2 Qwen/L3 실제 모델 검증, 실제 API calibration/holdout과 독립 ARTEX 수용은 아직 남아 있다. v2 Qwen/L3 bridge의 모의 배포 통합은2026-11-02 완료했다.

서명 시각은 같은 호스트의 Python/Go 표본 차이 최대5ms만 허용한다. 실제 진단에서 Python 발급 시각이 Go 수신 표본보다1ms 앞서는 사례를 확인했다. nonce·만료·원래 edge 요청의 단조시계5초 상한은 유지하며, 이를 넘는 clock 불확실성은 보호 오류로 처리한다.
