# 제공 기능과 남은 조건

## 이번 배포 폴더의 진입점

웹 콘솔: 실제 observe 수집기 기동, 상태·저장 건수·상관 상태·규칙 조건 조회, 활성 이벤트·경보 조회, 센서 연결 정보, 별도 JSONL 규칙 분석. 웹 화면과 API는 같은 Go 실행 파일에 포함됩니다. HTTP 수집·정규화 검증·회전 증거 저장·복구·탐지는 기존 구현을 연결합니다.

기존 CLI 소스와 배포 도구: 정책 제어·프록시 집행, source/case 원장, 사건 읽기 API, 사건 동기화·내보내기·보존 계획, 제한된 조사 실행, 제안·승인·집행, 선택 Linux 호스트 대응. 관련 DB·권한·신원·별도 서비스 설정을 갖추어야 각 기능을 사용할 수 있습니다.

## 사건 기억·라벨·학습 대상 선정

기본 로컬 웹 콘솔의 **사건 기억**은 수집 원본 snapshot의 replay와 증거 참조를 검산한 뒤 tenant별 사건 버전을 저장한다. 운영자 라벨의 근거·revision·이전 hash를 보존하고, 새 증거·동시 수정의 충돌을 거부하며, 보류·상충·중복을 제외한 불변 학습 선정을 제공한다. 정정 뒤 이전 선정의 재평가 필요 여부와 재시작 복원을 지원한다. [사용법·API·상한](CASE-MEMORY.md)을 따른다. 기본 Windows 로컬 검증에서 전체 Go 회귀·vet와 실제 HTTP·재시작 흐름을 확인했다.

선정은 운영자 검토 결과이며 오프라인 경량 후보 학습과 비교를 연결했다. 독립 평가·활성 모델 승격은 후속이다. 이 저장소는 기존 PostgreSQL case API/원장과 별개이며 전체 M7의 자산·센서 신뢰 계약 수용을 대신하지 않는다. 공유 저장 예산 profile에서는 coordinated writer 연결 전까지 사건 기억 API를 제공하지 않는다.

## 오프라인 학습 후보

사건 기억의 확정 라벨·현재 저장 선정에서 tenant별 경량 후보를 만들고 같은 cohort의 fit/전체 비교를 저장한다. 출처/특징/라벨/모델 pin, 상한 제외·전체 분모, 불변 원장·재시작 검산과 라벨 정정 후 재평가 필요 여부를 웹/API에 연결했다. [사용법·제한](OFFLINE-LEARNING.md)을 따른다. 공개 자료와 운영 자료의 구분을 유지하고, 같은 자료에서의 비교를 독립 품질/운영 개선으로 표시하지 않는다. 후보는 검토용이며 활성 모델이나 정책에 적용되지 않는다.

## 새 사건 shadow 관측

고정한 학습 후보로 시작 이후의 새 사건에서 예측을 먼저 저장하고 나중의 운영자 판정과 비교한다. 학습/기존 사건·과거 자료·미리 판정한 사례·중복 증거를 구분하고 전체 분모·제외 사유와 immutable snapshot 이력을 제공한다. 수동 snapshot과 사전 기준·명시적 시작을 요구하는2초 간격 자동 관측을 제공하며, 학습 원본/구현 변경·한도에서 중단한다. [계약](SHADOW-LEARNING.md), [자동 관측·추천 버전](LEARNING-LIFECYCLE.md)을 따른다. 검증한 incident projection 관측이며 전체 트래픽 coverage·독립 품질 평가·정책 승격은 아니다.

## 검토 화면의 추천 버전

최신 로컬 승인과 snapshot에 묶인 추천 pointer·1–50% 제한 비교·별도 신규 표본과 재승인 후100% 사용·호환 과거 버전 복원·중지를 제공한다. 새 관측/검토 source 변경으로 승인 stale이면 추천을 비운다. 변경 이력·tenant/CAS·source pin·재시작과 전역 중지 예산을 검증했다. 콘솔의 학습·관측·검토 흐름에서 현재 선택과 다음 검토 위치를 함께 확인하며 Chromium으로 안내·중지/재개·stale 추천 비우기를 검증했다. [범위](LEARNING-LIFECYCLE.md)를 따르며 실제 LLM·가드·방어 정책을 적용하는 production pointer는 아니다.

## Shadow 관측의 사전 기준·운영자 검토

첫 관측/새 사건 이전에 기준을 고정하고 표본·라벨 확보율·기간·오탐·기준 대비 악화와 최신 snapshot을 확인한다. 승인/반려/보류는 근거·CAS revision·정확한 snapshot과 함께 저장하며, 정정과 구현 변경 시 과거 결정은 이력을 유지하고 stale로 표시한다. [사용법](CANDIDATE-REVIEW.md)을 따른다. 다음 평가를 위한 로컬 승인만 제공하며 독립 평가·canary/운영 권한이나 모델 자기 승인을 추가하지 않는다.

## 로컬 Qwen 연결

**Qwen 조사**에서 설치된 도구 지원 Ollama 모델을 선택하고, 검증된 사건·원본 참조를 읽어 판단과 도구 결과를 저장한다. 분석 전용이 기본이며 사건별 운영자 실행 선택과 기존 제어기 자격을 설정한 경우에만 단일 주체·세션·경로의 최대60초 정책·해제를 제공한다. 원본·모델 revision pin, 잘못된 도구/근거 거부, 취소·예산, 재시작 비재실행을 검증했다. [연결·사용·독립 Qwen 실검증](LOCAL-QWEN.md)을 따른다. 모델 학습이나 다운로드를 수행하지 않는다.

## 명시적으로 등록한 객체 조회 보호 (P0/P1 기반)

별도 registry를 설정한 edge와 제품 Python SDK를 연결하면 단일 객체 GET/HEAD에서 반환 전 권한 판정과 Ed25519 proof/body 검사를 수행한다. 기존 lab-hmac-v1 신원·일관된 resolver snapshot·private upstream 통합이 필요하다. 기본 미설정이며 일반 앱 자동 보호나 운영 신원 연결 완료가 아니다. [지원 범위·설정·검증](PROTECTION-CONTRACT.md)을 따른다. 자동 native의 중복 발급/cooldown/restart 억제와 Qwen 최신 적격 근거 재검사도 보완했다. v2 사건·객체 정책과 실제 Decisions provider는 별도 로컬 작성자 profile에 연결했다. [v2 사용법](V2-DECISIONS.md)을 따른다. 실제 API 사용과 독립 ARTEX/운영 수용은 보류다.

2026-11-08에는 명시적 `session-snapshot-v1` 경로에 현재 세션 DB와 객체 ACL/payload를 같은 snapshot에서 읽는 SDK 계약을 추가했다. 폐기·만료·DB 신원 불일치는401, 객체 없음은404, DB 오류는503으로 구분하고 v2 권한 위반 후보로 집계하거나 기존 정책의429로 가리지 않는다. 기존 SQLite lab schema의 읽기 전용 예제와 원본 앱을 수정하지 않는 modern/legacy HTTP 재현 도구를 제공한다. [연결·검증 범위](SESSION-ADAPTER.md)를 따른다. 운영 OIDC/SSO나 임의 앱 자동 통합을 제공하지 않는다.

## Keycloak OIDC·미등록 경로 통제

선택 OIDC profile은 고정한 issuer/audience/authorized client/RSA 공개키·stable sub 매핑을 Go·SDK에서 검증하고, 앱 세션·ACL snapshot에 연결한다. 설정 pin 불일치·ID token·옛 HMAC fallback·변조를 거부한다. 선택 coverage는 SDK 등록과 명시적 앱 예외 밖을 upstream 전에 닫고, 감사 실패/원래 요청 예산 초과도 전달하지 않는다. 실제 Keycloak·원본 App으로411검사, 완전 등록 정상80/80과 세션·장애·재시작·만료를 확인했다. [설정·범위](OIDC-COVERAGE.md)를 따른다. offline token 검증, 앱 예외와 실제 SSO callback/즉시 IdP 폐기·운영 배포는 구분한다.

## v2 사건·객체 정책·Decisions 연결

명시적 -v2-state profile에서 SDK 서명 근거→현재 사건 SHA→서버 후보→resource/ACL revision별 owner claim·유한 임대→같은 edge 반환 전 집행을 연결했다. 로컬 관리 화면과 defense-v2 CLI, fixed-origin OpenAI Decisions provider의 mode·영속 예산·취소/지연/재시작 처리를 제공한다. 기본 off이며 실제 API 사용은 사용자 요청으로 미뤘다. [연결과 검증 범위](V2-DECISIONS.md)를 따른다. v1 Qwen/PG/remote controller는 자동 변환하지 않으며 설치 receipt를 실제 효과로 표시하지 않는다.

## v2 Qwen/L3와 효과·복구 관측

별도 pinned local L3 설정과 현재 사건 SHA에 묶인 bounded 도구 실행, L3 자기 claim 해제, 서버 응답 write 기반의 설치·차단·정상 영향·해제·복구 축을 연결했다. 2026-11-02 최신 edge/CLI의 Windows/Linux 빌드와 Linux 실행 파일·제품 Python SDK·모의 Ollama 통합 26항목, 관련 회귀·race·vet를 통과했다. 다른 owner 유지·활성 claim 재시작·모델 장애 시 운영자 해제·중단 실행 비재전송을 확인했다. 기본 disabled이며 실제 API/모델 실행·Windows 실행·독립 품질 수용은 후속이다. [사용법](V2-L3-OUTCOMES.md), 배포 검증 범위를 따른다.

## 웹에 아직 통합되지 않은 기능

Qwen 조사의 저장 실행에는 사건·모델 pin, 실제 도구 순서·상태·기록 시각·근거와 판정을 연결하는 조사 워크벤치를 추가했습니다. 전체 Run/Step 원본과 단계 상세를 함께 확인하며 진행·실패·취소를 구분합니다. 자유 형식 AI 작업 생성·대화·모델 설정과 별도 서명 승인·집행을 하나의 웹 흐름으로 운영하는 전체 시스템은 아직 남아 있습니다. 최신 구현·검증은 현재 개발 상태를 따릅니다. 파일 분석은 기존 규칙 엔진을 사용하며 LLM 분석으로 표시하지 않습니다. 기존 CLI 조사 기능의 provider/host 계약도 이 콘솔에서 자동으로 완성하거나 실제 모델로 대체하지 않습니다.

## 배포 준비와 운영 수용의 구분

이번 패키지는 실행·설정·빌드 구조를 만들고 로컬에서 검증하는 범위입니다. 독립 데이터·장기 부하·운영 신원·holdout·외부 서버·실제 Linux host 격리·장애 복구의 운영 수용은 별도 검증이 필요합니다. 기본 동작을 자동 차단·호스트 격리·완전 자율 방어로 바꾸지 않았습니다.

과거 실험 보고서나 성공 수치는 새 운영 검증 결과로 가져오지 않습니다. 최신 로컬 검사·빌드·기능별 배포 통합과 남은 조건은 2026-11-03 검증 기록을 따릅니다. 초기 복사 단계의 `.workspace-copy/validation.json`은 당시 기록입니다.
