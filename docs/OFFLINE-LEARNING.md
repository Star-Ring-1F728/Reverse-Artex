# 오프라인 학습 후보

**2026-11-09 G09 검증 경로:** [서명 라벨 입고·별도 선정과 후보 승격/복원](VERIFIED-LEARNING.md)을 추가했다. 운영자가 설치한 tenant별 공개키로 라벨과 추천 변경을 검증한다. 기존 로컬 경로는 정책 미설치 tenant에서 유지하며, 실제 LLM/가드 배포와 독립 품질·운영 수용은 후속이다.

2026-11-02 KST. G09의 제품 연결 단계로, 검토된 로컬 사건 기억에서 단일 tenant의 경량 분류 후보를 생성하고 같은 선정 자료에서 비교한다. 후보는 `QUARANTINED_LOCAL_ONLY`로 보존한다. 운영 모델·탐지 규칙·정책·L2/L3 provider는 바꾸지 않으며 외부 API나 모델 다운로드 없이 사용할 수 있다.

## 사용

1. **사건 기억**에서 수집 증거를 동기화하고 공격/정상 확인 라벨과 근거를 기록한다. 경보·HTTP 성공·LLM 판단을 확정 라벨로 자동 변환하지 않는다.
2. **학습 대상 선정**으로 현재 사건·라벨 hash를 고정한다. 보류·상충·stale·중복 증거는 기존 선정 계약대로 제외되고 전체 분모에 남는다.
3. **이 선정으로 학습 후보 생성**을 누른다. 생성 직전 원본을 다시 동기화하고, 저장 선정이 달라졌으면409를 반환한다. 다시 선정해야 한다.
4. **오프라인 학습 후보**에서 목록·비교 결과·출처 및 특징 hash를 확인한다. 후보는 재시작 뒤에도 조회된다. 같은 데이터/학습 버전의 재요청은 같은 ID를 반환하며 원장 기록을 추가하지 않는다.
5. 라벨 정정·증거 추가 뒤 **원본 동기화 후 재평가 필요 여부 확인**을 누른다. 기존 후보·당시 비교 결과는 보존하며 변경 사건을 표시한다. 새 선정으로 별도 후보를 만든다.

학습 상한 적용 후 확정 공격·확정 정상 각각2건 이상이 필요하다. 부족하면 `insufficient_confirmed_classes` 상태와 전체 선정/제외/출처를 저장하고 참고 기준을 유지한다. 이 최소 수는 코드 경로 검증에 필요한 학습 조건이며 독립 품질 수용에 충분한 표본 수가 아니다.

## 후보와 비교 계약

- 실제 입력은 기존 `Store.Dataset()`이 현재 저장 선정에서 원자적으로 고정한 사건·운영자 라벨이다. 공개 fixture 학습기나 미개봉 holdout을 읽지 않는다. 생성은 사건 기억의 lock 안에서 실행되며 ingestion lock을 잡지 않는다.
- 모델 입력은 증거/경보 수, 최대86400초로 제한한 사건 기간, HTTP/host 증거 수, rule 종류 수와 RA-001~008의 경보 수 총14개 정수다. ID·tenant/asset 이름·hash·라벨·검토 사유는 예측 벡터에 넣지 않는다. 원문 이벤트/응답 body/토큰은 학습 기록에 추가하지 않는다.
- 고정 recipe `case-metadata-stump/1`은 feature 하나의 정수 임계값·방향을 탐색한다. Fit false-benign을 먼저 최소화하고 다음으로 false-attack을 줄인다. 동점이면 기존 결과를 유지한다. 복잡한 공격 순서나 장기 행동 학습을 완료한 모델이 아니다.
- Tenant별로 저장 선정의 결정적 사건 순서를 사용한다. 같은 source snapshot의 fit 기여는8건, 같은 asset은32건, 전체 fit은128건으로 제한한다. 상한 제외 사례도 row·사유와 전체 선정에 남기고 확인된 전체 적격 사건 비교에 포함한다. Source snapshot 그룹 수는 독립 출처/판정자 수가 아니다.
- 참고 기준은 **경보가 생성된 모든 사건을 의심으로 보는 단순 기준**이다. 실제 활성 규칙/LLM과 동등한 기존 모델 점수라고 주장하지 않는다.
- Fit subset 비교와 전체 적격 선정 비교를 각각 저장한다. 둘 모두 학습 자료와 겹치는 같은 cohort 비교이며 독립 holdout이나 일반화 검증이 아니다. 경보가 없는 정상 사건의 모집단을 이 데이터로 평가하지 않는다. 동일 fixture 분리 성공을 운영 탐지율 개선으로 표시하지 않는다.
- 모든 후보는 `review_required=true`, `independent_evaluation=false`, `deployment_allowed=false`다. 후보의 benign/suspicious는 검토용 제안이며 기존 확정 라벨·검토 필요 상태를 덮어쓰지 않는다. 승격/자동 대응/활성 모델 pointer는 제공하지 않는다.

## 출처·불변 기록·정정

후보는 전체 selection과 case/label/source snapshot binding, data/config/feature/model/source fingerprint를 저장한다. Compile-time embedded trainer·dataset·store 소스에서 로컬 구현 fingerprint를 계산하며 외부 서명/빌드 출처 인증을 뜻하지 않는다. Candidate ID는 dataset·학습 source·config·feature pin에서 결정하고, candidate SHA는 생성 시각과 결과까지 결합한다.

새 candidate는 기존 `case-memory/journal.jsonl`의 hash-chain record에 append/Sync한 뒤에만 성공으로 반영한다. 재시작은 당시 사건/라벨/선정과 후보를 다시 생성해 features·분모·cap·model·비교·hash를 대조한다. 저장된 모델과 record checksum을 함께 고친 변조도 이 재계산과 다르면 거부한다. 후보 생성 실패는 운영자 라벨이나 원본을 수정하지 않는다.

최신성은 마지막으로 동기화한 사건 기억과 비교한다. 현재 trainer fingerprint와 저장 fingerprint의 차이도 재평가 필요로 표시한다. 기존 후보를 자동 재학습하거나 현재 라벨로 바꿔치기하지 않는다. 로컬 관리자가 원장 전체를 제거/교체하는 공격이나 reviewer 독립성은 로컬 checksum만으로 증명하지 않는다.

상한은 후보64개, 기존 journal32MiB/record2MiB/8192기록을 함께 적용한다. 한도 초과는507이며 오래된 후보를 자동 삭제하지 않는다. 목록은 요약만 반환하고 전체 row는 후보 하나씩 조회한다. 학습이 규칙·승인·저장 상한을 자체 수정할 수 없다.

후보가 없는 기존 원장은 그대로 읽는다. `learning_candidate` record를 기록한 뒤에는 이 필드를 모르는 과거 strict reader 바이너리로 되돌아가 열지 않는다. 백업은 종료 후 collector 원본과 case-memory를 함께 보존한다.

## 로컬 콘솔 API

기존 동일 origin·loopback host·콘솔 bearer 인증과 configured tenant 범위를 그대로 적용한다. Sensor 토큰은 사용할 수 없다.

| Method | /console/api 뒤 경로 | 동작 |
| --- | --- | --- |
| POST | `/cases/learning?tenant=alpha` | 원본 동기화 후 정확한 저장 선정으로 생성/동일 후보 반환 |
| GET | `/cases/learning?tenant=alpha` | 해당 tenant의 후보 요약 목록 |
| GET | `/cases/learning/detail?tenant=alpha&candidate_id=...` | 후보·당시 비교·현재 재평가 필요 여부 |

POST의 JSON은 `{"selection_sha256":"<저장 선정 hash>"}`다. 추가/중복/별칭 필드·null·추가 JSON과 모호한 query를 거부한다. 요청1024bytes·응답8MiB 한도와 기존 프로필별 case-memory 가용성을 적용한다. 현재 모델/승격/권한을 요청으로 바꾸는 필드는 없다.

## 별도 새 사건 관측

학습 완료 후보를 [수동 shadow 관측](SHADOW-LEARNING.md)에 연결할 수 있다. 계획 시작 전 사건을 제외하고 새 사건의 예측을 라벨보다 먼저 고정한 뒤 후속 판정과 비교한다. 같은 학습 cohort 비교·수동 prospective 관측·독립 holdout은 서로 다른 범위다.

## 다음 단계

실제 운영자가 검토한 표본 확보, 풍부한 사건 feature의 근거/마스킹 계약, 독립 시간·주체·변형 평가, 검토와 shadow/canary, 호환 가능한 활성 버전/복원은 별도 후속이다. 모델 recall0/4·독립 holdout/운영 수용의 이전 판정을 이번 후보 기능으로 갱신하지 않는다. Docker IPv6 전체 격리 시험의 환경 차단과도 별도 기능이다.
