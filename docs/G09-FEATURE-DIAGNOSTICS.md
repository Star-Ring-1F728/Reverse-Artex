# G09 — feature 분리 가능성 진단

후속 진단은 후보·학습 자료·임계값·운영 승격 기준을 변경하지 않는다. 기존 품질 평가가 불합격한 원인을 확인하고, 현재 관측만으로 오류 기준을 달성할 수 있는지 계산한다. API와 CLI는 집계만 반환하며 학습이나 승격을 실행하지 않는다.

## 확인된 한계

기존 frozen 후보는 `case-metadata-stump/1`, feature 0(`evidence_count`), threshold 2, `suspicious_at_or_above=false`다. 즉 증거가 2개 미만이면 의심으로 분류한다. 이는 학습 자료에서 맞춘 규칙이며 공격 인과를 입증하지 않는다.

소모된 120건을 별도 scorer UID에서 진단한 결과, 14차원 vector는 4개 그룹뿐이었다. 정상·공격이 섞인 그룹 2개에 87건이 속한다. 같은 vector에 같은 결정을 내리는 어떤 결정적 분류기도 이 자료에서 최소 27/120건을 틀린다. 단측 95% Wilson 상한 10% 기준에서 공격 60·정상 60의 클래스별 허용 오류는 각각 2건이다. 미탐 2건 이하를 지키면 달성 가능한 최소 오탐은 60건이므로 두 기준을 동시에 만족할 수 없다.

이는 **관측된 이 cohort에 대한 경험적 한계**다. 운영 전체의 Bayes 오류나 독립 일반화 성능을 추정한 것이 아니다. 분류기의 구조를 복잡하게 하거나 임계값을 바꾸어 이 정보 부족을 해결할 수 있다는 결론도 아니다. 기존 품질 불합격·승격 보류를 유지한다.

## 제품 진입점

- `GET /console/api/cases/learning/diagnostics?tenant=alpha&candidate_id=ID`
- `learning-control -action candidate-diagnostics -journal PATH -tenant alpha -candidate-id ID`
- evaluator 전용 `learning-evaluate -action diagnose -capsule CAPSULE -expected-capsule-sha256 PIN -inputs INPUTS -gold PRIVATE_GOLD -quality-report PRIOR_REPORT -out NEW_AGGREGATE_JSON`

후보 진단은 저장된 fit 행만 사용하고 선정 전체·fit 상한 제외·재평가 필요 여부를 보존한다. HTTP는 기존 bearer·loopback·origin·tenant·정확한 query 검사를 적용한다. 원장에 새 후보·서명·승격 기록을 쓰지 않는다. `necessary_global_bounds_feasible=true`는 해당 행의 클래스별 오류 한도가 수학적으로 가능하다는 필요조건일 뿐이다. 독립 품질·family별 비회귀·시간·coverage·운영 승인은 별도다.

quality 진단은 capsule/input/gold commitment와 기존 완료 quality report의 계획·cohort·집계 계약을 확인한다. 결과는 `spent_cohort_posthoc_not_independent_evaluation`, `cohort_feedback_spent=true`, `production_approval=false`, `independent_evaluation=false`다. ID·vector·개별 정답·최적 lookup 규칙·새 모델을 반환하지 않는다. `run`은 gold뿐 아니라 `-quality-report`도 파일을 열기 전에 거부한다.

## 경험적 하한 계산

확정 라벨을 같은 feature vector끼리 묶고 그룹별 공격 수 a·정상 수 b를 센다. 해당 그룹의 최소 오류는 min(a,b)이며 전체 하한은 그 합이다. 추가로 동적 계획법을 사용해 vector별 하나의 이진 결정을 선택할 수 있다고 낙관적으로 가정하고, 허용 미탐 예산 내 최소 오탐을 계산한다. 실제 stump보다 훨씬 강한 overfit lookup도 기준에 미달하면 기존 feature만으로 해당 자료의 기준을 달성할 수 없다. 최적 결정이나 lookup은 내보내지 않는다. uncertain/disputed도 전체 cases에 남고 준비도 통과가 되지 않는다.

이 계산은 제한된 입력(MaxCases 512)에서 수행하며, 테스트는 별도 전수 열거와 60개의 임의 그룹 구성을 대조한다. 입력 순서 불변·상충 그룹·Wilson 예산·unknown 분모·원장 무변경·다른 tenant 거부·변조된 gold/보고서 거부도 검증한다.


## 다음 개발의 입력 조건

새 후보를 만들기 전에 다음 관측 계약을 versioning해야 한다. 현재 이 작업은 진단까지 구현했으며 아래의 feature v2는 아직 구현하지 않았다.

1. 사건에 포함된 실제 authorization deny·validation·canary 관측을 규칙별 경보 수뿐 아니라 검증 가능한 증거 집계로 전달한다. 누락·부분 관측·중복과 사건 범위를 명시한다.
2. 승인된 QA와 비승인 행위를 구분할 수 있는 사전 권한·범위·만료·철회 관측을 신뢰된 센서에서 받는다. 라벨·사건 ID·cohort 순서·검토 결과를 feature에 넣지 않는다. 단순 QA 계정 이름을 정상 정답으로 사용하지 않는다.
3. vector/schema/runtime 변경을 새 버전으로 고정하고 구형 capsule을 임의 zero-fill로 호환시키지 않는다. 새 학습 자료와 새 미개봉 평가 자료를 역할·증거·시간으로 분리한다.
4. 새 후보·feature·기준을 동결한 후 새 cohort를 평가한다. 이미 진단한 cohort를 미개봉 holdout으로 재사용하거나 유리한 결과가 나올 때까지 반복하지 않는다.

측정·회귀·소스/바이너리 pin은 검증 영수증에 기록했다.




후속 [feature v2 관측·새 학습·봉인 평가](G09-CONTEXT-V2.md)를 구현했다. 180건으로 새 후보를 학습·동결한 뒤 새 통제 자료 240건에서 미탐 0/120·오탐 6/120, 오탐 단측 95% 상한 9.38%를 확인했다. 실제 gold 접근 차단과 전건 채점을 검증했으며, 외부 독립성·운영 승격은 승인하지 않았다.
