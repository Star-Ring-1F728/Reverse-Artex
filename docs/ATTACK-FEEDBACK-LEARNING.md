# 공격 피드백으로 보조 분류기 개선

G09의 24차원 사건 특징을 사용하는 보조 분류기다. 새 공격 관측과 현재 서명 라벨을 이전 학습 증거와 합쳐 새 후보를 생성한다. LLM 가중치를 학습하거나 학습 결과로 앱 권한·차단 정책을 바꾸지 않는다.

## 관측에서 재학습까지

1. Context trust를 설정한 collector가 센서 서명 관측을 저장한다. 사건 기억을 동기화하고 reviewer가 사건·증거·revision에 결합된 라벨을 서명한다. HTTP 403이나 모델의 예측 자체가 정답 라벨을 만들지는 않는다.
2. Collector를 정상 종료하거나 commit 잠금 아래 확보한 일관된 사본을 사용한다. `learning-context-prepare`가 원본 재생·센서 서명·현재 사건과 라벨 키를 대조해 학습 입력과 reviewer의 새 검토 요청을 내보낸다. 기존 원본과 case-memory 원장은 수정하지 않는다.
3. 별도 보관자는 학습에서 제외할 holdout의 **source/evidence hash만** `TrainingBoundary`에 넣고 서명한다. Trainer에 평가 gold나 평가 관측을 전달하지 않는다. 이 서명은 지정 키의 주장이다. 코드만으로 실제 보관자의 독립성이나 누락된 예약 목록을 인증할 수는 없다.
4. Reviewer가 전체 새 input/gold digest를 검토·서명한 뒤 `learning-context -action update`로 이전 후보와 비교한다. 이전 학습 증거가 빠지거나 새 증거가 없으면 거부한다. uncertainty/disputed 정정은 증거와 전체 분모를 유지하며 fit에서 제외한다.
5. 같은 새 학습 자료에서 미탐·오탐이 모두 나빠지지 않고 하나 이상 개선된 경우 `ready_for_shadow=true`다. 이는 학습 비교 결과다. 새 봉인 평가·실제 prospective canary·현재 품질과 별도 운영 서명이 있어야 기존 100% 조사 분류 경로에 적용할 수 있다.

## 준비 명령

```sh
bin/learning-context-prepare \
  -evidence data/collector -case-memory data/collector/case-memory/journal.jsonl \
  -context-trust config.action-context-trust.json \
  -request REVIEWED_CASE_GROUPS.json -out NEW_FEEDBACK_BATCH
```

Request schema는 `case-context-feedback-request/1`이고 `tenant_id`, 새 `dataset_id`, `recipe_sha256`, `reviewer_key_id`, `annotations`를 요구한다. 각 annotation은 정확한 `case_id`, `case_sha256`, `family`, `source_group`을 지정한다. Family/source를 예측이나 정답에서 자동 생성하지 않는다. 검토자는 이 metadata도 input의 일부로 서명한다.

출력은 `inputs.json`, `gold.json`, `review-template.json`, `review-trust.json`, `preparation.json`이다. 준비 보고서의 `planned = included + exclusions`와 각 제외 사유를 확인한다. 미동기화·서명 없는 라벨·stale 사건·metadata 누락을 조용히 표본에서 지우지 않는다. 실제 서명 관측이 없거나 불완전하면 추출이 실패한다. 출력 경로는 새 폴더여야 한다.

`review-template.json`의 서명을 reviewer가 채운다. 기존 v2 authority 계약처럼 reviewer/custodian/evaluator의 세 공개 역할을 사용한다. 개인키는 각 역할에 남기며 이 명령은 서명을 발급하지 않는다.

## 업데이트 명령

```sh
bin/learning-context -action update \
  -previous-candidate PREVIOUS_CANDIDATE.json \
  -inputs NEW_FEEDBACK_BATCH/inputs.json -gold NEW_FEEDBACK_BATCH/gold.json \
  -review SIGNED_REVIEW.json -review-trust NEW_FEEDBACK_BATCH/review-trust.json \
  -expected-review-trust-sha256 OPERATOR_RETAINED_TRUST_SHA \
  -training-boundary SIGNED_HOLDOUT_BOUNDARY.json -out NEW_UPDATE.json
```

Boundary schema는 `case-context-training-boundary/1`이다. `tenant_id`, 현재 `trust_sha256`, 정렬·중복 없는 `reserved_source_sha256`와 `reserved_evidence_sha256`, custodian `key_id`, `issued_at`, `expires_at`, `signature_base64`를 모두 넣는다. 기간은 최대 30일이고 사용 시 유효해야 한다. 서명 bytes는 아래 명령으로 만들며 Ed25519 domain은 `reverse-artex/context-training-boundary/1` 뒤 실제 LF 한 byte다.

```sh
bin/learning-context -action boundary-bytes \
  -training-boundary BOUNDARY_TEMPLATE.json -out NEW_SIGNING_BYTES.bin
```

Update 결과의 `candidate` 객체를 새 파일에 저장하면 다음 generation의 `-previous-candidate` 입력이 된다. `previous_on_current_training`과 `candidate_on_current_training`, 새/재생 증거 수와 `state`를 함께 확인한다. 개선이 없거나 두 오류 중 하나가 나빠지면 shadow 준비 상태로 표시하지 않는다. 모든 update는 `deployment_allowed=false`, `policy_mutations=0`, `requires_fresh_evaluation=true`다. `run` 동작은 피드백·gold·학습 입력을 계속 거부한다.

## 학습기와 연산 한도

기존 stump의 모든 경계를 정렬·누적 카운트로 계산한다. 기존 threshold·방향·동률 선택 순서는 유지한다. 512행·24특징에서 행마다 모든 후보를 다시 판정하던 탐색을 `O(F N log N)`으로 줄였다. 읽기 전용 embedded source의 fingerprint는 process에서 한 번 계산하며 라벨·키·입력·품질 결과를 이 cache에 저장하지 않는다.

단일 경계보다 학습 오류가 줄어드는 경우에만 `context-metadata-rules/3`를 사용한다. 최대 네 규칙의 OR이며 각 특징당 여덟 경계·폭 16의 결정적 beam을 사용한다. 각 규칙은 최소 세 공격 학습 사례를 덮고, 예측에는 사건 ID·정답·본문을 넣지 않는다. 탐색은 제한된 heuristic이며 임의 공격에 대한 최적해나 새 유형의 탐지를 보장하지 않는다. 자료가 분리 불가능하면 기존 보수적 후보를 유지한다.

입력은 최대 512사건·4096개 중복 없는 증거, 확정 공격·정상 각 30건, 최소 3 family/source group을 요구한다. 상한에서 오래된 공격을 몰래 제거하지 않는다. 새로운 series는 보관한 원본과 분리해 명시적으로 준비해야 한다. 결과 후 소비한 평가 자료로 tuning했다면 다음 후보에 새 holdout을 마련해야 한다.

## 버전 전환

24차원 모델/학습기와 feedback 소스가 runtime pin에 포함된다. 이번 학습기 변경으로 기존 v2 capsule·품질 policy·release/activation journal의 transitive pin이 바뀐다. 자동 변환·원본 덮어쓰기를 하지 않는다. 이전 build와 원장을 보존하고 사용 중인 profile을 중지한 뒤 새 학습·평가·서명 profile을 준비한다. 이 준비 없이 기존 profile을 새 실행 파일에 연결하면 불일치로 제공이 중지된다. 14차원 casememory 학습기·원장 형식과 기본 off 설정은 유지한다.

동작·정확도·학습 시간은 [이번 개선 검증 기록](VALIDATION.md#authorization-protection--2026-11-12)에서 확인한다. 로컬 합성 서명·자료의 통과를 독립 운영 품질로 해석하지 않는다.
