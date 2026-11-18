# G09 v2 카나리 후속 라벨 평가와 승격 검토 기준 — 2026-11-12

`learning-context-canary`는 [서명 승인된 v2 카나리](G09-CONTEXT-CANARY-RELEASE.md)의 미래 관측 기준을 고정하고, 관측 후 발급된 현재 서명 라벨로 판단 품질을 재검산한다. `freeze`와 `assess`만 제공한다. 결과는 별도 운영 승인 검토를 위한 자료이며 **모델 활성화·100% 적용·정책 변경을 수행하지 않는다.** `deployment_allowed=false`, `policy_mutations=0`, `mandatory_review_preserved=true`를 유지한다.

## 관측 전에 기준 고정

중지한 collector의 현재 검증된 증거와 서명 release를 사용해 한 번만 plan을 만든다. 경로는 `RELEASE_JOURNAL.evaluations/RELEASE_SHA/plan.json`이다. Tenant, release/bundle/config/trust·평가기 source pin, 기준, 시작 시각·원래 lease 종료, 기존 사건/증거 baseline, 기존 history 순번/head를 고정한다. 재시도는 원래 plan을 반환하며 새로운 baseline이나 시작 시각으로 바꾸지 않는다. 손상·부분 plan을 자동 교체하지 않는다.

기존 사건은 비교 대상에서 제외하고 시작 뒤 처음 생긴 사건을 모두 분모에 넣는다. Source에는 있는데 prediction이 없는 사건과 history에는 있는데 현재 source에서 사라진 사건도 누락으로 남긴다. 학습/기존 증거 중복·관측 불가·공유 증거·시각 불일치를 성공 표본으로 세지 않는다. 기준을 낮추거나 사용자 지정 사건 목록·시작/종료 구간을 넣는 옵션은 없다.

기준은 코드에 고정되어 있다. 후보·참고 분기에 각각 최소 60건, 공격/정상 각각 30건, 라벨/관측 coverage 100%, 실제 저장된 최초 예측 간 최소 3,600초, 후보의 단측 95% Wilson 미탐/오탐 상한 각각 10% 이하를 요구한다. 동일 사건에 후보 모델과 `all_alerts_suspicious`를 적용한 paired 비교에서 두 오류의 비퇴행과 총오류 감소도 필요하다. 분기별 서로 다른 사건의 단순 오류 건수 차이를 성능 개선으로 판정하지 않는다.

분기는 기존 candidate SHA·tenant·case ID bucket을 그대로 사용한다. 이는 운영 관측 비교이며 무작위 인과 실험이나 표본 독립성을 증명하지 않는다. 작은 후보 비율에서는 기존 512 사건/관측 이력 상한 안에서 필요한 표본을 확보하지 못할 수 있다. 부족하면 기준을 완화하지 않고 `BLOCKED`다. 분기 비율이나 후보를 바꿔 새 시험을 하려면 새 서명 release와 미래 plan이 필요하다.

## 정확한 예측 버전과 나중 라벨

현재 검증된 source의 정확한 case SHA마다 해당 버전의 첫 저장 예측을 사용한다. 같은 사건의 더 유리한 후속 예측으로 교체하지 않는다. 사건이 갱신되면 현재 버전에 대한 선행 예측과 라벨 결합을 다시 확인한다. 같은 case SHA의 반복 observed 기록에서 벡터·예측·증거가 충돌하면 거부한다. 실제 source에서 서명 문맥과 24-feature 벡터를 다시 추출하여 저장된 벡터/증거와 대조한다.

단순 계산 완료 시각은 파일 Sync 이전일 수 있다. 따라서 각 prediction의 저장 완료 상한을 다음 저장 attempt의 시작 시각 또는 마지막 `pending=false` 완료 state 시각으로 잡는다. 라벨의 서명 발급과 실제 import 시각이 모두 이 상한 뒤에 있어야 한다. 보수적인 상한 때문에 저장 완료를 입증하지 못한 경우도 미확정으로 남는다. 운영 절차는 **관측 종료·collector 정상 종료 후 라벨을 발급/입고**하는 방식이 명확하다.

현재 case-memory 원장을 replay 검증하고 현재 설치 trust와 같은 공개키의 `label_reviewer` 서명을 요구한다. 정확한 tenant/case/evidence/source/revision 결합, 라벨 원래 수용 시 유효기간, 현재 공개키·폐기 여부를 확인한다. 예측보다 먼저 알려진 라벨이 있으면 나중에 정정 서명을 받아도 선행 관측으로 세지 않는다. 최신 라벨이 uncertain/disputed거나 서명이 없거나 case가 달라졌으면 미확정이다.

정정은 최신 revision으로 재계산한다. 이전 정상 판정을 공격으로 정정해 미탐이 생기면 기존 유리한 결과를 유지하지 않는다. Report의 label snapshot SHA와 전체 결과 SHA도 바뀐다. 향후 승인 소비자는 보고서의 `passed`/SHA만 신뢰하지 말고 현재 원장·source·라벨로 재검산해야 한다.

## 판정과 보존

원래 서명 lease와 다음 release 변경 시각 중 빠른 시점이 종료다. 실행 중에는 전체 구간을 평가한 것으로 통과하지 않는다. 실패한 관측, unsaved check, capacity 중단, 30초를 넘긴 batch, 누락·미확정 라벨은 통과를 막는다. `observed_span_seconds`는 실제 선택된 저장 예측의 시각 차이며 lease가 오래되었다는 이유만으로 시간을 채우지 않는다.

표본·coverage·시간·오류 조건이 충족되어도 현재 독립 품질 capsule/endorsement·키·기한을 다시 확인한다. 모두 충족하면 상태는 `CANARY_CRITERIA_MET_SEPARATE_RELEASE_REVIEW_REQUIRED`이며 `release_review_ready=true`다. 별도 100% 운영 승인을 발급하는 상태가 아니다. `independent_canary_evaluation_proven=false`도 유지한다. 서명은 설치된 키의 권한·문서 결합을 확인하며 실제 판정의 진실성이나 평가자 독립성을 인증하지 않는다.

Release owner를 잡은 offline 읽기로 collector/다른 승인과 경합을 막는다. 기존 history의 active·archive·seal과 정확한 4096-byte 완료 state를 읽기 전용으로 검증하고 worker를 시작하거나 복구 파일을 만들지 않는다. Pending intent·torn file·해시/벡터 충돌·기준/현재 trust 변경을 자동 보정하지 않는다. 기존 모델·채점기·품질 반입·카나리 실행의 frozen source pin은 유지하며 새 읽기 adapter와 평가기를 별도로 pin한다.

Plan과 관측 이력은 로컬 hash/owner에 근거한다. 관리자 권한의 전체 파일 교체·시각 조작을 독립 외부 attestation으로 막는 구조는 아니다. 실제 디스크 예약·전원 장애·독립 머신 운영 수용을 이번 기능의 결과로 주장하지 않는다.

## 실행 절차

1. [v2 서명 카나리 승인](G09-CONTEXT-CANARY-RELEASE.md)을 준비·입고하고 collector를 중지한 상태에서 기준을 고정한다.
2. 원래 profile로 collector를 시작해 새 사건을 관측한다. 모든 사건의 예측/관측 불가가 원본 이력에 남는다.
3. 관측을 종료하고 collector를 정상 종료한다. 현재 case-memory를 동기화하고 [서명 라벨](VERIFIED-LEARNING.md)을 입고한다. 서명 개인키는 reviewer에게 남긴다.
4. 처음 보관한 plan SHA로 평가한다. 기존 결과를 덮어쓰지 않고 정정 시 새 보고서를 만든다.

```powershell
go build -o bin/learning-context-canary.exe ./cmd/learning-context-canary
.\bin\learning-context-canary.exe -action freeze `
  -profile INSTALLED_PROFILE.json -release-sha256 SIGNED_RELEASE_SHA `
  -evidence data/collector -out NEW_FROZEN_PLAN.json

.\bin\learning-context-canary.exe -action assess `
  -profile INSTALLED_PROFILE.json -release-sha256 SIGNED_RELEASE_SHA `
  -evidence data/collector -case-memory data/collector/case-memory/journal.jsonl `
  -expected-plan-sha256 OPERATOR_RETAINED_PLAN_SHA -out NEW_CANARY_REPORT.json
```

Exit 0은 report 생성 성공이다. 통과 여부는 `state`, `criteria_passed`, `quality_valid_now`, `release_review_ready`, `reasons`로 확인한다. `planned/scored/unresolved/unknown_labels/corrected_labels`, 양 분기, paired confusion matrix·신뢰 상한과 사건별 원본 참조를 함께 확인한다. 입력 자체의 변조나 contract 불일치는 오류로 거부한다. 출력은 새 파일만 쓰며 기존 결과/원본을 덮어쓰지 않는다.
