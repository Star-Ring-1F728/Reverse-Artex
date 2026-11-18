# Shadow 결과의 로컬 검토 기준과 결정

2026-11-02 KST. G09-D는 shadow 관측 전에 고정한 기준과 정확한 최신 snapshot을 연결하고, 운영자의 **다음 평가를 위한 승인 / 반려 / 보류**와 근거를 저장한다. 기준 충족과 운영자 결정은 별개다. 승인은 로컬 검토 상태이며 후보·관측의 `independent_evaluation=false`, `deployment_allowed=false`를 바꾸지 않는다. 운영 모델·규칙·정책·provider를 적용하는 API나 권한 토큰은 아니다.

## 사용

1. 학습 완료 후보에서 새 shadow 계획을 시작한다. **첫 관측과 새로운 사건·라벨 변경 전에** 아래 **관측 결과 검토 → 기준 고정**을 누른다.
2. 최소 공격/정상 판정 수, 관측 기간, 라벨 확보율과 정상→의심 비율 상한을 확인한다. 한 번 고정한 기준은 변경하지 않는다. 이미 관측한 계획에 기준을 사후 등록할 수 없다.
3. 새 사건은 라벨보다 먼저 예측을 고정한 뒤, 운영자 라벨을 기록하고 shadow 관측을 갱신한다.
4. 기준 미충족 이유와 원본을 검토한다. 모든 로컬 조건이 맞고 자료가 최신일 때만 **다음 평가를 위한 승인**을 선택할 수 있다. 근거와 결정을 저장한다. 반려·보류는 자료가 부족하거나 과거 구현에 묶인 기록에도 남길 수 있다.
5. 라벨 정정·새 사건·새 snapshot·학습 원본/구현 변경 뒤에는 이전 결정이 최신 근거를 대표하지 않는다. 이력을 보존하고 `REVIEW_STALE` 및 갱신/재평가 사유를 표시한다.

기준은 이미 등록된 후보/계획에만 연결한다. 등록 시 해당 tenant의 사건 기억이 shadow baseline과 정확히 같고 snapshot이0개여야 한다. 무관한 tenant의 쓰기나 기준과 무관한 원장 추가 자체를 실패 조건으로 삼지는 않는다. 같은 기준의 등록 재요청은 기존 기록을 반환한다. 기준을 바꾸려면 새 계획과 이후의 별도 자료가 필요하다. 이전 실패·검토를 삭제하거나 새 결과로 대체하지 않는다.

## 사전 기준

| 필드 | 기본값 | 허용 범위/의미 |
| --- | --- | --- |
| `minimum_confirmed_attack` | 20 | 2 이상, 정상 최소 수와 합계512 이하 |
| `minimum_confirmed_benign` | 20 | 2 이상, 공격 최소 수와 합계512 이하 |
| `minimum_observation_seconds` | 3600 | 0–604800초, 기준 등록부터 저장 관측까지 |
| `minimum_label_coverage_bps` | 9000 | 1–10000, 전체 새 사건 중 confirmed 판정 비교 비율 |
| `maximum_false_attack_bps` | 1000 | 0–10000, 정상 판정 중 의심으로 제안한 비율 상한 |

BPS10000은100%다. 기준 대비 false-benign/false-attack 수가 늘지 않아야 한다는 조건도 고정 적용한다. 참고 기준은 기존 G09-B/C와 같은 **모든 경보 사건을 의심으로 보는 단순 기준**이며 실제 LLM/활성 방어 모델의 품질과 동일시하지 않는다.

최소 표본·기간의 기본값은 로컬 검토용 설정이며 독립 통계 수용 기준을 보장하지 않는다. 기준을 낮춘 실험은 그 값과 전체 분모를 보존한다. 합성 통합 검사에서는2/2·0초·100% 정상→의심 상한의 완화된 workflow profile을 사용하며 이 결과를 성능 개선이나 운영 품질 수용으로 표시하지 않는다.

라벨 확보율의 분모는 excluded·awaiting을 포함한 shadow 전체 새 사건이다. 성능 비교는 그중 confirmed 판정과 비교 가능한 `scored` subset이다. 기간은 마지막 **저장 관측** 시각에서 계산하며 GET 시 현재 시각만으로 늘리지 않는다. 자료가 변하지 않는 반복 capture는 새 snapshot을 만들지 않으므로 단순히 기다린 것만으로 기간 조건을 새로 충족했다고 저장하지 않는다. 이 시간은 continuous coverage의 증거가 아니다.

## 정확한 근거와 동시 수정

기준은 shadow plan SHA·candidate SHA·model SHA와 검토 구현 source fingerprint에 묶인다. 각 결정은 기준 SHA, **최신 shadow snapshot SHA/revision**, 예상 검토 revision, 이전 결정 SHA, 판정·근거·로컬 작성자·시각과 당시 기준 계산을 저장한다.

저장 직전 source sync를 수행한 뒤 사건 기억 lock 안에서 최신 snapshot·case/label input·학습 binding을 확인한다. 운영자가 화면을 본 사이에 다른 검토나 관측이 저장되면409다. 정확히 같은 요청의 재전송은 같은 intent로 취급해 원장 기록을 늘리지 않으며, 현재의 stale 상태는 함께 반환한다.

승인은 기준 충족, 최신 source 동기화 상태, 현재 trainer/observer/review 구현과 변경 없는 학습 원본을 모두 요구한다. 반려·보류도 정확한 현재 기준·최신 저장 snapshot과 예상 검토 revision을 요구하지만 품질 조건은 요구하지 않는다. Snapshot이 없는 보류/반려는 빈 snapshot SHA와 revision0에 결합한다. 근거는 공백 제외1–1000자다.

GET은 기존 snapshot/결정을 바꾸거나 자동 승인하지 않는다. `local_criteria_met`는 당시 수치의 조건 충족, `approval_for_evaluation_available`은 현재 로컬 승인 입력이 가능한지, `state`는 마지막 결정과 최신성 상태다. `APPROVED_FOR_EVALUATION`은 독립 평가를 이미 수행했다거나 canary/운영 적용이 허용됐다는 뜻이 아니다.

검토 작성자는 기존 콘솔의 `local-operator`다. 사용자별 신원/독립 reviewer 인증·서명 승인이나 외부 보관을 추가하지 않는다. 모델이 자신의 결과를 검토·승인하는 도구는 연결하지 않았다.

## 저장·재생·상한

`review_plan`, `review_decision`을 기존 hash-chain journal의 별도 optional record로 append/Sync한다. 성공 Sync 뒤에만 메모리 상태와 응답을 반영한다. 기준은 shadow 계획당1개(전체16개), 결정은 기준당32개이며 기존32MiB/record2MiB/8192기록 상한을 함께 적용한다. 한도 초과는507이며 이력을 조용히 삭제하지 않는다.

재시작은 record 당시의 원본·순서·최신 snapshot을 따라 사전등록 조건, 기준 계산과 CAS·결정 hash를 재검산한다. 현재 source pin과 달라도 지원되는 v1 의미의 과거 기록은 읽고 현재 결정은 stale로 표시한다. Replay 중에는 현재 바이너리의 fingerprint로 과거 승인을 소급 거부하지 않는다. `review_v1.go`의 기준 의미는 보존하고 새 행동은 새 schema/지원 replay를 추가해야 한다. 알 수 없는 schema를 현재 규칙으로 임의 해석하지 않는다.

새 optional 필드가 없는 기존 원장은 hash 형태를 유지한다. 이번 store 변경으로 과거 candidate의 trainer pin이 달라지므로 신규 검토는 새 후보·shadow 계획에서 시작한다. 과거 원장이나 source pin을 고치지 않는다. Review record가 생긴 원장은 이를 모르는 과거 strict reader 바이너리로 열지 않는다.

## 로컬 콘솔 API

기존 bearer·loopback host·same-origin·configured tenant 범위를 그대로 적용한다. POST는 source sync 후 실행한다. Query는 `tenant`와 `run_id` 각각1개, JSON은 지정한5개 필드만 정확히 받으며8192bytes로 제한한다. 추가/중복/대소문자 별칭·null·추가 JSON을 거부한다.

| Method | /console/api 뒤 경로 | 동작 |
| --- | --- | --- |
| GET | `/cases/learning/review?tenant=alpha&run_id=...` | 기준·마지막 결정·이력·현재 기준 계산·최신성 |
| POST | `/cases/learning/review/plan?tenant=alpha&run_id=...` | 위 표의5개 기준 필드로 사전등록 |
| POST | `/cases/learning/review?tenant=alpha&run_id=...` | 아래5개 필드로 결정 저장 |

```json
{
  "expected_review_revision": 0,
  "review_plan_sha256": "<고정 기준 SHA>",
  "shadow_snapshot_sha256": "<최신 저장 관측 SHA, 없으면 빈 문자열>",
  "decision": "defer",
  "reason": "추가 표본이 필요합니다"
}
```

Decision은 `approve_for_evaluation`, `reject`, `defer`다. Actor·model·정책·배포 허용을 요청 필드로 바꿀 수 없다. 2026-11-03에는 이 승인을 요구하는 [검토 화면의 추천 버전·제한 비교·호환 복원](LEARNING-LIFECYCLE.md)을 연결했다. 독립 자료와 품질 gate, 서명된 별도 실행 권한과 실제 LLM/가드 운영 canary·활성 버전/복원은 후속이다.
