# 새 사건의 수동 shadow 관측

2026-11-02 KST. G09-C는 고정한 오프라인 후보를 **관측 시작 이후의 별도 사건**에 적용하고, 예측 이후에 기록된 운영자 판정과 비교하는 제품 기능이다. 예측과 판정 비교만 저장하며 기존 탐지·정책·모델 provider에 연결하지 않는다. 독립 holdout·실제 운영 승격 판정은 제공하지 않는다.

## 사용 순서

1. **사건 기억 → 학습 대상 선정 → 학습 후보 생성**에서 `학습 완료`인 후보를 연다. 현재 학습 source 버전과 원래 case/label binding이 맞아야 한다.
2. **이 후보로 새 사건 관측 시작**을 누른다. 당시 알려진 전체 사건, candidate/model/feature/trainer/evaluator pin, 시작 시각·원장 순서를 계획에 고정한다. 같은 후보·같은 시작 기준·같은 evaluator의 요청은 같은 계획을 반환한다.
3. 결과 검토를 진행하려면 첫 관측과 새 사건·라벨 변경 전에 **관측 결과 검토 → 기준 고정**을 수행한다. [기준·승인/반려 계약](CANDIDATE-REVIEW.md)을 따른다.
4. 이후 새 사건이 수집되면 **현재 사건 관측·평가**를 누른다. 원본을 동기화한 뒤 새로운 사건의 현재 증거와 예측을 고정한다. **새 사건 라벨을 저장하기 전에 먼저 관측해야 한다.**
5. 운영자가 원본을 별도로 검토해 라벨을 기록한다. 다시 관측·평가를 누르면 이미 고정한 예측과 이 후속 라벨을 비교한다. 새 학습이나 예측 교체는 하지 않는다.
6. 라벨이 정정되면 저장 관측에 갱신 필요가 표시된다. 다시 평가하면 새 revision에 정정 결과를 저장하고 과거 revision은 그대로 보존한다. 이력 버튼으로 이전 수치·예측·라벨 hash를 조회할 수 있다.

기본 관측은 **버튼/API 호출 때 수행하는 수동 snapshot**이다. 2026-11-03에는 사전 기준과 명시적 시작을 요구하는 [자동 관측](LEARNING-LIFECYCLE.md)을 별도로 연결했다. 둘 다 전체 트래픽을 가로채는 continuous shadow 배포나 전체 coverage 보장은 아니다. 목록의 시작 이후 모든 요청 수가 아니라, 검증한 원본 동기화에서 파생된 관측 가능한 legacy incident가 분모다.

## 별도 자료와 분모

계획 시작 전에 존재한 모든 사건 ID는 baseline으로 고정해 평가 cohort에서 제외한다. 학습 fit에서 제외됐던 사건과 기존 사건의 후속 revision도 새 사건으로 재사용하지 않는다. 이후 처음 저장된 case여도 첫 경보나 증거 event 시각이 시작 전이면 늦은 과거 자료로 제외한다. 저장 순서와 event-time cutoff를 함께 사용하지만 센서가 선언한 시각의 외부 인증을 추가하는 것은 아니다.

새 cohort의 각 사건은 최초 포착한 case SHA·source snapshot·feature vector·예측 시각·원장 순서를 고정한다. 라벨은 예측 함수의 입력이 아니다. 예측 전에 라벨 이력이 한 번이라도 있으면 그 사건은 나중에 라벨을 바꾸어도 prospective 점수에 넣지 않는다.

| 상태 | 의미 |
| --- | --- |
| `awaiting_label` | 예측은 고정됐고 후속 운영자 라벨을 기다림 |
| `scored` | 고정한 동일 증거에 대한 후속 confirmed 판정과 비교 |
| `prelabeled_before_prediction` | 최초 관측 전 라벨 이력이 있어 제외 |
| `preexisting_observation` | 시작 전 증거/경보가 늦게 들어온 사건 |
| `overlapping_evidence` | baseline 또는 다른 shadow 사건과 원본 증거를 공유 |
| `evidence_changed` | 예측 뒤 증거 revision이 바뀌어 비교할 수 없음 |
| `stale_label` | 라벨이 고정한 증거에 결합되지 않음 |
| `uncertain` / `disputed` | 판정 보류·상충으로 점수에서 제외 |

각 저장 관측에서 `total = scored + awaiting_label + excluded`를 유지한다. 참고 기준과 후보의 confusion count는 `scored` subset에서만 계산한다. 무라벨·제외 사례가 분모에서 사라지지 않으며, label coverage와 성능 수치를 함께 읽어야 한다. `predicted`는 제외로 바뀐 사건의 기존 예측도 포함할 수 있으므로 `scored`와 다르다.

학습 후보와 별도 사건이라는 조건만으로 주체·환경·판정자 독립성을 증명하지 않는다. 경보 없는 정상 모집단, 독립 관리자·봉인 자료, calibration/시간별 신뢰구간, 로컬 최소 표본/기간·사전 검토 기준은 [별도 검토 단계](CANDIDATE-REVIEW.md)에 연결했다. 독립 품질 수용 gate는 포함하지 않는다. 모든 관측은 `independent_evaluation=false`, `deployment_allowed=false`다.

## 변경과 재시작

GET은 마지막으로 저장한 비교 결과를 반환하고 점수를 자동으로 바꾸지 않는다. 현재 동기화된 사건·라벨이 달라졌으면 `refresh_required=true`다. 과거 revision을 조회해도 최신 자료로 오인하지 않게 이 값을 표시한다.

후보의 원래 선정에 있던 case/label binding이 바뀌거나 trainer/evaluator source가 바뀌면 `reevaluation_required=true`이며 새 관측을409로 거부한다. 기존 계획·모든 관측은 읽을 수 있다. 새 사건이 추가되는 것 자체는 shadow의 정상 동작이므로, 학습 원래 binding이 그대로면 관측을 이어갈 수 있다. 새 자료 때문에 후보의 전체 선정 최신성이 바뀌는 것과 학습 원본이 정정되는 것을 구분한다.

계획·각 snapshot은 기존 hash-chain journal에 append/Sync한 뒤에만 성공한다. Snapshot마다 previous hash와 revision, 관측 당시 case/label binding과 분모·비교 결과를 보존한다. 재시작은 당시 순서의 사건/라벨 상태와 이전 관측에서 예측·제외·점수를 재계산해 대조한다. 저장 prediction/metric과 바깥 checksum을 함께 고쳐도 재계산과 다르면 거부한다. 전체 로컬 원장의 관리자 교체나 외부 출처 인증은 이 검증의 보장 범위가 아니다.

평가 의미는 plan schema에 따라 선택한다. `case-shadow-plan/1`은 `shadow_v1.go`의 보존된 v1 재생 규칙을 사용한다. 이후 동작을 바꿀 때 새 schema/분기를 추가하고 v1 재생·feature 계약은 유지해야 한다. 같은 v1 계약에서 source fingerprint만 달라진 기록은 검산 후 읽고, 최신 evaluator가 아니므로 추가 관측은 막는다. 지원하지 않는 schema는 현재 규칙으로 임의 해석하지 않는다.

상한은 전체 shadow 계획16개, 계획당 snapshot32개이며 기존 case512개·journal32MiB·단일 기록2MiB·전체8192기록 한도를 함께 적용한다. 같은 입력에서 반복 관측은 동일 snapshot을 반환해 기록을 늘리지 않는다. 한도 초과는507이며 이력을 자동 삭제하거나 실패 사례를 교체하지 않는다. 목록은 요약, 상세는 snapshot 하나와 bounded 이력 요약만 반환한다.

## 업데이트·원장 호환

이 단계에서 store 소스가 확장되어 G09-B 바이너리로 만든 후보의 trainer fingerprint는 최신 source와 달라진다. 과거 후보·원장은 보존하고 같은 저장 선정으로 새 후보를 생성한 뒤 shadow를 시작한다. 과거 후보의 source pin을 고쳐 최신이라고 표시하지 않는다. 변경 없는 기존 학습 알고리즘과 stored pin으로 이전 후보의 replay 검산을 유지한다.

기존 record에서 optional shadow 필드는 생략되므로 예전 원장을 읽는다. Shadow record가 생긴 뒤 이 필드를 모르는 이전 바이너리로 해당 원장을 열지 않는다. 종료한 상태에서 원본 collector와 case-memory를 함께 백업한다.

## 로컬 API

기존 콘솔 bearer·loopback host·same-origin·configured tenant 경계를 따른다. 모든 mutation은 source sync 성공 후 실행하고, body는 해당 필드 한 개만 정확히 받아1024bytes로 제한한다.

| Method | /console/api 뒤 경로 | JSON/동작 |
| --- | --- | --- |
| POST | `/cases/learning/shadow?tenant=alpha` | `{"candidate_id":"..."}` 계획 시작 |
| POST | `/cases/learning/shadow/capture?tenant=alpha` | `{"run_id":"..."}` 예측 포착·후속 판정 snapshot 저장 |
| GET | `/cases/learning/shadow?tenant=alpha` | 계획 요약 목록 |
| GET | `/cases/learning/shadow/detail?tenant=alpha&run_id=...` | 최신 snapshot·계획·변경 상태 |
| GET | 위 상세 경로에 `&revision=1` | 해당 immutable snapshot 조회 |

중복/모호한 query, 알 수 없는 body 필드·중복·별칭·null·추가 JSON을 거부한다. 활성 정책·승격·모델/권한 변경 필드는 없다.

다음 후속은 독립 자료와 평가 gate, 사전 검토된 shadow 운영 방식, 제한 canary와 활성 버전·호환 복원이다. 이번 수동 관측 비교가 기존 실제 모델 품질·미개봉 평가·운영 수용 판정을 갱신하지 않는다.
