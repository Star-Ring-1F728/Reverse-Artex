# 자동 shadow 관측과 검토용 추천 버전

**2026-11-09 운영 G09 후속:** [실제 운영 분류기 승격·복원과 독립 평가 준비](PRODUCTION-LEARNING.md)를 추가했다. 별도 품질 attestation·운영 승인/canary 후 collector가 모델을 실행하고 실제 조사 도구가 영수증을 소비한다. 기본 off이며 실제 독립 자료·OS 격리/운영 품질 수용은 후속이다.

**2026-11-09 G09 검증 경로:** [서명 라벨 입고·별도 선정과 후보 승격/복원](VERIFIED-LEARNING.md)을 추가했다. 운영자가 설치한 tenant별 공개키로 라벨과 추천 변경을 검증한다. 기존 로컬 경로는 정책 미설치 tenant에서 유지하며, 실제 LLM/가드 배포와 독립 품질·운영 수용은 후속이다.

2026-11-03. 수집기 안에서 검증한 사건 기억의 변경을 자동 관측하고, 운영자가 승인한 최신 관측으로 검토 화면의 추천 버전을 선택한다. 경량 metadata 후보의 추천만 제공하며 실제 LLM·가드·방어 정책을 교체하지 않는다. `independent_evaluation`과 `deployment_allowed`는 계속 false다.

## 자동 관측

1. 현재 학습 구현과 원래 학습 자료가 일치하는 후보로 shadow 계획을 시작한다.
2. 첫 관측과 새 사건·라벨 변경 전에 [검토 기준](CANDIDATE-REVIEW.md)을 고정한다.
3. 해당 계획의 **새 사건 자동 관측**에 근거를 입력하고 시작한다. 기본은 중지이며 명시적으로 시작한 계획만 자동 관측한다.
4. 수집기 소유 worker 한 개가 2초마다 원본 snapshot을 검증·동기화한다. 사건 기억 import와 라벨 쓰기는 같은 store 잠금 아래 예측→라벨 순서를 보존한다. 라벨 정정 후 비교도 새 snapshot으로 저장한다.
5. 저장 관측, worker의 마지막 성공·오류, 중단 사유를 확인한다. 새 자료가 없는 poll은 snapshot을 추가하지 않는다. source 검증이 실패하면 이전 결과를 성공으로 갱신하지 않는다.

관측은 검증된 legacy incident projection이 분모다. 전체 네트워크 트래픽·경보 없는 정상 모집단의 continuous coverage가 아니다. 재시작하면 명시적으로 켰던 관측만 동일 원장으로 재개한다. 새 source를 검증해 현재 상태를 포착하며, 중단 동안 관측하지 못한 자료를 이미 관측한 것처럼 기록하지 않는다. 라벨이 먼저 있던 사건, 과거·중복·변경된 증거의 제외 규칙은 [기존 shadow 계약](SHADOW-LEARNING.md)을 따른다.

현재 제어 기록은 `case-shadow-auto/2`다. 초기 로컬 `/1`의 source pin 없는 기록도 원래 JSON/hash를 유지해 읽고 blocked로 표시한다. 읽는 동안 원장을 고치거나 그 상태를 자동 재개하지 않는다. 알 수 없는 schema는 거부한다.

학습 원본·trainer/observer·자동 관측 구현의 pin이 달라지면 이전 이력은 읽고 자동 관측은 blocked다. 계획당 snapshot32개, 전체 계획16개, 자동 관측 변경64회와 기존 journal32MiB/8192기록 한도를 유지한다. 한도 도달을 무한 저장·자동 삭제·계획 교체로 숨기지 않는다. 별도 기준과 새로운 자료로 새 계획이 필요하다. 자동 관측 구현 pin이 바뀐 경우도 근거를 검토하고 명시적으로 다시 설정해야 한다.

자동 관측 중지와 추천 중지는 원본 sync에 의존하지 않으므로 원본 검증 오류 중에도 가능하다. 켜진 기능마다 전역 원장에 중지용 sequence1개·8192bytes와 변경 이력의 마지막 중지 slot을 논리적으로 예약한다. 일반 쓰기는 이 예약을 사용하지 못한다. 이는 앱 원장 예산이며 실제 디스크 고장·외부 프로세스의 디스크 고갈·fsync 실패를 해결하는 물리적 저장 예약은 아니다. 저장 실패는 fail-closed 오류로 남긴다.

## 검토용 추천 버전

**검토용 추천 버전**은 tenant별 현재 pointer와 변경 이력을 제공한다. 변경에는 이유·expected revision과 최신 shadow snapshot·승인 decision의 정확한 SHA가 필요하다. 승인·비교·추천 어느 것도 운영 배포 권한을 만들지 않는다.

- **제한 비교:** 현재 선택한 shadow의 최신 로컬 승인이 있어야 한다. 후보 비율은1–50%로 고정한다. run/tenant/case ID의 versioned hash bucket으로 후보와 단순 참고 기준을 나눈다. 라벨이나 feature로 분배하지 않는다. control은 기존 활성 LLM이 아닌 `all_alerts_suspicious`다. 중첩 제한 비교는 거부한다.
- **추천100% 사용:** 같은 제한 비교가 먼저 있어야 한다. 제한 비교를 시작하기 전에 예측한 사건은 새 표본으로 재사용하지 않는다. 이후 후보 bucket의 공격/정상 표본·전체 분모/coverage·기간·오류가 사전 기준을 충족하고, 최신 snapshot을 다시 승인해야 한다.
- **이전 버전 복원:** 과거100% 사용 기록이 있는 run만 선택할 수 있다. 그 버전의 현재 학습/관측 구현과 자료가 호환되고, 최신 관측을 새로 승인해야 한다. 새 버전을 임의로 rollback 명목으로100% 사용하는 경로는 없다. 원래 cohort cutoff를 복원한다.
- **추천 중지:** 최신 pointer revision과 이유로 중지한다. stale 상태나 원본 sync 실패에서도 가능하다.

추천은 저장된 예측에서 현재 pointer와 최신 승인 snapshot으로 계산한 읽기 전용 projection이다. 변경 SHA와 `projection_shadow_snapshot_sha256`로 재현하며 실제 요청에 추천을 전달했다는 receipt가 아니다. 새 사건·라벨·관측·검토 구현 변경으로 승인이 stale이면 추천을 비우고 `latest_review_required`로 중단한다. 운영자는 shadow의 원본과 분모를 확인하고 최신 관측을 검토한다. 반려·보류는 추천을 중단시킨다. 자동 승인·자동100% 승격은 없다.

추천 변경은 tenant당32회다. 모든 변경은 hash-chain journal에 Sync 후 공개한다. 재시작은 request/CAS·후보·review/snapshot binding·canary 조건을 재계산한다. 지원되는 과거 source pin은 검산 후 읽고 현재 실행에는 stale을 표시한다. 이전 단계 원장은 계속 읽지만 새 optional record를 모르는 과거 바이너리로 새 원장을 열지 않는다. 수집기를 멈추고 원본과 사건 기억을 함께 백업한다. store 확장으로 이전 후보의 trainer pin이 달라지므로 신규 실행은 원래 선정으로 새 후보를 만든다.

## 로컬 API

기존 loopback·bearer·same-origin·configured tenant 경계를 따른다. query/body는 아래 필드만 정확히 받으며 중복·추가·null·추가 JSON을 거부한다. POST body는8192bytes, Content-Type은 유효한 `application/json`이어야 한다. GET은 변경하지 않는다.

| Method | `/console/api` 뒤 경로 | 동작 |
| --- | --- | --- |
| GET/POST | `/cases/learning/automatic?tenant=alpha&run_id=...` | 자동 관측 상태/변경, GET은 worker 상태 포함 |
| GET/POST | `/cases/learning/advisory?tenant=alpha` | 추천 pointer·현재 projection·이력/변경 |

자동 관측 POST:

```json
{"expected_revision":0,"enabled":true,"reason":"별도 신규 사건의 관측 시작"}
```

추천 POST는 아래7개 필드가 모두 필요하다. action은 `canary`, `activate`, `rollback`, `stop`이다. stop은 run/두 SHA를 빈 문자열, percent를0으로 보낸다. activate/rollback은 percent100이다. reason은 trim 후1–1000자다.

```json
{"expected_revision":0,"action":"canary","run_id":"<run>","review_decision_sha256":"<latest approval>","shadow_snapshot_sha256":"<latest snapshot>","percent":10,"reason":"후보 추천의 제한 비교"}
```

동일 요청의 재전송은 이력을 늘리지 않는다. 다른 요청의 오래된 expected revision은409다. 수집 증거 동기화·학습/검토·활성 pointer는 구분하며, 다른 tenant의 run이나 임의 actor/배포 필드를 받지 않는다.
