# G09 운영 분류기 승격·복원과 독립 품질 평가 준비

2026-11-09 KST. G09가 학습한 **14개 사건 특징의 stateless metadata 분류기**를 collector의 실제 source 동기화 경로에 배포한다. 기본 설정은 off이며, 기존 추천 화면의 pointer와 별도 원장을 쓴다. 활성 버전은 새 실제 사건에 추론을 수행하고 영수증을 Sync한 뒤 실제 조사 도구 `get_case`의 `production_triage` 문맥으로 소비된다. LLM 가중치·Ollama 모델·V2 Decisions 모델을 교체하는 배포 계약이 아니다. V2는 입력 schema와 운영 저장소가 달라 이 artifact를 직접 로드하지 않는다.

## 개발 완료 범위와 독립 평가의 경계

이번 개발은 운영 모델의 사전 평가·승격·canary·복원·자동 추론과 독립 평가 인계 인터페이스다. 공개 합성 검증에서 쓰는 보관자/평가자/배포 승인자의 서명은 **테스트용 주장**이다. 실제 독립 관리자·미개봉 자료·OS 계정/저장소 격리·실제 표본 품질 수용을 완료한 결과가 아니다. `PREPARED_NOT_READY`만으로 품질 통과나 배포를 허용하지 않는다.

운영자가 별도 경로로 확인한 보관자·평가자·배포 승인자 공개키가 필요하다. 역할의 actor와 공개키는 서로, 그리고 활성 라벨 reviewer/기존 release approver와 중복되지 않아야 한다. 코드가 검증하는 것은 그 키에 권한이 있고 특정 주장을 서명했다는 사실이다. 사람/조직의 독립성과 실제 gold 접근 경계는 관리자가 외부 증거로 확인해야 한다. 같은 개발자에게 키 역할만 여러 개 주는 것으로 독립성을 충족했다고 표시하지 않는다.

## 1. 운영 정책 사전 고정

`config.learning-trust.example.json`에 `evaluation_custodian`, `independent_evaluator`, `production_approver` 역할을 추가했다. 예제 공개키는 placeholder로 유효하지 않다. 실제 키를 제품 데이터나 테스트에 미리 설치하지 않는다. 기존 신뢰 정책은 다음 revision으로만 갱신하며 키 변경 시 과거 후보/계획/배포는 stale로 차단된다.

`config.learning-production.example.json`은 기본 `enabled:false`다. 새 운영 정책은 파일시스템 운영자가 collector를 종료한 뒤 `learning-control`로 설치한다. 웹 콘솔은 정책·신뢰 키를 설치하거나 기준을 낮출 수 없다. disabled 정책에서도 정직한 사전 준비를 만들 수 있지만 cohort/품질 입고와 배포는 막힌다. 켜려면 독립 역할을 준비하고, 다음 운영 정책 revision으로 명시적으로 설정한 뒤 그 정책으로 새 평가 계획을 만든다.

```powershell
.\bin\learning-control.exe -action production-policy-template -journal data/collector/case-memory/journal.jsonl -tenant alpha
.\bin\learning-control.exe -action production-policy -journal data/collector/case-memory/journal.jsonl -tenant alpha -input production-policy.local.json
```

기본 독립 평가 기준은 전체60건·공격30·정상30·최소3 family/3 source group, coverage100%, 개별30초 이내, false-benign/false-attack의 **단측95% Wilson 상한 각각10% 이하**다. 기준 모델보다 두 오류가 늘지 않고 전체 오류가 엄격히 감소해야 한다. family별 두 클래스와 비퇴행도 확인한다. 동률·보류·timeout·누락을 성공으로 합치지 않는다. 이 수치는 초기 incident-triage 운영 정책이며 모든 위협·서비스에 적합한 검증 목표를 보장하지 않는다.

표본 기준·오류 상한·canary 기간/표본·평가 유효기간은 operator policy → preregistered plan에 결합한다. 모델/학습 작업은 변경하지 못한다. Wilson 계산은 독립 Bernoulli 표본 가정을 가진다. source group 이름 수만으로 독립성을 증명하지 않으며 실제 출처/중복·시간 블록의 타당성은 관리자가 검증해야 한다. 현재 평가 모집단은 기존 수집기의 경보에서 투영한 사건이며 경보 없는 정상 트래픽 전체를 대표하지 않는다.

## 2. 후보·기준 모델과 평가 계획 동결

검증 라벨 선정 `/2`로 생성한 현재 `fit_complete` 후보만 사용할 수 있다. 일반 로컬 라벨의 선정 `/1` 후보나 바뀐 라벨·원본·trainer pin은 거부한다. `quality-prepare`는 사건/라벨/holdout을 읽어 새 정답을 만드는 작업이 아니다. 후보·모델·14개 feature schema·trainer/runtime source·현재 incumbent·운영 정책·trust·학습 증거 제외 목록 SHA를 먼저 고정한다.

```powershell
.\bin\learning-control.exe -action quality-prepare -journal data/collector/case-memory/journal.jsonl -tenant alpha -candidate-id CANDIDATE_ID
.\bin\learning-control.exe -action quality-status -journal data/collector/case-memory/journal.jsonl -tenant alpha -plan-id PLAN_ID
```

반환의 `capsule` 객체가 인계 artifact이고 `capsule_sha256`가 별도 전달할 pin이다. UTF-8 JSON으로 `capsule` 객체만 내보낸다. `quality-status`의 전체 wrapper를 평가 CLI 입력으로 쓰지 않는다. 계획 ID는 응답에서 보관한다. prepare 한 번은 새로운 사전등록이며 계획은 journal당16개로 제한된다. 기존 계획/실패 결과를 고쳐 다음 후보의 성공으로 바꾸지 않는다.

데이터/외부 조건이 없으면 `PREPARED_NOT_READY`, 보관자가 서명한 봉인이 입고되면 `SEALED_READY_FOR_EVALUATION`이다. 평가자의 별도 결과가 들어오기 전에는 `QUALITY_ACCEPTED`가 되지 않는다. disabled 정책·키/원본/구현 변경·유효기간 초과는 blocker로 표시한다. 정책/구현 변경 뒤 과거 원장을 수정해 현재라고 표시하지 않는다.

## 3. 별도 보관자의 cohort 봉인

보관자는 개발/runtime/worker가 gold를 읽을 수 없는 계정·스토리지에서 독립 자료를 준비한다. 개발 채팅/제품 저장소에는 실제 gold를 넣지 않는다. provenance 원본, 표본 출처/기간·중복배제·독립 판정·gold 접근 거부/관리자 읽기 성공의 증거는 관리자가 별도로 보관한다.

`CohortSeal`은 plan ID·tenant·trust·dataset ID·inputs/gold/provenance SHA·정렬된 전체 증거 멤버십 SHA·전체 표본 수·family/source group 수·training_overlap0·독립 보관/접근 경계 주장·발급/만료·보관자 key ID를 서명한다. schema는 `case-quality-cohort/1`, 서명 domain은 `reverse-artex/quality-cohort/1\n`이다. `CohortSigningBytes` 또는 CLI `-action cohort-bytes`가 정확한 bytes를 제공한다. 표준 base64 Ed25519만 수락한다. 만료는 신규 입고 기한이며 최대24시간이다.

입고는 `POST /console/api/cases/learning/quality/cohort?tenant=alpha` 또는 `-action cohort-import`를 사용한다. 같은 plan의 정확한 재전송은 새 기록을 만들지 않는다. 같은 dataset ID·inputs/gold/provenance·멤버십 pin을 다른 plan으로 재사용하면 거부한다. 이력과 거부 표본을 보존하고 이미 피드백을 받은 holdout을 새 독립 자료로 포장하지 않는다.

라벨 없는 `case-quality-inputs/1`은 dataset ID와 최대512개 row다. row는 opaque ID, family, source group, 정렬된 `evidence_keys_sha256`, 그 목록의 canonical SHA(`evidence_sha256`), 고정 길이14개 정수 feature만 가진다. 멤버십 key는 기존 정규화된 증거 참조의 `(stream, tenant, asset, event_id, line_sha256)` canonical digest다. 학습 capsule에 제외 key를 고정하며 같은 증거의 부분 공유·중복 row도 거부한다. 동일 feature vector라는 이유만으로 서로 다른 원본을 합치지는 않는다.

`case-quality-gold/1`은 별도 private artifact로 dataset ID와 정확한 row ID별 `confirmed_attack`, `confirmed_benign`, `uncertain`, `disputed`만 가진다. source hash는 이 계약의 Go JSON canonical document digest이며 원본 파일 bytes의 SHA와 같다고 가정하지 않는다. `LearningDocumentDigest`를 사용한다. JSON의 중복·별칭·누락·null·추가 필드와 라벨을 숨긴 입력 필드는 거부한다.

## 4. 라벨 없는 실행과 별도 채점

같은 동결 source의 `learning-evaluate` 실행 파일을 신뢰 인계 경로로 배포한다. 실행 명령에는 별도 전달한 capsule pin을 반드시 준다. 출력은 새 파일에만 쓰고 fsync하며 기존 파일을 덮어쓰지 않는다. `run`은 gold/scorer 옵션을 받으면 capsule이나 입력을 열기 전에 거부한다. 입력 파일은 일반 파일·최대2MiB, 목록은 계약 상한으로 제한한다.

```powershell
.\bin\learning-evaluate.exe -action run -capsule capsule.json -expected-capsule-sha256 TRUSTED_CAPSULE_SHA -inputs inputs.json -out predictions.json
# 별도 evaluator 계정/환경에서만:
.\bin\learning-evaluate.exe -action score -capsule capsule.json -expected-capsule-sha256 TRUSTED_CAPSULE_SHA -inputs inputs.json -predictions predictions.json -gold private-gold.json -out report.json
```

runtime은 feature vector만 예측하며 labels/family/source/ID는 예측 함수에 넣지 않는다. scorer는 같은 source/model로 예측을 재계산해 바꾼 output을 실패로 처리한다. 누락·timeout·invalid·변조는 전체 계획 분모에 남고 합격하지 못한다. 불확실/상충 라벨은 학습 정답이나 성공으로 합치지 않고 coverage를 낮춘다. class/family 분모, 기준 모델 비교, 실패 수·관측 지연·신뢰구간 gate의 이유를 남긴다. 추가 개선이 없으면 rejected다. 개별 지연은 고정 feature vector에 대해 두 모델 예측 함수를 호출한 구간의 millisecond 측정이다. 파일 읽기·입력 검증·프로세스 시작·collector polling/큐를 포함한 end-to-end 지연 수용을 이 수치로 대체하지 않는다.

CLI score의 종료0은 채점 artifact 생성 성공이다. `report.passed`가 품질 판정이다. CLI는 보관자/평가자 독립성이나 OS gold 격리를 스스로 인증하거나 서명하지 않는다. 실제 권한 분리·소프트웨어 출처와 외부 운영 증거는 관리자 책임이다.

## 5. 평가자의 결과 입고

별도 `independent_evaluator` 키가 `SignedQualityReport`를 서명한다. schema는 `case-quality-attestation/1`, domain은 `reverse-artex/quality-report/1\n`이다. 정확한 report·tenant·trust·독립성/격리 주장·key ID·발급/만료에 결합한다. evaluator는 보관자·배포 승인자·학습 라벨 reviewer와 actor/공개키가 달라야 한다.

`POST /cases/learning/quality/report?tenant=alpha` 또는 CLI `-action quality-import`가 입고한다. 서명과 모든 commitment·분모·수치 관계·미리 고정한 기준의 재계산을 확인한다. 거부 결과도 감사 이력에 보존하며 plan당 결과는 하나다. 결과를 바꿔 재수용하거나 같은 gold를 재튜닝하지 않는다. 평가가 정정/철회돼야 하면 운영자는 즉시 production stop을 수행하고 trust/policy·새 독립 자료/계획으로 재평가한다. 현재에는 별도 결과 철회 record API를 제공하지 않는다.

`QUALITY_ACCEPTED`는 지정 evaluator의 유효한 주장과 기준 수치를 수락했다는 상태다. 임의 서명 결과를 현실의 독립성 증명으로 확대하지 않는다. 실제 운영 활성화는 다음 단계의 별도 production 승인과 canary가 필요하다.

## 6. 실제 운영 승격·복원

`SignedProductionChange`는 schema `case-production-authorization/1`, domain `reverse-artex/production-change/1\n`을 쓴다. `production_approver` 키가 trust, exact request, 발급/만료를 서명한다. request는 expected revision, action, quality plan/결과/운영 정책/runtime source pin, 사전 shadow review run/decision, canary pin, 비율, 근거를 모두 고정한다. 같은 서명 재전송은 새 버전을 만들지 않는다. 서명 bytes는 CLI `-action production-bytes` 또는 `ProductionSigningBytes`로 얻는다.

- **canary:** 독립 품질 수락·신선도·현재 학습/런타임/정책·최신 shadow의 로컬 승인 후1–50%로 시작한다. 기준 모델은 동결한 실제 incumbent이며 첫 배포는 `all_alerts_suspicious`다. 중첩 canary와 다른 incumbent을 기준으로 평가한 계획을 거부한다.
- **activate:** 운영 canary 시작 이후 새 사건에 실제로 수행한 영수증과 이후 발급·서명한 라벨이 필요하다. 후보 branch의 표본/공격/정상/coverage·95% 상한·관측 시각 span·기준 branch를 확인한 정확한 `canary_sha256`에 별도 서명을 요구한다. 사전 shadow 승인은 canary 시작 때 동결하고 이 운영 근거가 다음 승격을 담당한다. 새 reject/defer는 serving을 차단한다.
- **rollback:** 과거 activate 기록이 있는 동일 plan/model만100%로 복원한다. 새 서명·현재 trust/policy·feature/runtime/state 호환·유효한 품질 결과가 필요하다. 이 모델은 stateless이므로 재개할 optimizer/checkpoint 상태는 없다. 향후 다른 상태 schema/임의 LLM 파일은 지원하지 않는다. 유효기간이 끝났거나 구현이 바뀐 구버전은 복원 대신 stop과 새 검증이 필요하다.
- **stop:** expected revision과 근거만으로 즉시 중지한다. signing key·원본 재검증·평가 수락이 필요하지 않다. 각 켜진 production pointer에 원장 sequence1개/8192bytes와 마지막 중지 이력 slot을 논리적으로 예약한다. 실제 디스크 장애를 해결하는 물리 예약은 아니다.

운영 canary 분모는 새 사건의 최초 추론이다. 배포 전 사건은 별도 baseline 제외 수로 남는다. 새 case ID라도 기존/학습 증거와 겹치거나 판정이 먼저 있었으면 성공 표본이 아니다. 동일 case의 증거 revision을 새 독립 사례로 늘리지 않으며 변경·미판정·상충·중복을 제외/대기 분모에 남긴다. 시간은 실제 관측·후속 판정의 span이며 프로세스의 연속 uptime 증명은 아니다. cohort 구성과 결과를 확인한 후 승인한다.

## 7. 실제 소비와 장애 경계

서명된 pointer가 저장되면 console profile의 단일 source observer가2초마다 실제 collector snapshot을 검증·동기화한다. 자동 shadow가 꺼져 있어도 운영 serving이 켜져 있으면 동작한다. ingress 쓰기/정책 writer 잠금과 분리하며, 모델 실패/blocked가 기존 규칙 탐지 권한을 바꾸지 않는다.

현재 case revision별 model/feature/runtime/release SHA·14개 feature·출력·branch·원본 SHA·시각·mandatory-review 유지·정책 변경0의 추론 영수증을 같은 원장에 Sync한다. 읽기 GET은 새 추론을 만들지 않는다. 배포 후 실제 사용 여부는 `latest_receipts`와 사건 상세의 `production_inference`로 확인한다. `runtime_enabled`는 설정/게이트 상태이며 영수증 없이 실제 사용량을 추정하지 않는다.

실제 `localassistant.get_case`는 이 영수증을 `production_triage`로 모델의 tool observation에 포함한다. 읽기 전 source를 다시 검증하고, 현재 사건/활성 release와 맞는 영수증만 제공한다. label/정책/승인 권한을 예측에 부여하지 않고 기존 근거·필수 검토·contain/release 권한 검사를 유지한다. 이미 전달된 문맥을 소급 취소하지 않으며 버전 pin을 보존한다.

원본/학습 라벨·trust/키·운영 정책·feature/구현 변경, 평가 유효기간 초과, 검토 철회 때 새 serving과 현재 영수증 노출을 차단한다. 재시작은 요청 CAS·서명·모델·원본·canary·실제 예측을 당시 순서대로 재계산한다. 임의 model output과 바깥 checksum을 함께 고친 변조도 거부한다. 과거 기록은 보존하며 이를 모르는 과거 strict-reader 바이너리로 새 journal을 열지 않는다.

한도: 평가 계획16개, 단일 cohort512건/32family·학습 제외 key4096개, 운영 변경 tenant당32회, 추론 영수증4096개, 기존 journal32MiB/8192기록·record2MiB. cap 도달 시 자동 삭제/새 원장 교체/실패 표본 제외를 하지 않는다. 오류를 확인하고 명시적으로 stop·운영 인계를 수행한다.

## API / CLI 진입점

모든 API 경로는 `/console/api/cases/learning` 뒤에 붙으며 기존 bearer·loopback·same-origin·configured tenant 검사를 적용한다. query는 tenant와 명시한 plan_id만, JSON은 exact 필드·32KiB 상한이다. 변경 전 source sync는 stop을 제외하고 필수다. CLI는 기존 journal을 독점하며 collector 종료 후 마지막 동기화 상태를 대상으로 한다.

| Method | 경로 | CLI action |
| --- | --- | --- |
| POST | `/quality/prepare?tenant=alpha` (`candidate_id`) | `quality-prepare -candidate-id ID` |
| GET | `/quality?tenant=alpha&plan_id=ID` | `quality-status -plan-id ID` |
| POST | `/quality/cohort?tenant=alpha` | `cohort-import` |
| POST | `/quality/report?tenant=alpha` | `quality-import` |
| GET | `/production?tenant=alpha` | `production-status` |
| POST | `/production?tenant=alpha` | `production-change` |
| POST | `/production/stop?tenant=alpha` (`expected_revision`, `reason`) | `production-stop -expected-revision N -reason ...` |

정확한 Go JSON 계약은 `internal/casememory/quality_types.go`, `production_types.go`에 있다. 보관자/평가자/승인자가 서명 전에 모든 pin·대상·기준·상태를 검토한다. 예제에는 실제 키·서명·운영 모델 활성화를 넣지 않는다.

## 독립 환경 재개 조건

관리자는 독립 출처·사전 판정·표본 블록·feature/label provenance와 gold 접근 거부, evaluator 신원/키 수명주기·소프트웨어 인계 pin을 마련한다. 이를 확인한 외부 역할의 봉인과 결과만 실제 운영 준비로 받는다. 개발용 공개 반복 시험은 이 조건을 대신하지 않는다. 로컬 관리자가 journal·바이너리·신뢰 설정을 통째로 과거 상태로 바꾸는 공격에는 외부 checkpoint가 추가로 필요하다.



## 2026-11-09 최종 검증

최종 소스/빌드·검증 영수증에 Go 전체1,590 pass/9 skip/0 fail·vet·세 실행 파일 빌드와 최종 HTTP17/17·37/37·운영37/37을 기록했다. 활성 모델의 실제 새 사건 추론, 조사 도구의 영수증 소비, 강제 중단 후 복원과 중지/rollback·키 폐기를 검증했다. 실제 LLM/외부 API 호출0, 기본 운영 정책 설치0이며 실제 독립 품질·OS gold 격리는 미입증이다. 모든 시험 자원 정리와 source/binary pin 일치를 확인했다.


## 후속 로컬 OS 검증과 품질 결과

로컬 blind 평가·OS gold 격리를 별도 구현하고 실행했다. 실제 별도 UID·capability 제거·namespace/chroot에서 같은 gold inode에 대한 runtime EACCES와 scorer 읽기를 확인했고 120/120건을 채점했다. 후보는 공격 60건 중 33건 미탐, 정상 60건 모두 오탐으로 **품질 불합격**이다. 후보와 기준은 결과 후 바꾸지 않았으며 운영 승격하지 않았다. 기본 정책은 계속 OFF다. 같은 개발 관리자가 호스트를 관리하므로 외부 독립성은 false로 서명하고 독립 수용 근거로 입고하지 않는다. 이전 합성 lifecycle 검증의 격리 미입증 상태와 구분해 별도 결과 영수증에 기록했다.


후속 [feature 분리 가능성 진단](G09-FEATURE-DIAGNOSTICS.md)을 후보 HTTP·CLI와 evaluator 전용 사후 진단에 추가했다. 소모된 cohort에서 최소 경험적 오류 27/120과 미탐 예산 내 최소 오탐 60을 확인해 현 feature의 정보 부족을 기록했다. 이 진단은 품질 승인·운영 승격·새 모델 학습을 수행하지 않는다.


후속 [feature v2 관측·새 학습·봉인 평가](G09-CONTEXT-V2.md)를 구현했다. 180건으로 새 후보를 학습·동결한 뒤 새 통제 자료 240건에서 미탐 0/120·오탐 6/120, 오탐 단측 95% 상한 9.38%를 확인했다. 실제 gold 접근 차단과 전건 채점을 검증했으며, 외부 독립성·운영 승격은 승인하지 않았다.
