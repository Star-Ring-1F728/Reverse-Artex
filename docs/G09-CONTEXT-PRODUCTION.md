# G09 v2 서명 승인형 조사 분류

`learning-context-production`은 완료된 v2 카나리를 현재 증거·서명 라벨로 다시 평가한 뒤, 별도 운영 승인에 따라 적격 사건 전체에 분류 참고값을 제공한다. 이 승인 경로를 추가할 때는 기존 24-feature 모델·학습기·평가기와 제한 카나리의 source pin을 유지하고 새 승인 경로와 평가 읽기 adapter를 별도로 pin했다. 이후 [공격 피드백 학습 개선](ATTACK-FEEDBACK-LEARNING.md)은 학습기를 변경하므로 runtime과 transitive source pin이 바뀐다. 기존 v2 자료를 새 버전에서 사용하려면 해당 문서의 명시적 재평가·승인 절차를 따른다.

후보는 stateless metadata 분류기이며 단일 stump와 검증된 제한 OR 규칙을 지원한다. 적용 범위는 detector가 만든 사건의 조사 분류이며, 정상 트래픽 전체나 임의 LLM의 배포를 뜻하지 않는다. `candidate_percent=100`, `mandatory_review_preserved=true`, `policy_mutations=0`이다. 기존 SDK/ACL·정책 집행의 권한 검사는 계속 적용한다.

## 활성화의 선행 조건

기존 [카나리 평가](G09-CONTEXT-CANARY-EVALUATION.md)를 끝내고 현재 품질 결과가 유효해야 한다. 양 분기에 각각 최소 60사건·공격/정상 각 30사건, 라벨/관측 coverage 100%, 실제 저장 예측 간 최소 3,600초, 미탐/오탐의 단측 95% Wilson 상한 각각 10% 이하, 같은 사건의 참고 기준 대비 비퇴행과 총오류 감소가 필요하다. 누락·미확정·실패와 기준 미달은 활성화를 막는다.

`context_production_approver`의 actor와 Ed25519 공개키는 canary approver·reviewer·custodian·evaluator·sensor·issuer와 구분한다. 설치한 키의 권한과 문서 결합을 코드가 검증한다. 실제 독립 검토와 외부 checkpoint의 진실성은 관리자가 확인한다. 공개 fixture의 자체 생성 역할 서명은 이 조건의 실제 충족 증거가 아니다.

기본 policy는 disabled다. 운영 키와 실제 독립 자료는 이번 개발에서 설치하지 않았다.

## 준비와 서명

수집기를 정상 종료하고 일관된 증거와 현재 case-memory를 사용한다. 경로는 파일시스템 운영자가 지정한다.

```sh
bin/learning-context-production -action policy-template \
  -canary-profile config.context-canary-profile.json \
  -approvers config.context-production-approvers.json \
  -out NEW_DISABLED_POLICY.json
```

[공개키 예제](../config.context-production-approvers.example.json)의 placeholder를 실제 별도 공개키로 교체한다. 관리자가 근거를 확인하여 새 policy를 명시적으로 enabled로 설치하고, [profile 예제](../config.context-production-profile.example.json)에 policy·원래 canary profile·새 production journal 경로를 설정한다.

```sh
bin/learning-context-production -action activate-prepare \
  -profile config.context-production-profile.json \
  -release-sha256 COMPLETED_CANARY_RELEASE_SHA \
  -plan-sha256 FROZEN_EVALUATION_PLAN_SHA \
  -evidence data/observe \
  -case-memory data/observe/case-memory/journal.jsonl \
  -until RFC3339_EXPIRY_WITHIN_CURRENT_QUALITY_VALIDITY \
  -key-id SEPARATE_PRODUCTION_APPROVER \
  -reason '검토한 근거와 적용 범위' -out NEW_APPROVAL_TEMPLATE.json
```

준비는 모델을 적용하거나 nonce를 소비하지 않는다. 승인 문서는 expected revision/head, action, policy·후보·canary release·평가 plan, 현재 검토 근거, 고정 만료와 nonce를 묶는다. 재평가 시각 자체만 바뀐 같은 근거는 같은 binding을 유지한다. 원본·라벨·관측 이력의 변경은 binding을 바꾼다.

별도 승인자는 내용을 확인한 뒤 `independent_review_confirmed`와 `external_review_checkpoint_sha256`에 실제 검토 근거를 기재한다. 서명 개인키는 승인자에게 남긴다.

```sh
bin/learning-context-production -action signing-bytes \
  -approval REVIEWED_PUBLIC_APPROVAL.json -out NEW_SIGNING_BYTES.bin
```

서명 domain은 `reverse-artex/context-production-approval/2`와 LF 한 바이트다. 출력 bytes에 Ed25519 서명하고 `signature_base64`를 채운다. 서명 제출은 최대 15분이며, 활성화 기한은 현재 품질 유효기간을 넘을 수 없다.

```sh
bin/learning-context-production -action approve \
  -profile config.context-production-profile.json \
  -approval SIGNED_PUBLIC_APPROVAL.json -evidence data/observe \
  -case-memory data/observe/case-memory/journal.jsonl -out NEW_RESULT.json
```

승인 직전에 증거·라벨을 다시 평가하고 policy/키를 다시 읽는다. 정정된 라벨, 폐기한 키, 다른 plan·후보, 유효기간 초과, stale revision/head, 잘못된 signature와 nonce 변경을 거부한다. 승인 결과를 저장한 뒤 output 전송에 실패하면 원래 서명으로 재조회할 수 있다. 같은 nonce의 재전송은 현재 상태를 반환하며 중지된 버전을 되살리지 않는다.

## 수집기와 실제 소비

```sh
reverse-artex -console -out data/observe -context-trust config.action-context-trust.json \
  -context-production-profile config.context-production-profile.json
```

Shadow·canary·production profile 중 하나를 선택한다. 현재는 등록된 단일 tenant와 별도 저장 예산을 사용한다. 기본 profile 미설정 상태에서는 활성화가 없다.

수집 commit과 같은 잠금에서 immutable snapshot을 만들고 잠금을 푼 뒤 재생·추론한다. 원본이 같으면 새 추론 sample을 저장하지 않아 idle polling이 이력 상한을 소모하지 않는다. 새 source는 실제 관측 영수증을 Sync한 뒤 노출한다. 이전 snapshot의 참고값을 새 사건 버전에 붙이지 않는다.

각 영수증은 activation·candidate·model·review·case·source·attempt SHA와 시각을 보존한다. 실제 조사 도구 `get_case`의 `v2_production_triage`에서 소비한다. 지연된 첫 모델 응답 뒤에도 도구 실행 시점에 다시 확인한다. 긴급 중지와 최종 참고값 반환은 같은 잠금에서 순서를 결정한다. 이미 전달한 과거 조사 기록은 유지한다.

재검증 결과 재사용은 동일 source bytes·검증한 plan/history·현재 라벨/trust·release head·activation에만 적용한다. 요청마다 현재 policy·키·품질 기한과 실제 관측 버전을 확인한다. 라벨 정정·키 폐기·원본 손상은 재사용된 결과로 가리지 않는다.

## 중지와 복원

인증 console API는 다음 두 경로를 제공한다.

- `GET /console/api/cases/context-production/status?tenant=alpha`
- `POST /console/api/cases/context-production/stop?tenant=alpha`

중지 JSON은 `{"expected_revision":1,"reason":"operator stop"}`이다. 기존 Host·same-origin·Bearer·tenant 검사를 적용하고 stale revision은 409다. 웹으로 키·policy·승인 문서·경로를 설치하는 API는 제공하지 않는다.

키가 폐기되거나 profile이 손상돼도 offline 긴급 중지를 할 수 있다.

```sh
bin/learning-context-production -action stop -journal data/context-production/journal.jsonl \
  -tenant alpha -expected-revision N -reason 'operator stop' -out NEW_STOP.json
```

`rollback-prepare`는 과거 이 원장에 활성화한 동일 후보/canary release를 대상으로 한다. 현재 원본·라벨·품질을 다시 평가하고 새로운 별도 승인·nonce·기한을 요구한다. 기한이 끝난 과거 승인 자체를 재사용하지 않는다.

원장은 단일 owner·revision CAS·hash chain·쓰기 후 Sync로 관리한다. 최대 32MiB·64개 변경이며 중지용 8KiB/한 변경을 남긴다. Sync가 불명확하면 현재 프로세스는 제공을 멈춘다. 부분 쓰기·손상 원본·미완료 관측 intent를 보존하고 자동 덮어쓰기나 takeover를 하지 않는다. 관리자에 의한 전체 파일/시각 교체 방어에는 별도 외부 checkpoint가 필요하다.

Offline `status`의 `REVALIDATION_REQUIRED`는 기록 존재를 뜻한다. 실제 수집기에서 현재 근거 검증과 추론 영수증을 확인한 상태는 `PRODUCTION_TRIAGE`다.


독립 품질 평가와 실제 운영 승인은 별도 절차를 따릅니다. [운영 학습 계약](PRODUCTION-LEARNING.md)
