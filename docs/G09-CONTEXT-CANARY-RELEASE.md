# G09 v2 서명 승인·제한 카나리·중지·복원 — 2026-11-11

`learning-context-release`는 [v2 품질 반입 검증](G09-CONTEXT-QUALITY-ADMISSION.md)을 다시 수행한 뒤, 별도 승인자가 서명한 제한 카나리 버전을 영속 원장에 기록한다. Collector는 이 버전으로 실제 사건을 관측하며 Qwen 조사 도구의 `get_case`에 `v2_canary_triage`를 전달한다. 기본 설정에는 카나리 profile이 없고, policy template도 disabled다. **범위는 조사 참고값의 제한 비교다. 모든 결과는 `deployment_allowed=false`, `policy_mutations=0`, `mandatory_review_preserved=true`를 유지한다.**

100% 운영 활성화나 자동 차단 명령은 추가하지 않았다. 기존 24-feature v2 trainer/scorer와 품질 반입 검증기의 source pin은 유지한다. v1 운영 객체로 변환하거나 기존 운영 모델을 교체하지 않는다.

## 승인과 영속 버전

승인 역할은 `context_canary_approver`다. Authority의 reviewer/custodian/evaluator와 다른 actor·Ed25519 공개키를 요구하며 sensor/issuer 공개키를 재사용할 수 없다. 운영자가 설치한 공개키와 현재 품질 policy·context trust를 다시 확인한다. 로컬 개발 서명이나 관리자·조직의 실제 독립성을 코드가 인증하는 것은 아니다.

승인은 tenant, 예상 revision, 이전 원장 head, action, 정확한 bundle/policy/baseline SHA, 후보 비율 1–50%, 고정 종료 시각, 새 nonce와 검토 사유를 묶는다. 서명 domain은 `reverse-artex/context-canary-release/2\n`이며 마지막 `\n`은 LF 1 byte다. 승인 제출 유효기간은 최대 15분이다. 수용 후 카나리 lease는 별도로 서명한 고정 종료 시각까지며 현재 품질 결과의 유효기간을 넘을 수 없다.

원장은 strict JSONL hash chain, revision CAS, 쓰기 후 Sync, 단일 프로세스 owner로 관리한다. 동일한 서명·nonce의 재전송은 원래 기록만 반환하며 중지된 버전을 재활성화하지 않는다. 같은 nonce의 변경된 요청은 거부한다. 새 package 반입은 이미 사용한 plan ID, dataset ID, input/gold/source/membership/predictions pin 중 하나라도 재사용하면 거부한다. 이 중복 원장은 해당 journal 범위다.

`rollback`은 이전에 승인되어 원장에 남아 있는 동일 bundle만 대상으로 한다. 새 승인 서명·현재 revision/head·현재 품질 검증·새 관측 baseline과 기한이 필요하다. 중지 후 같은 package 복원은 가능하지만 실행 중 같은 package로 하는 무의미한 rollback은 거부한다. 새 카나리/복원은 collector를 정상 종료한 상태에서 수행하고 재시작한다. 실행 중 collector가 원장 owner를 보유해 offline 승인과 경합하지 않는다.

## 실제 관측과 조사 도구

승인 직전의 검증된 증거 snapshot에서 tenant 사건 ID와 증거 key를 baseline으로 고정한다. 기존 사건과 baseline 증거를 포함한 사건은 비교 대상에서 제외한다. 새 사건은 candidate SHA·tenant·case ID의 결정적 bucket으로 후보/참고 분기에 배정한다. 참고 분기는 `suspicious` 기준값을 전달하고 후보 예측을 노출하지 않는다. 내부 shadow 영수증에는 양 분기를 재검산할 수 있는 원본 후보 예측이 남으며 이는 운영자 파일 접근 범위다. 분기 정보는 기밀 접근 통제 수단이 아니다.

기존 shadow 실행기가 snapshot 복구 검증과 24-feature 모델 관측을 수행하고 먼저 영수증을 Sync한다. API 조회나 Qwen 도구 호출 자체는 새 표본을 만들지 않는다. 정확한 최신 snapshot SHA, case SHA, candidate SHA, 이번 승인 이후 시작한 시도의 영수증만 전달한다. 관측 불가·학습 증거 중복·baseline 제외 사유는 그대로 남긴다. Collector 입력이 늘었으나 관측이 아직 따라오지 않았다면 이전 snapshot의 판단을 새 사건에 붙이지 않는다.

현재 설정·키·품질·lease를 snapshot 수집 전후와 참고값 반환 전에 다시 검사한다. Qwen 첫 모델 응답이 지연될 수 있으므로 `get_case` 실행 시점에도 현재 사건과 카나리를 다시 조회한다. 중지/만료/폐기/설정 불일치 후에는 새 조사 도구 응답에서 참고값이 빠진다. 이미 동기화된 과거 조사 이력은 보존한다. 실제 모델 서비스의 추론 품질 검증은 이 연결 검증에 포함하지 않는다.

## 중지와 복구 경계

Console에는 인증된 `GET /console/api/cases/context-canary/status?tenant=alpha`와 `POST /console/api/cases/context-canary/stop?tenant=alpha`만 추가했다. Host·same-origin·Bearer·단일 tenant query를 기존 console guard로 제한한다. Web으로 path, 공개키, policy, bundle, 승인 문서를 받는 경로는 없다. Status에는 내부 사건별 후보 예측을 포함하지 않는다.

중지 본문은 `{"expected_revision":1,"reason":"operator stop"}`의 정확한 JSON contract다. 오래된 revision은 409이며 worker를 중지시키지 않는다. 올바른 중지 요청은 worker와 참고값을 먼저 멈춘 뒤 원장에 기록한다. Sync가 실패하면 현재 프로세스는 중지 상태와 owner를 유지하고 추가 사용을 거부한다. 저장이 실패한 중지를 전원 장애 뒤까지 보장하는 것은 아니다. 현재 공개키가 폐기되거나 품질 결과가 만료되어도 별도 offline `stop`은 가능하다.

원장은 최대 32MiB·128개 변경·16개 package로 제한하고 실행 중 긴급 중지용 8KiB·1개 변경 여유를 남긴다. Package마다 관측 이력은 활성 64개/8MiB, archive 2개, 전체 32MiB로 제한한다. 관측 경로는 `JOURNAL.observations/BUNDLE_SHA/`로 고정하여 수집기 `-out` 변경으로 이력을 초기화하지 않는다. Rollback/재시작도 같은 경로를 사용한다. 끝나지 않은 intent·손상 원장·torn line을 지우거나 자동 새 이력으로 우회하지 않는다. 잘못된 카나리 profile/이력은 카나리만 중지하고 기본 증거 수집은 계속한다.

이 수치는 논리 파일 길이/개수 상한이며 물리 디스크 예약이나 실제 ENOSPC 실험 결과가 아니다. 전체 원장·관리자 파일을 과거 백업으로 교체하는 공격은 독립 외부 원장 없이 검출할 수 없다. 기록에 나타난 policy/admission revision의 역행·동일 revision 다른 내용은 거부한다. 코드 pin이 달라진 과거 원장은 검토를 요구하며 자동 변환하지 않는다. 손상/미완료 원본과 archive를 보존하고 별도 검토 후 복구해야 한다.

## 설치 형식과 CLI

[Profile 예제](../config.context-canary-profile.example.json)와 [별도 승인 공개키 목록 예제](../config.context-canary-approvers.example.json)를 제공한다. Placeholder는 실행 가능한 키가 아니다. Profile 상대경로는 profile 파일 위치 기준이다. private key는 승인자에게 남기고 이 CLI에 입력하지 않는다. Bundle은 `{"capsule": PUBLIC_V2_CAPSULE, "endorsement": SIGNED_INDEPENDENT_ENDORSEMENT}`다.

```powershell
go build -o bin/learning-context-release.exe ./cmd/learning-context-release
.\bin\learning-context-release.exe -action policy-template `
  -admission-policy CURRENT_ADMISSION_POLICY.json `
  -authority-trust CURRENT_PUBLIC_AUTHORITIES.json `
  -context-trust CURRENT_PUBLIC_CONTEXT_TRUST.json `
  -approvers SEPARATE_PUBLIC_APPROVERS.json -out NEW_DISABLED_RELEASE_POLICY.json
```

Template에는 현재 코드·품질 policy pin을 넣는다. 운영자가 실제 독립 근거와 키를 확인하여 admission/release policy를 명시적으로 enabled로 설치한다. Policy SHA는 `contextlearning.Digest`의 Go typed JSON SHA이며 들여쓰기를 포함한 파일 바이트 SHA와 다르다. 준비 명령은 서명용 공개 문서만 만들며 원장 상태를 바꾸지 않는다. Collector가 중지되어야 baseline이 서명과 제출 사이에 바뀌지 않는다.

```powershell
.\bin\learning-context-release.exe -action canary-prepare `
  -profile INSTALLED_PROFILE.json -bundle PUBLIC_BUNDLE.json `
  -evidence data/collector -percent 10 -until REVIEWED_CANARY_END_RFC3339 `
  -key-id release-approver-1 -reason "reviewed canary scope" -out NEW_UNSIGNED_APPROVAL.json
.\bin\learning-context-release.exe -action signing-bytes `
  -approval NEW_UNSIGNED_APPROVAL.json -out NEW_APPROVAL_SIGNING_BYTES.bin
# 별도 승인자가 내용을 확인하고 Ed25519 서명 후 signature_base64를 채운다.
.\bin\learning-context-release.exe -action approve `
  -profile INSTALLED_PROFILE.json -bundle PUBLIC_BUNDLE.json `
  -evidence data/collector -approval SIGNED_APPROVAL.json -out NEW_APPROVED_RESULT.json
.\reverse-artex.exe -console -config config.json `
  -context-trust config.action-context-trust.json -context-canary-profile INSTALLED_PROFILE.json
```

기한은 현재 품질 결과 안의 실제 검토 시각으로 지정한다. `rollback-prepare`는 같은 준비 옵션으로 과거 승인 bundle의 새 서명 문서를 만든다. `package -journal JOURNAL -bundle-sha256 SHA -out NEW_BUNDLE.json`으로 원장에 저장된 공개 bundle을 내보낼 수 있다. 중지한 collector의 상태는 `status -profile PROFILE -out NEW_STATUS.json`, 키/profile 장애 시 긴급 중지는 `stop -journal JOURNAL -tenant alpha -expected-revision N -reason REASON -out NEW_STOP.json`이다. 출력은 새 파일에만 쓰며 기존 증거를 덮어쓰지 않는다.
