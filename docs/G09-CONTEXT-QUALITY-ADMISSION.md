# G09 v2 품질 결과 반입 사전검증 — 2026-11-11

`learning-context-quality`는 24-feature v2 후보의 공개 capsule·품질 보고서와 별도 평가자의 서명을 검증한다. 현재 공개키, sensor/issuer trust, 동결한 기준, 전체 분모와 수치를 대조해 다음 릴리스 검토에 전달할 결과를 새 파일에 저장한다. **모델 설치·운영 pointer·정책 변경은 수행하지 않으며 모든 결과의 `deployment_allowed`는 false다.**

기존 운영 경로의 14-feature `/1` 객체로 변환하거나 배열을 채워 넣지 않는다. `internal/contextadmission`을 별도로 추가하여 기존 v2 trainer/scorer·shadow 및 v1 production의 frozen source를 유지했다. 기존 413개 Go/모듈/포함 자원이 동일하고, 공개 v2 capsule과 현재 runtime pin도 일치한다.

## 현재 신뢰와 별도 평가 서명

운영자가 확인한 authority trust와 context trust를 파일로 지정한다. Capsule에 든 키만으로 스스로 반입 권한을 만들 수 없다. Policy의 두 trust SHA와 현재 파일, 후보·계획·capsule·별도 평가 envelope의 pin이 모두 같아야 한다. Authority는 `label_reviewer`, `evaluation_custodian`, `independent_evaluator` 각 1개이며 actor·공개키가 서로 달라야 한다. 폐기된 키와 sensor/issuer 공개키를 authority로 재사용하는 경우도 거부한다.

새 policy schema는 `case-context-admission-policy/2`, scope는 `incident_triage_context/2`다. 기본은 disabled다. Feature/runtime·이번 admission 검증기 source SHA를 함께 고정하며 코드나 trust가 바뀌면 과거 policy를 조용히 재수용하지 않는다. Report 유효기간은 최대 24시간이고 품질 기준을 낮추는 policy 필드는 없다. [설정 형식 예제](../config.context-quality-policy.example.json)의 placeholder는 그대로 사용할 수 없다.

기존 scorer report의 `external_independence_proven=false`, `production_approval=false`는 유지한다. 채점 프로그램이 사람·환경의 독립성이나 배포를 스스로 인증하는 값이 아니다. 별도 evaluator의 `case-context-independent-quality/2` envelope가 정확한 report·capsule·현재 trust·외부 custody checkpoint SHA·독립성/격리 주장·발급/만료를 서명한다. Ed25519 domain은 `reverse-artex/context-independent-quality/2\n`이며 `\n`은 실제 LF 1 byte다.

Custodian의 기존 v2 cohort 서명도 다시 검증한다. Cohort의 독립 보관과 gold 접근 거부, evaluator envelope의 독립성/격리가 모두 필요하다. **코드가 확인하는 것은 설치된 키의 주장과 문서 결합이다.** 관리자·조직의 실제 독립성, checkpoint 원본과 gold 접근 경계는 운영자가 외부 증거로 확인해야 한다. 개발용 키와 로컬 통제 자료를 실제 독립 평가로 표시하지 않는다.

## 수치·분모 재검산

후보·모델·24-feature/runtime·training recipe/source/input/gold·review/trust pin, plan ID, capsule SHA, cohort 서명과 report의 입력/gold/capsule 결합을 확인한다. 학습과 같은 source/input/gold pin 및 선언된 training overlap은 거부한다. 새 report가 동일 holdout을 재사용했는지 판정하는 영속 사용 원장은 이번 CLI에 없다. 후속 릴리스 경로가 cohort 재사용 방지를 함께 적용해야 한다.

Report의 `passed`만 신뢰하지 않고 다음을 다시 계산한다.

- 전체 60건 이상, 공격/정상 각 30건 이상, 최소 3 family/3 source group, coverage 100%, 개별 30초 이하
- 전체와 family별 confusion matrix 정수 범위·클래스/표본 합계, family 누락·중복·순서, 참고 기준 `all_alerts_suspicious`의 수치
- 단측 95% Wilson 미탐/오탐 상한 각각 10% 이하, 참고 기준 대비 두 오류의 비퇴행과 전체 오류의 엄격한 감소, family별 두 클래스·비퇴행
- 누락·실패·unknown 분모와 원래 실패 이유, 선언된 confidence bound 및 `passed/reasons`와 재계산 결과의 일치

실패한 예측은 frozen scorer의 참고 기준에서도 실패 수치로 남을 수 있다. 이를 정상 참고 예측으로 덮어쓰지 않는다. 실패·불확실 사례가 있는 유효한 보고서는 전체 계획 분모를 유지한 `BLOCKED` 결과가 된다. 서명·schema·pin·수치 내부 관계 자체가 잘못된 문서는 오류로 거부하며 출력 파일을 만들지 않는다.

## CLI 사용

기본 build의 도구 목록에 새 명령을 포함했다. 개별 빌드도 가능하다.

```powershell
go build -o bin/learning-context-quality.exe ./cmd/learning-context-quality
.\bin\learning-context-quality.exe -action policy-template `
  -tenant alpha -authority-trust PUBLIC_AUTHORITIES.json `
  -context-trust PUBLIC_CONTEXT_TRUST.json -out NEW_DISABLED_POLICY.json
```

Template는 현재 공개키와 코드 pin에 결합한 disabled policy다. 운영자는 독립 역할·근거를 확인한 뒤 별도 파일에서 enabled를 명시하고 정확한 policy SHA를 전달한다. Canonical SHA는 Go typed JSON의 SHA256(`contextlearning.Digest(policy)`)이며, 들여쓰기를 포함한 파일 바이트의 SHA와 다르다. 같은 파일에 든 자체 checksum만으로 외부 출처를 인증하지 않는다.

Evaluator는 서명 전에 전체 envelope를 검토한다. 서명 bytes 생성에는 공개 문서만 사용하고 개인키는 해당 평가자에게 남긴다.

```powershell
.\bin\learning-context-quality.exe -action endorsement-bytes `
  -endorsement UNSIGNED_ENDORSEMENT.json -out NEW_SIGNING_BYTES.bin

.\bin\learning-context-quality.exe -action check `
  -policy INSTALLED_POLICY.json -expected-policy-sha256 POLICY_SHA_FROM_OPERATOR `
  -capsule PUBLIC_CAPSULE.json -expected-capsule-sha256 CAPSULE_SHA_FROM_TRUSTED_CHANNEL `
  -authority-trust CURRENT_PUBLIC_AUTHORITIES.json `
  -context-trust CURRENT_CONTEXT_TRUST.json `
  -endorsement SIGNED_INDEPENDENT_ENDORSEMENT.json -out NEW_DECISION.json
```

입력은 bounded regular file과 strict JSON만 받는다. 중복/unknown/null 필드, v1 schema, gold·training input·private-key 옵션을 거부한다. 지원하지 않는 옵션은 파일을 열기 전에 거부한다. 출력은 새 파일에만 쓰고 Sync/Close 오류를 반환하며 기존 결과는 덮어쓰지 않는다.

Exit 0은 판정 파일 생성 성공이다. 품질 반입 조건은 `accepted`와 `reasons`로 확인한다. 독립 보관/평가 미주장·정책 disabled·유효기간 초과·품질 미달이면 `BLOCKED`다. 조건을 모두 만족해도 상태는 `QUALITY_ACCEPTED_RELEASE_APPROVAL_REQUIRED`이고 실제 배포 권한은 없다. `decision_sha256`는 로컬 문서 pin이며 승인자의 전자서명이 아니다. 이후 소비자는 현재 입력과 시각으로 다시 검증해야 한다.

이 단계는 read-only 사전검증으로, 영속 cohort 중복 원장·별도 release approver·v2 serving/canary·활성화/rollback 연결은 후속이다. 실제 운영 정책을 설치하거나 기존 v1 release를 변경하지 않았다.
