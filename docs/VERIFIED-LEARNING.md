# G09 검증 라벨 입고·선정과 서명된 후보 승격·복원

**2026-11-09 운영 G09 후속:** [실제 운영 분류기 승격·복원과 독립 평가 준비](PRODUCTION-LEARNING.md)를 추가했다. 별도 품질 attestation·운영 승인/canary 후 collector가 모델을 실행하고 실제 조사 도구가 영수증을 소비한다. 기본 off이며 실제 독립 자료·OS 격리/운영 품질 수용은 후속이다.

2026-11-09 KST. 제품의 기존 사건 기억 → 후보 → shadow → 검토 → 추천 버전 흐름에 **운영자가 지정한 공개키 기반의 검증 경로**를 추가했다. 서명된 라벨의 정확한 사건·증거 binding을 검증하고 별도 선정으로 학습한다. 승격·복원은 검토 화면의 경량 metadata 모델 추천 버전을 대상으로 한다. 실제 LLM·가드·방어 정책의 배포 권한을 만들지 않는다.

## 신뢰 설정

`config.learning-trust.example.json`을 별도 파일로 복사해 tenant와 공개키를 설정한다. 예제의 placeholder는 유효한 키가 아니므로 그대로 설치할 수 없다. 개인키는 검토자/승인자의 외부 서명 경로에 보관하며 collector와 이 CLI가 읽거나 생성하지 않는다.

- `label_reviewer`는 근거를 검토한 라벨을 서명한다. `release_approver`는 특정 후보 실행의 최신 검토·관측 SHA에 결합된 추천 버전 변경을 서명한다. 다른 role의 키로 요청을 대체할 수 없다.
- 키 ID·actor·role·공개키·폐기를 tenant별 신뢰 정책에 고정한다. 키32개, 정책 revision1부터 연속 증가, 기존 journal 전체8192기록/32MiB 상한을 적용한다. 최초 revision은1이며 같은 revision의 다른 내용·과거/건너뛴 revision을 거부한다.
- 같은 정책의 재설치는 원장에 쓰지 않는다. 키 교체/폐기는 다음 revision에서 명시적으로 기록한다. 과거 정책과 라벨은 삭제하거나 고치지 않는다.
- 신뢰 정책을 최초 설치한 tenant는 이후 추천 canary/activate/rollback에 서명을 요구한다. 서명 없는 기존 선정이나 API로 되돌아가 우회할 수 없다. 기존 추천은 blocked가 되며 **중지**는 서명 없이 계속 가능하다. 정책이 없는 tenant의 기존 로컬 경로는 유지한다.
- 정책 변경은 모든 기존 검증 후보·관측의 실행을 stale로 만든다. 그대로 유지된 reviewer 키의 이전 라벨은 새 선정에 사용할 수 있지만 새 정책 pin으로 후보·관측·검토를 다시 만들어야 한다. 폐기·교체된 reviewer 키의 라벨은 선정에서 제외한다.

collector에서 먼저 수집 증거를 동기화하고 종료한 뒤, 명시적인 기존 journal에 정책을 설치한다. `learning-control`은 collector와 동일한 배타 잠금을 사용하며 오타 경로에 새 journal을 만들지 않는다. 실제 키를 테스트나 기본 데이터에 미리 설치하지 않는다.

```powershell
.\bin\learning-control.exe -action trust -journal data/collector/case-memory/journal.jsonl -tenant alpha -input learning-trust.local.json
.\bin\learning-control.exe -action status -journal data/collector/case-memory/journal.jsonl -tenant alpha
```

신뢰 정책 교체는 파일시스템 운영자의 명시적 CLI 작업이다. 웹 콘솔에는 정책 설치/교체 API를 두지 않았다. 새 원본을 지속 검증하는 collector를 재시작한 뒤 아래 서명 입고 API를 사용한다. CLI 입고·선정은 collector를 종료한 상태의 **마지막 동기화 snapshot**을 대상으로 하며 라이브 원본 재검증을 대신하지 않는다.

## 라벨 서명과 입고

`SignedLabel`은 다음 필드를 모두 정확히 한 번씩 요구한다. 중첩 객체에도 중복·별칭·알 수 없는 필드·누락·null·추가 JSON을 허용하지 않는다. 최대 JSON32KiB, 근거는 기존1–1000자다.

```json
{
  "trust_sha256": "<GET learning/trust의 hash>",
  "schema": "case-verified-label/1",
  "tenant_id": "alpha",
  "case_id": "<case ID>",
  "expected_label_revision": 0,
  "previous_label_sha256": "",
  "case_sha256": "<현재 사건 SHA>",
  "source_snapshot_sha256": "<그 사건 버전의 source snapshot SHA>",
  "evidence_sha256": "<선정 binding의 evidence SHA>",
  "value": "confirmed_attack",
  "reason": "검토한 독립 근거와 판정 사유",
  "basis": "evidence_review",
  "key_id": "label-reviewer-1",
  "issued_at": "<UTC RFC3339 시각>",
  "expires_at": "<발급 이후 최대24시간 이내>",
  "signature_base64": "<외부 Ed25519 서명>"
}
```

검토자는 `confirmed_attack`, `confirmed_benign`, `uncertain`, `disputed` 중 하나와 원본 근거를 판단한다. `basis`는 `evidence_review`만 허용한다. 공개 fixture supervision이나 모델의 자기 판정을 입고 과정에서 확정 라벨로 자동 변환하지 않는다. 유효 서명은 지정한 키 소유자의 주장임을 검증하며 그 주장 자체의 진실·판정자 독립성·실제 사건 모집단을 증명하지 않는다.

서명 bytes는 `casememory.LabelSigningBytes` 또는 `learning-control -action label-bytes -input label.json`으로 얻는다. payload는 `reverse-artex/verified-label/1\n` domain과 Go JSON 직렬화이며 `signature_base64`를 빈 문자열로 만든다. 다른 JSON 정렬/공백/시간 직렬화를 직접 만들어 서명하지 않는다. 외부 서명기는 이 bytes를 Ed25519로 서명해 표준 base64를 `signature_base64`에 넣는다. CLI는 키를 받는 옵션이 없다.

종료된 collector의 기존 원장에서 template를 만들 수도 있다. template 생성은 라벨 저장이나 판정을 하지 않는다. 판정 시각이 관측보다 먼저라면 해당 라벨을 이후 예측의 평가에 사용할 수 없으므로, 실제 검토 직후 발급·서명한다.

```powershell
.\bin\learning-control.exe -action label-template -journal data/collector/case-memory/journal.jsonl -tenant alpha -case-id CASE_ID -key-id label-reviewer-1 -value uncertain -reason "추가 근거 검토 필요"
.\bin\learning-control.exe -action label-import -journal data/collector/case-memory/journal.jsonl -tenant alpha -input signed-label.json
```

입고는 현재 신뢰 정책 SHA·reviewer role·서명·입고 기한·tenant·case·현재 revision·이전 라벨 SHA·사건 내용·source snapshot·evidence SHA를 모두 검증한다. Store 입고 단계는 잘못된 서명을 라벨 쓰기와 라벨 처리에 따른 자동 관측 전에 거부한다. 라이브 API의 source sync는 별도 선행 단계이므로 요청이 거부되더라도 새로 검증한 원본 사건은 동기화될 수 있다. 자동 관측이 켜진 경우 유효한 라벨을 쓰기 전에 예측을 고정한다. 저장 proof에는 서명 원본과 수락 당시 신뢰 pin을 보존하고, actor는 정책에서 읽는다. 호출자가 actor를 지정하지 못한다.

정확한 재전송은 여전히 현재인 저장 영수증을 반환하며 이력을 늘리지 않는다. 이후 라벨/사건 변경·정책 변경 뒤 과거 요청을 재전송해 되돌릴 수 없다. admission 기한은 신규 입고에 적용하며 이미 수락한 증거의 보관 기한이나 추천 버전 TTL이 아니다.

## 검증 학습 데이터 선정

별도 `/cases/selection/verified` 또는 CLI `-action select`를 사용한다. 선정 schema는 `case-learning-selection/2`이고 신뢰 정책 SHA를 함께 고정한다. 일반 로컬 선정 `/1`과 섞이지 않는다.

현재 증거에 결합된 확정 라벨 중 현재 정책의 reviewer 키가 여전히 허용하는 서명만 적격이다. 서명 없는 로컬 `confirmed_*`는 `unverified_label_authority`로 제외한다. 보류·상충·미판정·stale·중복/공유 증거의 기존 제외 사유를 보존한다. 단일 tenant의 전체 사건을 `total = eligible + excluded`로 유지하며 제외 사례도 사라지지 않는다. 서명 라벨이라도 같은 증거를 독립 표본으로 늘리지 않는다.

```powershell
.\bin\learning-control.exe -action select -journal data/collector/case-memory/journal.jsonl -tenant alpha
.\bin\learning-control.exe -action candidate -journal data/collector/case-memory/journal.jsonl -tenant alpha -selection-sha256 SAVED_SELECTION_SHA
```

후보 생성은 기존 dataset/feature/trainer·fit 상한·quarantine 계약을 재사용한다. 라벨 정정·증거 변경·신뢰 정책 변경 뒤 과거 선정으로 학습하면409에 해당하는 conflict다. source/config/feature/model·선정·라벨 pin과 분모를 그대로 저장한다. 새 필드가 없는 과거 원장은 기존 해시를 유지해 재생하며, 구현 fingerprint가 바뀐 이전 후보로 신규 관측을 조용히 재개하지 않는다.

## 서명된 승격과 복원

검증 선정으로 생성한 후보에서도 기존 순서를 따른다.

1. 별도 신규 사건의 shadow 계획을 시작하고 첫 관측 전에 검토 기준을 고정한다.
2. 예측을 먼저 저장하고 이후 발급·서명한 라벨을 입고한다. 최신 관측을 평가하고 운영자가 `approve_for_evaluation`을 남긴다.
3. 별도 release 승인자가 현재 신뢰 pin·정확한 요청을 서명해 canary1–50%를 시작한다.
4. canary 시작 이후 후보 bucket에 들어온 신규 표본이 사전 기준을 충족해야 한다. 최신 관측을 다시 검토·서명해 activate100%를 요청한다.
5. rollback100%는 과거 실제 activate 기록이 있는 동일 run만 선택한다. 현재 학습/관측/신뢰 정책과 자료가 호환되고 최신 승인·서명이 있어야 한다. 신규 후보를 rollback 명목으로100% 사용하지 못한다.

`SignedAdvisory` 계약은 아래와 같다. `request`는 기존 추천 변경의7개 필드를 모두 요구한다. signing bytes는 `casememory.AdvisorySigningBytes` 또는 CLI `-action advisory-bytes -input release.json`으로 얻으며 domain은 `reverse-artex/verified-advisory/1\n`이다.

```json
{
  "schema": "case-verified-advisory/1",
  "tenant_id": "alpha",
  "trust_sha256": "<현재 신뢰 정책 SHA>",
  "request": {
    "expected_revision": 0,
    "action": "canary",
    "run_id": "<shadow run ID>",
    "review_decision_sha256": "<최신 approve_for_evaluation SHA>",
    "shadow_snapshot_sha256": "<그 승인이 검토한 최신 snapshot SHA>",
    "percent": 10,
    "reason": "사전 기준을 확인한 제한 비교"
  },
  "key_id": "release-approver-1",
  "issued_at": "<UTC RFC3339 시각>",
  "expires_at": "<발급 이후 최대24시간 이내>",
  "signature_base64": "<외부 Ed25519 서명>"
}
```

승격 시 모든 scored 평가 라벨도 검증 서명과 현재 증거 binding이 있어야 한다. signed `issued_at`이 최초 예측보다 먼저인 판정은 prospective 승격 근거로 거부한다. label signer의 키로 release 서명을 대신할 수 없다. 기한이 지난 새 승인·위조·tenant/대상/비율 변경·오래된 CAS·중첩 canary·사전 표본으로의 activate는 거부한다.

서명된 pointer는 정확히 승인·서명한 snapshot과 decision에 묶인다. 이후 관측/검토가 바뀌면 `signed_release_refresh_required`로 추천을 비운다. 다음 activate 또는 과거 활성 run의 rollback도 새 승인·서명을 요구한다. canary 표본이 부족하면 stop 후 새 canary를 명시적으로 시작한다. 서명 없는 최신 로컬 승인만으로 예전 서명을 새 snapshot의 승인으로 해석하지 않는다.

정책/원본/구현의 변화도 기존 pointer를 blocked로 만든다. 기존 `stop`은 서명·신규 source sync·최신 품질 수용 없이 수행할 수 있다. 새 서명 경로가 정책 쓰기·LLM provider·가드 변경에 연결되지는 않는다. `independent_evaluation=false`, `deployment_allowed=false`와 기존 실모델·독립 holdout/운영 수용 보류를 유지한다.

## 라이브 API

collector 재시작 후 기존 bearer·loopback·same-origin·configured tenant 검사를 그대로 적용한다. query는 `tenant` 하나만 받는다. POST body32KiB와 exact JSON 계약을 적용하며, 변경 전 source sync가 실패하면 진행하지 않는다. console bearer로 trust를 설치/교체할 수 없다.

| Method | `/console/api` 뒤 경로 | 동작 |
| --- | --- | --- |
| GET | `/cases/learning/trust?tenant=alpha` | 설치한 공개 trust와 pin |
| POST | `/cases/label/verified?tenant=alpha` | SignedLabel 입고 |
| GET/POST | `/cases/selection/verified?tenant=alpha` | 검증 선정 미리보기/불변 저장 |
| POST | `/cases/learning/advisory/verified?tenant=alpha` | SignedAdvisory canary/activate/rollback |

후보 생성·shadow·검토·중지는 기존 API를 재사용한다. 기존 `/cases/learning/advisory` 응답의 `verified_authorization_required`는 해당 tenant의 서명 경로 사용 여부다. source 오류 중 중지는 기존 unsigned stop endpoint로 가능하다.

## 저장·검증 범위

trust·라벨 proof·검증 선정·signed release는 같은 journal의 기존 append/Sync·hash chain·OS 배타 잠금·크기/개수 상한을 사용한다. 쓰기 실패 시 성공 pointer를 먼저 공개하지 않으며, 재시작은 당시 정책·서명·CAS·선정·모델·관측·검토·canary/복원 조건을 순서대로 재생한다. Signature payload와 바깥 checksum을 함께 바꾼 라벨도 서명 검증에서 거부한다.

구현 검증은 합성 사건·별도 테스트 키만 사용한다. 실제 확정 라벨/독립 관리자의 입고, 독립 표본·통계 품질, 외부 서명자의 신원/키 관리 운영, OS 격리, 실제 LLM/가드 배포·복원은 이번 개발의 실증 결과가 아니다. 로컬 관리자가 전체 journal·바이너리·신뢰 설정을 함께 과거 상태로 교체하는 공격에는 별도 외부 checkpoint가 필요하다.

새 optional record/필드가 있는 원장은 이를 모르는 과거 strict-reader 바이너리로 열지 않는다. 백업은 collector를 종료하고 원본과 case-memory를 함께 보존한다. 새 빌드의 signed 후보가 과거 trainer/observer pin을 조용히 재사용하지 않는다.
