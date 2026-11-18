# 사건 기억과 라벨 이력

**2026-11-09 G09 검증 경로:** [서명 라벨 입고·별도 선정과 후보 승격/복원](VERIFIED-LEARNING.md)을 추가했다. 운영자가 설치한 tenant별 공개키로 라벨과 추천 변경을 검증한다. 기존 로컬 경로는 정책 미설치 tenant에서 유지하며, 실제 LLM/가드 배포와 독립 품질·운영 수용은 후속이다.

2026-11-01 KST. M7의 로컬 사건·라벨·학습 데이터 선정 연결을 제공한다. 외부 유료 API나 모델 서버 없이 기본 웹 콘솔에서 사용한다.

## 사용

1. `start.bat` 또는 `sh start.sh`로 실행하고 터미널의 콘솔 링크를 연다.
2. **사건 기억 → 수집 증거 동기화**를 누른다. 실제 수집기의 HTTP/host 경보를 사건으로 저장한다. 파일 분석의 샘플은 별도 메모리에서 실행되므로 이 목록에 들어오지 않는다.
3. Tenant를 고르고 사건을 연다. 자산, 경보 시각, 증거 hash, 원본 event/alert 참조와 저장된 사건 버전을 확인한다.
4. **공격 확인 / 정상 확인 / 보류 / 상충** 중 판정과 근거를 입력하고 **라벨 이력 저장**을 누른다. 기존 판정을 정정하면 새 revision을 추가한다.
5. **학습 대상 선정**을 누른다. 전체·선정·제외 건수와 사건별 제외 사유를 확인한다. **선정 기록·해시 보기**에서 불변 선정 ID를 보관할 수 있다.
6. 라벨을 정정한 뒤 **저장한 선정의 재평가 필요 여부 확인**을 누르면 영향을 받은 사건이 표시된다. 새로고침/재시작 후의 이전 선정은 보관한 ID로 아래 saved API에서 조회한다.

라벨의 `confirmed_*`는 이 로컬 콘솔 운영자가 원본을 검토해 기록한 판정이다. 경보나 LLM 출력이 자동으로 확정 라벨이 되지 않는다. 작성자는 `local-operator`로 기록되며 별도 개인별 신원 인증을 뜻하지 않는다. 기존 콘솔 키 소유자는 설정된 모든 tenant를 관리할 수 있고, 다른 tenant를 지정한 사건 조회는 거부된다.

## 증거와 정정 계약

- 동기화는 수집기의 ingestion lock 안에서 bounded immutable snapshot을 캡처하고 lock을 해제한 후 기존 detector replay를 검산한다. 완전한 event/alert/evaluation commit 및 원본 참조를 검증한 동일 snapshot에서 사건을 투영한다. 실패한 수집기·미완료 원본은 가져오지 않는다.
- 각 사건 버전은 원본 event/alert line SHA-256, 원본 식별자·tenant·asset, 전체 source snapshot SHA-256, 저장 시각과 사건 내용 hash를 가진다. 원본 데이터는 기존 collector 파일에 남는다.
- 내용이 같은 사건을 다시 동기화하면 버전을 늘리지 않는다. 새 버전은 기존 증거·경보를 포함해야 하며, 증거 변경·기존 사건 누락/rollback은 거부한다. 저장한 원본 hash는 외부 출처 인증이나 독립 보관 증명이 아니다.
- 라벨은 현재 사건 내용 hash, 이전 라벨 hash, 순차 revision, 근거와 작성 시각에 묶인다. 저장 직전 source 동기화를 수행하므로 화면을 연 뒤 증거가 바뀌었거나 다른 검토가 저장되면 HTTP 409로 재조회가 필요하다.
- 새 사건 증거가 들어오면 기존 라벨은 보존되지만 `label_current=false`가 된다. 현재 증거를 다시 검토해 새 라벨을 기록해야 학습 선정에 사용할 수 있다.

## 학습 데이터 선정

선정은 단일 tenant의 모든 저장 사건을 포함하고 제외 사례도 분모에 남긴다. 현재 증거 버전에 묶인 `confirmed_attack` / `confirmed_benign`만 후보가 된다.

| 제외 사유 | 의미 |
| --- | --- |
| `unlabeled` | 판정 이력 없음 |
| `stale_label` | 판정 이후 증거 버전 변경 |
| `uncertain` | 보류 판정 |
| `disputed` | 상충 판정 |
| `duplicate_evidence` | 다른 사건과 같은 원본 증거를 공유 |
| `conflicting_labels` | 공유한 증거에 서로 다른 판정이 기록됨 |

같은 원본 증거가 겹치면 관련 사건들을 독립 표본으로 중복 선정하지 않는다. WAF/app request fusion이나 독립 표본 출처의 인증은 이 legacy incident 투영으로 추가하지 않는다. 선정 기록은 사건·라벨·증거 hash와 제외 사유를 고정하고, 이후 사건/라벨/선정 결과의 변화가 있으면 재평가 필요를 반환한다. 같은 내용의 선정 저장은 동일 ID를 재사용한다.

선정 뒤 [오프라인 학습 후보](OFFLINE-LEARNING.md)를 생성·비교하고 정정 영향을 확인할 수 있다. 외부 모델 학습 provider, G09 공개 fixture 학습기의 운영 데이터 입고, 독립 holdout, shadow/canary, 활성 모델 승격/rollback은 후속이다. 기존 정책 writer·승인·호스트 집행 권한을 추가하지 않는다.

학습 완료 후보는 [새 사건 수동 shadow 관측](SHADOW-LEARNING.md)에 연결해 예측을 먼저 고정하고 후속 판정과 비교할 수 있다.

관측 결과의 [기준 사전등록·운영자 검토](CANDIDATE-REVIEW.md)와 결정 이력을 같은 원장에 보존한다. 계획당32개의 결정 상한을 적용한다.

## 내부 HTTP API

모든 경로는 동일 origin·loopback host와 `Authorization: Bearer <콘솔 접속 키>`를 요구한다. 센서 토큰으로는 사용할 수 없다. Query 값은 URL encoding한다. 기본 응답 상한은 8 MiB다.

| 메서드 | 경로 (`/console/api` 뒤) | 기능 |
| --- | --- | --- |
| POST | `/cases/sync` | source replay 검산과 사건 저장 |
| GET | `/cases?tenant=alpha` | 해당 tenant 사건 요약 |
| GET | `/cases/detail?tenant=alpha&case_id=...` | 사건 버전·증거 참조·라벨 이력 |
| POST | `/cases/label?tenant=alpha&case_id=...` | 라벨 revision 추가 |
| GET | `/cases/selection?tenant=alpha` | source 동기화 후 현재 선정 미리보기 |
| POST | `/cases/selection?tenant=alpha` | source 동기화 후 불변 선정 저장 |
| GET | `/cases/selection/saved?tenant=alpha&sha256=...` | 저장 선정과 현재 사건 기억 비교 |

라벨 JSON은 다음 네 필드를 정확히 한 번씩 요구한다. 알 수 없는 필드·중복·대소문자 별칭·null·추가 JSON을 거부한다. `expected_label_revision`은 현재 라벨 이력 개수(최초 0), `case_sha256`는 상세 조회의 현재 사건 hash다. 근거는 1–1,000자다.

```json
{
  "expected_label_revision": 0,
  "case_sha256": "<현재 사건 내용 SHA-256>",
  "value": "uncertain",
  "reason": "현재 근거만으로 판정을 확정하기 어려움"
}
```

saved 조회의 최신성은 **마지막으로 동기화한 사건 기억**과 비교한 값이다. 현재 수집 원본까지 반영하려면 먼저 sync를 호출한다. 콘솔의 확인 버튼은 이를 수행한다.

## 저장과 범위

기본 영속 파일은 `data/collector/case-memory/journal.jsonl`이며 `data_dir` 설정을 따른다. 사건 변경 묶음·라벨·선정을 하나의 hash-chain JSONL 기록으로 append하고 `Sync` 성공 후에만 메모리 상태와 성공 응답을 반영한다. 실행 중 journal의 OS 배타 잠금을 유지한다. 쓰기 결과가 불명확하면 이후 접근을 닫고, 재시작은 저장된 hash·순서·참조를 다시 검산한다. 손상된 마지막 행이나 hash 불일치는 자동 절단하지 않는다.

상한: journal 32 MiB, 단일 기록 2 MiB, 512사건, 사건당 64개 사건 버전·64개 라벨 버전, 256개 저장 선정·64개 학습 후보·16개 shadow 계획(계획당32개 snapshot), 전체 8,192개 기록. 원본 snapshot의 기존 32 MiB/100,000건 한도도 적용한다. 용량 한도는 조용히 오래된 판정을 삭제하지 않고 거부한다. 백업은 앱을 종료한 뒤 collector 원본과 case-memory를 함께 보존한다.

기본 Windows/Linux 로컬 콘솔에서 제공한다. 공유 저장 예산(`-storage-budget-*`) profile은 별도 coordinated journal writer가 필요하므로 이 API가 503을 반환한다. 기존 PostgreSQL `case-api`·case/source 원장·DB migration과 별개 저장소이며 이 변경이 해당 DB의 역할/권한 계약을 대체하지 않는다. 전체 M7의 자산 owner/센서 coverage·request fusion·외부 운영 신원·운영 수용 완료 선언은 아니다.

## 회귀 검사

```powershell
go test ./internal/casememory ./internal/incident ./web ./cmd/reverse-artex
go vet ./...
```

검사는 합성 사건으로 tenant 격리, label CAS, 정정/선정 재평가, 증거 변경/rollback 거부, 원본 commit 검산, 동시 접근, journal 잠금·손상/미완료 행 거부, 쓰기 실패 이후 중단과 재시작 복원을 확인한다. 로컬 콘솔에 새 실제 운영 사건 라벨을 미리 넣지 않는다.
