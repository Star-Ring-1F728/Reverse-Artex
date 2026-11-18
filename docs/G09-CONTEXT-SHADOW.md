# G09 feature v2 shadow 관측 — 2026-11-10

`context-shadow`는 중지한 실제 collector의 증거 또는 그 오프라인 사본에서 v2 사건을 관측한다. `internal/contextshadow`와 별도 CLI만 추가하여 기존 feature/trainer/scorer의 frozen source를 변경하지 않았다. 기존 production pointer와 웹 콘솔의 자동 observer에는 아직 연결하지 않았다.

후보의 독립 전달 SHA, 공개 검토 trust, 공개 sensor/issuer trust를 명시한다. 후보 schema·model·feature·runtime pin과 deployment_allowed=false, tenant와 review/context trust digest를 검증한다. 후보 hash는 선택한 bytes를 고정하며 그 자체가 외부 승인이나 정답 보증은 아니다. 현재 후보와 다른 trust를 임의 교체하지 않는다.

`evidence.Capture`가 32 MiB/100,000 records 상한의 불변 사본을 만들고 `recovery.VerifySnapshot`으로 모든 HTTP/host detector commit을 재생한다. 사본의 context trust와 후보 pin이 같아야 한다. `incident.Build`의 tenant 사건 전부를 사용하며 512건을 넘으면 표본 추출 없이 거부한다. 다른 tenant 사건은 별도 개수로 남긴다. Alert가 없는 요청 전체가 아니라 detector가 만든 사건의 관측이다.

사건별 참조 원본·센서 서명과 v2 24차원 feature를 검증하고 후보의 예측을 남긴다. host-only·맥락 불충분·128개 초과 증거·부적합 vector와 학습 증거 overlap은 unknown/unavailable로 분모에 남기며 0 vector로 채우지 않는다. 사본 전체의 replay/서명 무결성 실패는 run을 거부하고 영수증을 만들지 않는다. 사건 0건의 coverage는 0이다.

영수증은 source/manifest/case/evidence/model/feature/runtime/observer source pin, 실제 시각, 전체·성공·불가 분모와 coverage를 포함한다. 원시 토큰·개별 gold를 읽지 않는다. `-gold`, `-review`, `-predictions`, `-inputs` 같은 학습·채점 옵션은 입력 파일을 열기 전에 거부한다. 출력은 source 밖의 새 파일만 만들고 Sync/Close 오류를 반환한다. 로컬 영수증 hash는 전자서명이나 외부 custody 증명이 아니다.

## 사용

제품 폴더에서 다음과 같이 실행한다. 먼저 collector를 정상 중지하거나 일관성을 확보한 별도 사본을 준비한다. Capture의 연속 읽기는 실행 중 writer의 원자적 snapshot/lock이 아니다.

```powershell
go build -o bin/context-shadow.exe ./cmd/context-shadow
.\bin\context-shadow.exe `
  -candidate FROZEN_CANDIDATE.json `
  -expected-candidate-sha256 CANDIDATE_SHA_FROM_TRUSTED_CHANNEL `
  -review-trust PUBLIC_AUTHORITIES.json `
  -context-trust PUBLIC_CONTEXT_TRUST.json `
  -evidence OFFLINE_COLLECTOR_DIRECTORY `
  -out NEW_RECEIPT_OUTSIDE_EVIDENCE.json
```


## 검증과 남은 작업

관련 Go 검사 132 pass / 1 skip / 0 fail이다. skip은 Windows symlink 생성 권한이다. 새 명령의 vet, Windows 빌드와 Linux/amd64 cross-build가 통과했다. Linux 실행은 이번 작업에서 수행하지 않았다. 서명된 HTTP event/evaluation/alert fixture로 Windows 실행 파일을 실제 실행해 suspicious 1건과 영수증을 확인했다. 이 fixture는 연결 검산용이며 기존 180/240건 품질 결과에 합산하지 않는다.

검사는 후보/신뢰/증거 변조·profile 제거 거부, 학습 overlap의 unknown 분모 보존, host 전용 사건 unknown, 다른 tenant 집계, 사건 0건, 출력 덮어쓰기와 source 내부 출력 거부, 라벨 옵션 거부를 포함한다. 초기 fixture의 UA/잘못된 canary 경로 실패는 fixture를 수정해 해결했고 기록된 실패 로그는 보존했다.

기존 최종 공개 capsule 파일 hash와 현재 runtime/feature pin의 일치를 확인했다. 이전 source-manifest는 최종 binding 수정 전의 actioncontext/observation.go와 event/event.go 두 항목이 달라 현재 전체 source manifest로 사용하지 않는다. 이번 작업은 이 두 파일을 수정하지 않았다.

검증 영수증 · 실행 파일 영수증

다음 단계는 실행 중 collector의 일관된 snapshot 전달과 영속 관측/웹 연결, 실제 운영 센서·권한 issuer 통합, 외부 독립 자료와 canary/부하 검증이다. 이번 단계는 offline shadow이며 실제 운영 품질·승격/자동 방어를 승인하지 않는다.

후속 [실행 중 collector·웹 콘솔 연결](G09-CONTEXT-LIVE.md)을 구현했다. 오프라인 CLI 계약은 유지하며 live 경로는 수집 commit 잠금으로 확보한 immutable snapshot만 사용한다.
