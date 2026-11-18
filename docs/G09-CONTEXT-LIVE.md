# 실행 중 collector와 v2 shadow 콘솔 — 2026-11-10

실행 중인 collector에서 고정 v2 후보를 관측하고 웹 콘솔의 **사건 기억 → 권한·행위 맥락 v2 관측**에서 시작·중지·한 번 관측·상태·저장 이력을 확인한다. HTTP/host 단건·batch/group이 사용하는 같은 `ingester.mu` 아래에서 immutable evidence snapshot을 확보한다. 실패한 ingester는 읽기도 거부한다. detector 재생·v2 추출·예측·영수증 저장은 수집 잠금을 푼 뒤 실행한다. 실행 중 디렉터리를 외부 CLI로 임의 읽는 방식은 사용하지 않는다.

후보·공개 authorities·sensor/issuer trust는 운영자가 파일시스템에서 설치한다. 웹 요청은 경로나 모델을 올리지 못하며 설치된 후보 SHA만 지정한다. 현재는 collector당 tenant 하나의 고정 profile을 지원한다. 기본은 미설정·중지 상태다. v1 observer/production 모델과 다른 24차원 shadow 경로이며 방어 정책이나 운영 모델을 바꾸지 않는다.

## 설정과 실행

[예제](../config.context-shadow.example.json)를 사본으로 만들고 실제 후보 경로·독립 전달 SHA·공개 authorities 경로를 채운다. 상대 경로는 profile 파일의 디렉터리 기준이다. placeholder는 검증에 실패한다. candidate의 context trust와 collector의 `-context-trust`가 정확히 같아야 하며 trust를 바꾸려면 호환 후보·검증이 필요하다. 실험 키를 운영 신뢰로 자동 승계하지 않는다.

```powershell
.\build.bat
.\reverse-artex.exe -console -config config.json `
  -context-trust PUBLIC_CONTEXT_TRUST.json `
  -context-shadow-profile LOCAL_SHADOW_PROFILE.json
```

Windows에서 `build.ps1`, Linux에서 `build.sh`로 collector와 context-shadow 도구를 빌드할 수 있다.

콘솔 접속 링크로 로그인한 뒤 tenant를 선택한다. **자동 관측 시작**은 즉시 한 번 실행하고 이후 2초마다 snapshot을 확인한다. **한 번 관측**은 작업을 하나 예약한다. HTTP는 202로 빠르게 응답하고 화면이 상태를 조회한다. busy/queued 중 중복 요청은 409다. **관측 중지**는 source 접근 없이 동작하며 예약·진행 작업을 취소한다. 중지와 경합한 작업은 예측을 발행하지 않고 취소 실패 기록을 남긴다. 재시작 후 자동 실행은 이어가지 않는다.

## 저장과 실패 처리

`<collector out>/context-shadow/`에 OS owner lock과 순서별 `attempt-NNNNNN.json`을 저장한다. 성공 영수증과 실패/취소 모두 synced 새 파일로 남긴다. 기본 활성 구간은 128회/32 MiB이며, 가득 차면 원본 파일을 삭제하지 않고 `segment-NNNNNN/`으로 같은 루트 안에서 옮긴다. 사전 Sync한 이동 intent가 파일별 SHA/바이트 수/순서와 이전 seal을 고정하며, 모든 이동 후 `seal-NNNNNN.json`으로 봉인한다. 전역 sequence와 과거 조회를 유지한다.

기본 보관은 최대 8개 구간, 활성·보관·seal·상한 marker 합계 256 MiB이며 먼저 도달하는 count/byte 제한을 적용한다. 동시에 활성 구간만 메모리에 유지한다. 전체 상한에 닿으면 관측만 storage.state=full로 멈추고 collector는 계속 수집한다. 미저장 관측은 별도 unsaved_checks로 남기고, 상한 marker를 작은 예약 공간에 Sync해 재시작 후에도 중지 상태를 유지한다. 상태/이력 읽기는 계속 가능하다. `storage` profile로 더 작은 운영 상한을 지정할 수 있지만 코드의 최대값보다 늘릴 수 없다. 화면은 최근 16개 이력을 보여주며 sequence API로 봉인 구간도 조회한다.

이는 협조하는 관측 writer의 regular file length 상한이다. 파일시스템 할당량이나 전체 디스크 quota가 아니다. 중단된 이동 intent·부분 파일·구간 변조는 자동 복구/삭제하지 않고 재개를 거부한다. 전체 상한 뒤 계속하려면 collector를 중지하고 기존 context-shadow 디렉터리를 검증·보존할 별도 이름/위치로 옮긴 뒤 같은 collector 설정으로 재시작한다. 새 이력은 별도 session으로 sequence 1부터 시작하며 과거 세션을 새 표본으로 합산하지 않는다. 파일을 지우거나 오래된 실패를 성공으로 바꾸지 않는다.

각 영수증은 그 snapshot의 현재 전체 사건을 담는다. 새 snapshot에도 같은 사건이 다시 포함될 수 있으므로 이력의 건수를 독립 품질 표본으로 합산하지 않는다. host-only/맥락 부족/학습 overlap은 unknown과 분모를 유지한다. 라벨을 소비하거나 품질 채점하지 않는다.

source 검증 실패는 실패 attempt를 남기고 자동 관측을 멈춘다. 저장 결과가 불명확하면 현재 프로세스의 후속 요청도 막는다. corrupt/partial/다른 후보 history를 자동 복구·삭제·takeover하지 않는다. 자료를 보존한 뒤 운영자가 별도 경로에서 해결해야 한다. profile·history·trust 변경은 재시작 시 검증한다. shared-storage-budget 모드에서는 이 기록을 예산 밖에 쓰지 않도록 새 live profile을 거부한다.

worker의 30초 context는 lock 대기·snapshot 반환 전후·결과 발행 전 검사에 적용한다. replay/추출은 기존 byte/record/case 상한 내 동기 작업이므로 즉시 선점되는 hard process timeout을 뜻하지 않는다. live snapshot은 같은 commit 잠금 아래 단일 읽기를 수행한다. 지속 부하와 기본 구간 회전·상한 검증은 후속 부하·보관 검증을 따른다. 최대 32 MiB/100,000 source records와 512 tenant cases의 기존 snapshot 범위는 유지한다. 파일 Sync와 owner lock은 물리 전원 장애·외부 custody/전자서명을 보증하지 않는다.

## API

기존 loopback Host·Bearer·same-origin guard를 적용한다. 모든 endpoint는 `/console/api/cases/context-shadow/` 아래에 있고 정확한 tenant query를 요구한다.

- `GET status?tenant=...`: 현재 상태, 최신 attempt, 최근 이력
- `GET history?tenant=...&sequence=...`: 저장 attempt
- `POST start?tenant=...`, `POST capture?tenant=...`: JSON `{"candidate_sha256":"..."}`
- `POST stop?tenant=...`: JSON `{}`

다른 tenant profile은 404, 미설정 상태 조회는 configured=false다. mutation body의 unknown/duplicate/alias field와 비정상 query를 거부한다. tenant 전환 시 이전 결과·후보 표시를 즉시 비운다. 과거 이력 조회와 중지는 source 장애 중에도 가능하다.
