# 로컬 Qwen 사건 조사와 제한 대응

2026-11-01 KST. 기존에 설치한 Ollama 모델을 제품 콘솔의 사건·증거 조회 및 정책 도구에 연결한다. 모델 다운로드, 가중치 학습, 외부 유료 API는 사용하지 않는다.

## 기본 사용

1. 설치된 Ollama를 실행한다. CLI만 사용하는 환경은 별도 터미널에서 `ollama serve`를 실행한다. 기본 접속은 `http://127.0.0.1:11434`다.
2. `start.bat` 또는 `sh start.sh`로 제품을 켜고 출력된 콘솔 링크를 연다.
3. **사건 기억 → 수집 증거 동기화**에서 실제 수집 경보를 저장한다. 사건을 열고 **이 사건을 Qwen으로 조사**를 누르거나 **Qwen 조사** 메뉴에서 tenant·사건·설치 모델을 고른다.
4. **사건 분석 시작**을 누른다. 모델이 `사건 조회 → 원본 근거 확인 → 판단 기록`을 수행한다. 비동기 진행과 도구별 인자·결과, 판단 요약, 근거 event ID가 조사 이력에 저장된다.
5. 진행 중 조사는 **진행 중 조사 취소**로 중단할 수 있다. 취소가 이미 적용된 정책을 자동 철회한다는 뜻은 아니다. 이전 조사는 재시작 후에도 조회할 수 있다.

설치 모델 목록과 `tools` capability, 모델 digest를 실제 Ollama에서 확인한다. 클라우드/remote 모델, 설치되지 않은 모델, 실행 중 바뀐 alias를 거부한다. 모델을 자동으로 내려받는 경로는 없다. 이 PC에서 실제 확인한 모델은 `hauhaucs-aggressive:9b-8k`이며 다른 도구 지원 설치 모델도 직접 선택할 수 있다.

분석은 확정 라벨을 생성하거나 모델을 학습하지 않는다. 모델 판단은 원본 증거와 분리된 조사 결과다. 다른 언어로 답하거나 근거 이상의 추론을 포함할 수 있으므로, 운영자는 원본 참조와 도구의 검증된 결과를 함께 확인한다. 특히 `edge_effect_verified=false`는 해당 도구가 edge 효과를 측정하지 않았다는 의미다.

## 임시 차단과 해제

기본 실행은 분석 전용이다. **임시 차단 판단·실행**은 운영자가 사건을 고르고 해당 버튼을 눌러 이 실행에 제한 대응을 허용하는 동작이다. 자동 상시 대응이나 모델의 임의 권한 확대를 제공하지 않는다.

운영자가 기존 policy-control/edge 서비스를 구성하고 다음 환경 변수를 제품 프로세스에 제공했을 때만 대응 버튼이 활성화된다.

| 변수 | 의미 |
| --- | --- |
| `RA_OLLAMA_ORIGIN` | 선택 설정. 기본 `http://127.0.0.1:11434`; literal loopback HTTP origin만 허용 |
| `RA_CONSOLE_DEFENSE_ENABLED` | `1`일 때 이 콘솔의 제한 대응 허용 |
| `RA_POLICY_CONTROL_URL` | 실제 policy-control의 literal loopback HTTP origin. 기존 수집기 증거 전달도 이 설정을 사용 |
| `RA_POLICY_EVIDENCE_TOKEN` | 기존 collector → control 증거 전달 자격 |
| `RA_POLICY_ADMIN_TOKEN` | 제어기의 기존 운영자 정책·철회 자격 |
| `RA_POLICY_READER_TOKEN` | 제어기 상태 조회 자격 |
| `RA_POLICY_SNAPSHOT_KEY` | 제어기의 정책 snapshot 서명 검증 키 |

제어기 역할별 자격은 서로 다른 32자 이상의 값이어야 한다. 실제 값은 모델 메시지, UI 상태, 조사 trace에 넣지 않는다. 제어기/edge 배포 자체는 [운영 안내](OPERATIONS.md)를 따른다.

모델은 `apply_temporary_deny`에서 조회한 사건의 event ID만 고른다. 서버는 동일 사건 hash, 원본 line hash, 단일 tenant·asset, 최근 1분 내 인증·complete·거부된 HTTP 관측을 재검사한다. 대상 principal·session·route, 정책 ID 및 최대 **60초 TTL**은 서버와 기존 제어기가 고정한다. URL·셸 명령·임의 TTL·다른 tenant·호스트 격리는 모델 입력 항목이 아니다. 현재 실제 제어기 어댑터의 수용 범위는 기존 `lab-app` / `lab-api`와 등록된 가상 tenant 계약이다.

대응 도구에는 위 조건을 통과한 가장 최신 이벤트 1개만 후보로 제공한다. 기존 이벤트는 분석 근거로 유지한다. 모델 응답을 받은 뒤에도 사건 hash와 1분 유효시간을 다시 검사하므로, 느린 모델 응답 때문에 유효시간이 지난 대응은 거부된다.

적용 명령 전에 의도를 저장하고, 적용 뒤 서명된 snapshot의 정확한 대상·범위·TTL을 대조한다. 결과가 불확실하면 실패로 기록하고 자동 재시도하지 않는다. `controller_state=active`는 제어기 상태 확인이며 실제 edge 차단 증명은 별도 업무 요청이 필요하다.

**선택한 임시 차단 해제**는 이 콘솔의 이전 조사에서 만든 정확한 정책만 대상으로 한다. 현재 사건 버전 검사를 유지하며, 서명된 현재 snapshot에서 원래 정책과 일치하는 활성 상태를 확인한 뒤 철회한다. 자연 TTL 만료는 명시 해제로 계산하지 않는다. 해제와 복구 효과도 구분한다.

이 연결은 기존 일반 운영자 `/v1/policies`·`/v1/revoke` 계약을 사용한다. 별도의 Ed25519 서명 승인 원장과 `action-execute` 작업을 수행했다고 주장하거나 그 게이트를 변경하지 않는다.

## API와 저장

모든 경로는 기존 콘솔의 loopback host·동일 origin·콘솔 bearer 인증을 사용한다. 센서 토큰으로는 사용할 수 없다. Tenant는 설정한 목록에서만 허용한다.

| 메서드 | `/console/api` 뒤 경로 | 기능 |
| --- | --- | --- |
| GET | `/ai/status` | 설치 모델·로컬 접속·대응 사용 가능 여부 |
| POST | `/ai/runs?tenant=...` | 사건에 고정된 비동기 조사 시작, HTTP 202 |
| GET | `/ai/runs?tenant=...` | 해당 tenant의 저장 조사 이력 |
| GET | `/ai/run?tenant=...&id=...` | 조사 상태·판단·도구 실행 결과 |
| POST | `/ai/cancel?tenant=...&id=...` | 해당 조사의 취소 요청 |

조사 시작 JSON은 `tenant_id`, `case_id`, `case_sha256`, `model`, `mode`를 요구한다. `mode`는 `analyze`, `contain`, `release`이며 release만 원래 차단 조사 ID인 `source_run_id`를 추가한다. 모델에 임의 자연어 명령이나 자격을 보내는 필드는 없다.

`data_dir/qwen-runs/`에 조사별 JSON을 원자적으로 교체하고 Sync한다. 구조화된 trace·판단·정책 결합을 정규화 hash로 확인하며 원시 사고 과정과 모델의 자유 형식 출력은 저장하지 않는다. 시작 시 중단된 조사는 `interrupted`로 표시하고 재실행하지 않는다. 원본 손상이나 감사 쓰기 실패 시 새 도구 실행을 중단한다.

상한은 동시 조사 1개, 저장 조사 64개, 조사당 최대 6회 모델 호출·240초, 단일 통신 90초, 단일 입력 48 KiB·누적 입력 256 KiB·응답 64 KiB, 조사에 제공할 원본 참조 32개다. Collector ingestion lock은 source snapshot 캡처 동안만 사용하고 모델 응답을 기다리지 않는다. 공유 저장 예산 profile은 journal writer 연결 전까지 이 기능을 제공하지 않는다.


## 검증 범위

11월 18일 합성 ARTEX 검증에서 AI 차단·해제의 완료 횟수와 실행 시간을 기록했습니다. 자동 대응의 반복 안정성과 실제 운영 환경의 추가 유출 방지는 별도 검증 항목입니다. [공개 검증 요약](VALIDATION.md#november-18-artex-simulation)
