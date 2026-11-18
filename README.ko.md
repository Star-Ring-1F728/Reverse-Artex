# Reverse Artex

**베타 버전 · 0.1.0-beta.1**

Reverse Artex는 직접 소유하거나 평가 권한을 받은 애플리케이션에서 HTTP 증거를 수집하고 의심스러운 활동을 탐지하며, 애플리케이션의 접근 제어를 지원합니다.

[English](README.md) · 한국어

[MIT](LICENSE) · Linux amd64 단일 호스트 연동용 · Windows amd64 로컬 콘솔 평가용. [베타 범위](docs/BETA-SCOPE.ko.md)

## ARTEX 시뮬레이션과 베타 성능

2026년 11월 18일 · 직접 관리하는 합성 시험 환경

| 검증 항목 | 결과 |
| --- | --- |
| **SDK 권한 검사 및 에지 검증** | 시험 데이터는 취약한 대조 경로에서 전체 시나리오 항목 중 **486건**에 노출됐으며 보호 경로에서는 **0건**이었습니다. 미리 정한 정상 대조 요청 **192/192건**은 예상 응답과 일치했습니다. |
| **AI 차단·해제** | **6회 중 4회 완료**했습니다. 완료된 실행에서 차단과 해제는 평가를 포함해 단계별로 **9.1~12.4초**가 걸렸습니다. 대조 표본에서 AI가 추가로 막은 유출은 **0건**이었습니다. |
| **Linux 베타 후보 부하** | **초당 100건**으로 약 **3분** 동안 보호된 HTTPS 읽기 **18,000건**을 정상 처리했습니다. **p99 223.9ms**였습니다. |
| **Windows 베타 ZIP 부하** | 두 구성 모두 **1,400/1,400건** 정확히 응답했습니다. **초당 100건** 구간에서 선택 기능인 15/25ms 일괄 처리 설정을 적용하자 p99가 **724.4 → 259.8ms**로 줄었습니다. **250ms 기준**을 충족하지 못했습니다. |

시뮬레이션에는 SDK·세션·객체 ACL 연동을 적용했습니다. Linux와 Windows는 각기 다른 부하 조건에서 측정했습니다. [시뮬레이션 범위와 베타 부하 조건(영문)](docs/VALIDATION.md#november-18-artex-simulation)

## 빠른 시작

### 1. 콘솔 실행

신뢰할 수 있는 배포자가 제공한 베타 압축본의 SHA-256을 확인한 뒤 전체를 쓰기 가능한 폴더에 푸세요. Windows에서는 `.\start.bat`, Linux에서는 `sh start.sh`를 실행합니다. 미리 빌드된 콘솔은 브라우저에서 열 수 있습니다.

소스에서 빌드하려면 Go 1.26 이상을 설치하고 저장소 루트에서 실행합니다.

**Windows PowerShell**

```powershell
.\build.bat
.\start.bat
```

**Linux**

```sh
sh build.sh
sh start.sh
```

### 2. 샘플 분석

웹 콘솔은 한국어로 제공됩니다.

1. 터미널에 출력된 **전체 접속 링크**를 여세요. 기본 주소는 `127.0.0.1:9081`이며 링크의 `#token=...`도 필요합니다.
2. **파일 분석 → 샘플 12건으로 기능 확인**을 선택하거나 [샘플 JSONL](docs/examples/http-sample.jsonl)을 업로드하세요.
3. 분석한 이벤트 12건과 탐지 근거를 확인하세요. 샘플은 별도 공간에서 분석되며 정책 적용은 0건입니다.

콘솔은 기본적으로 관측 모드로 시작합니다. 접속 링크와 센서 토큰은 비공개로 보관하세요. [처음 실행 안내와 문제 해결](docs/QUICKSTART.ko.md)

### 3. 앱 연결

- **증거 수집.** **연결 설정**에서 센서 ID, 자산, 테넌트, 토큰을 확인하세요. 정규화한 이벤트는 `POST /v1/events`, 일괄 입력은 `POST /v1/events/batch`로 보냅니다. 수집 후 **개요**, **이벤트**, **경보**에서 수집 상태와 결과를 확인하세요. [센서 API와 데이터 계약](docs/SENSOR.md)
- **권한 보호.** 보호할 경로를 등록하고 앱 SDK를 세션·신원·객체 ACL 검사에 연결하세요. [보호 계약](docs/PROTECTION-CONTRACT.md) · [세션·ACL 연동](docs/SESSION-ADAPTER.md) · [OIDC](docs/OIDC-COVERAGE.md)
- **사건 조사.** **사건 기억**에서 증거를 동기화하세요. 로컬 AI 분석은 **Qwen 조사**에서 설치한 도구 지원 Ollama 모델을 선택해 시작할 수 있습니다. [로컬 조사와 제한 대응](docs/LOCAL-QWEN.md)

### 4. 종료·백업·복구

**Ctrl+C**를 누르고 수집기가 종료될 때까지 기다리세요. `config.json`과 `data/` 전체를 함께 백업하세요. 데이터 디렉터리마다 쓰기 프로세스를 하나만 실행하고, 재시작한 뒤 새 접속 링크를 여세요.

중지 상태에서 기본 저장소를 확인하려면 Windows에서 `.\reverse-artex.exe -recover-check -out data/collector`, Linux에서 `./reverse-artex -recover-check -out data/collector`를 실행하세요. 복구 오류가 나면 원본 파일과 로그를 보존하세요. [저장소 운영과 복구](docs/OPERATIONS.md)

## 기능과 지원 환경

- **증거와 탐지:** 인증된 HTTP 수집, 규칙 기반 경보, 사건 이력, 검토한 라벨, 명시적으로 시작하는 섀도 학습을 지원합니다. [기능 범위](docs/CAPABILITIES.md)
- **파일 분석:** 별도 공간에서 JSONL을 분석합니다. 한도는 파일당 1 MiB, 이벤트 1,024건, 레코드당 16 KiB입니다. [파일 분석 안내](docs/QUICKSTART.ko.md#3-샘플과-파일-분석)
- **선택 연동:** 앱 SDK는 Python 3.10 이상, 로컬 조사는 Ollama, 사건 API는 PostgreSQL을 사용합니다. Docker Compose 프로필은 수집 API를 실행합니다. V2 보존 원장과 네트워크 네임스페이스 격리는 Linux 기능입니다. macOS는 소스 빌드 스크립트를 제공하며 베타 실행 검증 범위에서는 제외됩니다. [지원 범위(영문)](docs/COMPATIBILITY.md)

## 검증 상세

- **11월 18일:** ARTEX 시험에서 SDK 권한 검사, 서명 응답, AI 차단·해제를 검증했습니다. AI 실행 두 번은 응답 전달 또는 세션 상태 문제로 미완료됐습니다. Windows는 로컬 평가 범위입니다. [최신 검증 범위와 한계(영문)](docs/VALIDATION.md#november-18-artex-simulation)
- **11월 15일:** 당시 Windows 압축본에서 정상 응답 **954/954건**이 일치했고, 지정 검사 **69/69건**을 데이터 노출 없이 거부했습니다. 이전 Windows 부하 실패도 원래 결과와 함께 확인할 수 있습니다. [권한 보호 시험(영문)](docs/VALIDATION.md#packaged-authorization-evaluation--2026-11-15) · [Windows 부하 이력(영문)](docs/VALIDATION.md#windows-operating-challenge--2026-11-15)
- **11월 14일:** 별도 WSL2/ext4 시험에서 **초당 100건**으로 **36만 건 모두 HTTP 200**, **오류 0건**, 전체 **p99 198.867ms**를 기록했습니다. 일부 50초 구간은 250ms를 넘었습니다. [1시간 부하 조건과 결과(영문)](docs/VALIDATION.md#earlier-completed-latency-qualification--2026-11-14)

## 문서

- [빠른 시작](docs/QUICKSTART.ko.md) · [운영](docs/OPERATIONS.md) · [방어 계층과 ARTEX 시뮬레이터 한국어 요약](docs/DEFENSE-LAYERS.md#한국어-요약)
- [릴리스 패키징(영문)](docs/RELEASING.md) · [공개 준비 체크리스트(영문)](docs/PUBLIC-RELEASE-CHECKLIST.md) · [변경 이력(영문)](CHANGELOG.md)
- [보안 정책](SECURITY.ko.md) · [기여 안내](CONTRIBUTING.ko.md) · [의존성 고지(영문)](THIRD_PARTY_NOTICES.md)

## 라이선스와 출처

Reverse Artex는 [MIT 라이선스](LICENSE)를 따르는 별도 방어 프로젝트입니다. 단일 바이너리, 내장 콘솔, 실행 스크립트 구조는 [ARTEX 글로벌판](https://github.com/jiwoochris/artex-global)을 참고했습니다.
