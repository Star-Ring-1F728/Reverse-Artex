# Reverse Artex 운영과 배포

## 네이티브 웹 콘솔

Windows는 `start.bat`, Linux/macOS는 해당 OS에서 빌드한 후 `sh start.sh`로 시작합니다. 콘솔과 HTTP 수집기가 같은 프로세스의 `127.0.0.1:9081`을 사용합니다. 웹 자산은 실행 파일에 포함되므로 Node.js·npm·별도 프런트엔드 서버가 필요하지 않습니다.

`config.json`이 없으면 기본 설정과 무작위 센서 토큰을 생성합니다. 접속 링크의 콘솔 키는 프로세스 수명 동안만 유효합니다. 센서 토큰과 콘솔 접속 키를 공개 저장소나 공유 로그에 넣지 마십시오. 외부 관리자는 SSH 터널 등으로 같은 localhost 포트에 연결합니다. 이 패키지는 인터넷 공개용 관리자 로그인·TLS 프록시를 자동 구성하지 않습니다.

```json
{
  "listen": "127.0.0.1:9081",
  "data_dir": "data/collector",
  "correlation": "session",
  "sensor_id": "lab-app",
  "asset_id": "lab-api",
  "tenants": ["alpha", "beta", "public"]
}
```

환경 변수 `RA_SENSOR_TOKEN`, `RA_SENSOR_ID`, `RA_ASSET_ID`, `RA_TENANTS`를 명시하면 해당 값이 우선합니다. 명령행의 `-listen`, `-out`, `-correlation`은 이번 실행의 설정 파일 값보다 우선합니다. 설정 수정 후 재시작해야 반영됩니다.

## 데이터 보존과 재시작

사건 기억의 [자동 shadow 관측·추천 버전](LEARNING-LIFECYCLE.md)은 기본 중지이며 사전 기준·명시적 시작이 필요합니다. 활성 상태는 원장에서 복원하고 source/학습 자료가 달라지면 중단합니다. 중지 동작은 원본 검증 실패와 분리하고 원장 예산을 예약합니다. 이 기능의100% 추천이나 복원이 LLM/가드 운영 배포를 의미하지는 않습니다.

`data/collector/`에는 events·alerts·evaluations와 복구 metadata를 저장합니다. 저장 한도에 도달하면 수집 오류를 반환하며 기존 근거를 임의로 지우지 않습니다. UI의 이벤트·경보 화면은 활성 파일의 최근 200개 완료 레코드만 읽습니다. 봉인된 이전 구간은 이 화면에서 재검색하지 않습니다.

Ctrl+C 또는 SIGTERM으로 요청 처리를 마무리하고 증거 저장소를 닫습니다. 복구 검증 오류가 나면 로그를 보존하고 기존 data를 삭제하지 마십시오. 같은 data 경로를 여러 writer가 공유하지 않도록 인스턴스당 별도 경로를 사용합니다. 백업은 수집기를 중지한 상태에서 `config.json`과 `data/`를 함께 보관하고, 복원 후 `-recover-check -out data/collector`로 복구를 먼저 확인합니다. 이 옵션은 웹 콘솔 옵션과 함께 사용하지 않습니다.

## 정책 제어·집행 및 사건 저장소

기본 시작은 관측 모드입니다. `bin/`의 서비스는 개별로 설정·실행합니다. 각 CLI의 `-h`가 현재 인자 계약입니다. 역할별 credential은 서로 달라야 합니다.

- `policy-control`: 정책·감사 원장. `RA_POLICY_ADMIN_TOKEN`, `RA_POLICY_READER_TOKEN`, `RA_POLICY_EVIDENCE_TOKEN`, `RA_POLICY_SNAPSHOT_KEY`가 각각 필요합니다. 각 값은 최소 32자입니다. 예: `bin/policy-control.exe -listen 127.0.0.1:9084 -out data/control`.
- 수집기의 승인된 정책 증거 전달: `RA_POLICY_CONTROL_URL`과 `RA_POLICY_EVIDENCE_TOKEN`을 설정합니다. 재시작 후 미전달 근거가 남아 있으면 현재 복구 상태를 검토한 뒤 명시적으로 `-policy-resume`을 선택해야 합니다.
- `policy-edge`: 고정 upstream과 별도 private 관리 주소를 사용하는 집행 프록시입니다. 토큰·서명·신원 전달 계약과 보호 서비스 연결을 별도로 구성해야 하며, 기본 시작 스크립트에서 자동으로 트래픽을 전환하지 않습니다.
- `case-api`, 원장·동기화 CLI: 별도 PostgreSQL과 `db/migrations/`의 migration·역할·권한 설정이 필요합니다. 기본 웹 콘솔의 수집·조회에는 PostgreSQL이 필요하지 않습니다.
- `host-response`: 기본은 simulation이며 실제 Linux 집행은 등록된 namespace 어댑터·scope·권한·별도 서명 trust의 명시적 설정이 필요합니다. 네이티브 호스트 격리를 기본으로 켜지 않습니다.

## Docker API 수집기

이 compose 구성은 웹 콘솔이 없는 API 수집기 프로필입니다. 웹 콘솔은 위의 네이티브 시작 방식을 사용합니다.

1. `.env.example`을 `.env`로 복사합니다.
2. `RA_SENSOR_TOKEN`에 고유한 무작위 32자 이상 값을 설정합니다. 센서·자산·tenant를 확인합니다.
3. `docker compose up -d --build`를 실행합니다.
4. `http://127.0.0.1:9081/v1/runtime-health`로 확인합니다. 입력 API에는 Bearer 인증이 필요합니다.

데이터는 이름 있는 Docker volume에 남습니다. `docker compose down`으로 중지하며, 데이터를 보존하려면 volume 삭제 옵션을 사용하지 않습니다. 기본 호스트 게시 주소는 loopback입니다. 이 작업에서 Docker 이미지를 빌드하거나 외부 서버에 배포하지 않았습니다.

## 검증 기록

`.workspace-copy/validation.json`과 관련 로그에 이번 폴더의 실제 검사 결과를 저장합니다. Windows 로컬 검사, Linux 전용 어댑터, Docker, 외부 서버 수용을 구분합니다. 제공된 시작 구조가 운영 부하·독립 신원·복구·모델 품질·격리 수용 조건을 자동 충족하지는 않습니다.
