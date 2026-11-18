# Windows SCM으로 browser BFF 실행·종료

선택 SCM host는 `SERVICE_CONTROL_STOP`/`SERVICE_CONTROL_SHUTDOWN`을 기존 `run_browser_server`의 host-owned event에 연결한다. HandlerEx는 STOP_PENDING 보고와 event 설정만 하고 HTTP·DB·drain은 worker thread에서 처리한다. listener 시작 뒤 RUNNING이며, 새 요청 수용 여부는 별도 `/readyz`로 확인한다. 공개 HTTP 종료 경로는 없다.

START_PENDING에서는 control을 받지 않는다. RUNNING에서 STOP/SHUTDOWN을 받으면 STOP_PENDING으로 한 번 전환한다. 중복 stop/INTERROGATE가 가짜 checkpoint 진행을 만들지 않으며, app 정리와 gateway 반환 뒤 마지막으로 STOPPED를 한 번 보고한다. [Microsoft lifecycle 규칙](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus)을 따른다.

정상 drain은 Win32/service/process exit0이다. 미완료 drain은 Win32 `ERROR_SERVICE_SPECIFIC_ERROR`(1066)/service exit2/process exit2, 설정·기동·호스트 오류는 service exit1이다. 남은 요청/cleanup 미완료를 성공으로 바꾸거나 이미 시작한 SQL을 강제 취소했다고 주장하지 않는다. OS 강제 종료는 graceful이 아니며, 시스템 shutdown에서는 OS 시간 예산 안에 grace를 구성해야 한다. 전역 shutdown registry는 바꾸지 않는다.

## 진입점과 설정

`sdk/python/examples/browser_sso_service.py`는 서비스 설치·변경을 하지 않는 SCM 전용 진입점이다. 등록된 **실제 Python executable**에서 실행하며, 자식 base Python을 만드는 Windows venv redirector를 SCM binary로 등록하지 않는다. dispatcher 부트스트랩은 표준 라이브러리만 사용하고 gateway/crypto/DB 초기화는 ServiceMain에서 한다. matching ABI 의존성을 별도 venv에 보관하면 `--dependency-path`로 site-packages를 지정한다. .pth startup hook은 실행하지 않는다.

설정은 최대64KiB regular JSON이다. 아래 schema/argv 외 key, duplicate key, 임의 environment override, admin 초기화/회전/이관·describe 명령과 stdin EOF lifecycle은 거부한다. identity/DB는 기존 local absolute 파일이어야 한다.

```json
{
  "schema": "browser-sso-windows-service/1",
  "gateway_argv": [
    "--identity-config", "C:\\Reverse-Artex\\config.oidc.local.json",
    "--database", "C:\\Reverse-Artex\\data\\application-native.db",
    "--database-profile", "sqlite-native-acl/1",
    "--public-origin", "https://app.example",
    "--edge-origin", "http://127.0.0.1:9082",
    "--listen", "127.0.0.1:9083",
    "--browser-state-key-env", "RA_SSO_STATE_KEY",
    "--shutdown-timeout", "10"
  ]
}
```

공유 상태 초기화/이관은 기존 관리 절차로 먼저 수행한다. key/client secret은 서비스 계정에 외부 환경 주입으로 공급하며 config·SCM command line에 원문을 넣지 않는다. SCM 서비스가 대화형 사용자의 environment를 자동 상속하지는 않는다. source/Python/의존성/config를 보호하고 writable DB 디렉터리는 서비스 계정 범위로 구분한다. 이 host는 운영 비밀 관리자나 계정/ACL 정책을 자동 구성하지 않는다.

```powershell
& '<real-base-python.exe>' -B sdk/python/examples/browser_sso_service.py --service-name ReverseArtexBrowser --config '<absolute-service.json>' --dependency-path '<absolute-matching-site-packages>' --check
```

`--check`는 bounded 설정/argv/경로만 확인한다. listener/SCM 연결·DB schema·key·실제 계정 권한 readiness 수용은 아니다. SCM 밖에서 run하면 연결 오류1063으로 닫히며 콘솔 서버로 자동 fallback하지 않는다.


## 검증

소스에서 SDK 의존성을 설치한 뒤 공개 합성 단위 테스트를 실행할 수 있습니다. 실제 배포의 신원 공급자와 저장소, 서비스 종료 동작은 해당 환경에서 확인하세요. [테스트 안내](../CONTRIBUTING.md)
