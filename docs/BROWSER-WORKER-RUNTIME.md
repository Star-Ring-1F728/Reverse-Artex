# 공유 SSO 워커 준비 상태·종료 drain

공유 키 회전·상태 이관에 이어, 예제 BFF에 **준비 상태 확인·새 요청 수용 차단·진행 중 요청 drain**을 연결했다. `reverse_artex_guard.browser_server.BrowserSSOServer`는 literal `127.0.0.1` listener만 허용하고, 기존 BrowserSSOHandler의 Host/Origin·CSRF·cookie·token 검증과 private edge read allowlist를 사용한다.

이 런타임은 선택적인 로컬 gateway/reference 구현이다. Python의 [`http.server`](https://docs.python.org/3.14/library/http.server.html)는 일반적인 운영 웹 서버의 대체재로 권장되지 않는다. 실제 운영 HTTP 스택·TLS reverse proxy/LB·부하/장기 가용성 수용은 해당 배포에서 별도로 수행한다.

## 준비 상태와 생존 확인

관리 런타임을 사용한 worker는 다음 경로를 제공한다. 같은 경로를 기존 비관리 HTTPServer에 자동 추가하지 않는다.

| 경로 | 정상 응답 | 비정상/종료 준비 | 확인 범위 |
| --- | --- | --- | --- |
| `GET/HEAD /healthz` | 200, `{"live":true}` | listener 종료 후 접속 불가 | 로컬 HTTP 처리 생존; DB/IdP 접근 없음 |
| `GET/HEAD /readyz` | 200, `{"ready":true}` | 503, `{"ready":false}` | 새 요청 수용 상태와 로컬 상태/세션 DB |

공유 상태의 ready 검사는 현재 keyring·OIDC/origin/capacity context·최소 generation·인증된 epoch 이력을 확인하고 browser/session 테이블의 필요한 열을 조회한다. 실제 요청과 같은 공유 SQLite unit을 사용하므로 DB write lock 충돌도 503으로 닫힌다. native/legacy 메모리 모드는 기존 session 테이블에 읽기 전용 probe를 한다.

probe는 session을 조회하거나 만료 행을 prune하지 않고, state를 소비하거나 token 수명을 늘리지 않는다. 응답에는 key ID·epoch·principal·token·cookie·CSRF·DB 오류 이유를 넣지 않는다. Host와 클라이언트 Authorization/RA header 거부 규칙은 probe에도 적용하며, query는400, GET/HEAD 이외 method는405다. 모든 응답은 no-store다. `/auth/session`의 guest200을 readiness 대신 사용하지 않는다.

이것은 로컬 저장소/worker 준비 상태다. 모든 암호문 행의 무결성 감사, 이후 쓰기 성공/여유 디스크 보장, 원격 IdP나 edge/SDK의 가용성 검사는 아니다. 실제 요청에서 현재 session/권한·암호문 인증과 오류 처리를 계속 수행한다.

## 종료 순서와 결과

1. 로컬 supervisor가 종료를 요청하면 `begin_drain()`이 readiness를 즉시503으로 바꾼다.
2. 이후 새 일반 요청은 body·인증 state 처리 전에503 + `Retry-After: 1`로 거부한다. login/callback/logout/backchannel과 app read에 모두 적용한다. health probe는 계속 처리한다.
3. 이미 수용한 요청은 body 처리·외부 code exchange·앱 상태 transaction·응답 전송이 끝날 때까지 기다린다. 요청 카운터는 `_handle()` 반환 이후의 응답 쓰기도 포함한다.
4. grace 안에 모두 끝나면 이 controller를 닫고 listener/연결을 정리한다. 공유 session·pending transaction·logout ledger는 다른 worker에서 유지한다. 메모리 모드는 자신이 보유한 앱 digest를 폐기한다.

정상 종료는 CLI exit0와 `drained:true, timed_out:false, active_requests:0, cleanup_complete:true`로 보고한다. `stop()`은 idempotent이며 `serve_forever()`와 다른 thread에서 호출한다. [`socketserver.shutdown`](https://docs.python.org/3.14/library/socketserver.html#socketserver.BaseServer.shutdown)의 같은-thread 교착 제약을 따른다.

대기 시간이 지나면 이 controller의 late callback 설치와 새 state 소비를 닫고 연결을 종료한다. CLI는 **exit2·drained:false·timed_out:true·남은 요청 수·cleanup 미완료**를 보고한다. 이미 시작한 SQL을 강제로 취소하거나 rollback했다고 주장하지 않는다. 해당 worker process를 퇴역시키고 결과가 불명확한 작업은 기존 작업/state 계약에 따라 확인해야 한다. 라이브러리로 embed한 host도 미완료 보고를 정상 종료로 취급하지 않는다.

timeout 이후 이미 소비한 authorization state를 재전송하면 거부된다. 사용자는 로그인을 다시 시작해야 할 수 있다. 메모리 모드의 미완료 폐기나 강제 process 종료에서는 앱 digest가 원래 만료까지 남을 수 있다. 공유 모드에서 다른 worker의 유효 session을 종료 worker가 전역 폐기하지 않는다. SQLite state transaction의 원자성은 기존 계약을 따른다.

## 실행과 supervisor

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'sdk/python'
# RA_SSO_STATE_KEY는 외부 비밀 관리 경로에서 주입한 canonical base64 32-byte key다.
python -B sdk/python/examples/browser_sso_gateway.py `
  --identity-config config.oidc.local.json --public-origin https://app.example `
  --edge-origin http://127.0.0.1:9082 --listen 127.0.0.1:9083 `
  --database data/application-native.db --database-profile sqlite-native-acl/1 `
  --browser-state-key-env RA_SSO_STATE_KEY --shutdown-timeout 10 --max-connections 64
```

`--shutdown-timeout`은0.05..60초(default10), `--max-connections`는1..1024(default64)다. 연결 수를 제한하고 idle header 읽기에 timeout을 적용해 종료를 시작하지 않은 소켓이 worker thread를 무제한 점유하지 못하게 한다. 수용량 초과는 자격 정보가 없는 고정503 응답 뒤 연결을 닫는다. 공개 TLS proxy는 connection/body/timeout 제한도 해당 환경에 맞춰 관리한다.

main-thread runner는 SIGINT·SIGTERM·가능한 경우 SIGBREAK를 등록하고 반환 시 기존 handler를 복원한다. handler는 bool만 설정하며 lock·DB·서버 shutdown을 직접 호출하지 않는다. Python의 [signal handler 제약](https://docs.python.org/3.14/library/signal.html#signals-and-threads)을 따른다.

Windows의 강제 TerminateProcess나 작업 관리자 종료는 이 graceful 경로를 보장하지 않는다. 파이프로 프로세스를 실행하는 local supervisor는 `--shutdown-on-stdin-eof`를 **명시적으로** 추가하고, 종료 때 child stdin을 닫아 같은 drain 절차를 실행할 수 있다. 기본 실행은 stdin EOF를 종료 요청으로 사용하지 않는다. CLI/공개 config/HTTP에 비밀값이나 shutdown token을 추가하지 않았으며, HTTP로 drain을 시작하는 관리 경로도 만들지 않았다.

EOF supervisor 입력은 독점 읽기하는 pipe·일반 파일이나 embed의 in-memory stream이다. 같은 stream을 다른 thread가 동시에 읽거나 미리 buffer에 읽어 둔 입력을 제어 명령으로 사용하지 않는다. 대화형 콘솔은 SIGINT/SIGBREAK를 사용한다. 종료 시 입력 대기를 취소하고 reader thread를 join하며, 호출자가 소유한 stream은 닫지 않는다. Windows pipe는 [PeekNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe), POSIX pipe는 bounded select 후 읽는다.

라이브러리 embed는 `BrowserSSOServer(..., readiness_check=...)`와 `run_browser_server(...)`를 사용한다. readiness callback은 bounded·비변경 probe여야 한다. `run_browser_server`의 signal 설치는 main thread에서만 허용하며, host가 signal을 소유하면 `install_signals=False`와 별도 `threading.Event`로 종료를 요청한다.

## 공유 키 회전·worker 교체

[키 회전 절차](BROWSER-STATE-MIGRATION.md)에 따라 먼저 모든 worker가 새 key를 preload하도록 교체하고 각 worker의 `/readyz`를 확인한다. epoch commit 후 구키만 가진 worker는 health200이어도 ready503이며, 준비한 worker는 인증된 새 epoch에 따라 ready200을 유지한다.

LB는 readiness200인 worker에 새 요청을 보내고, 종료 worker는 먼저 drain하여 신규 요청을 차단한다. 그 뒤 남은 요청을 기다려 worker를 교체한다. readiness는 snapshot이므로 LB 검사와 실제 요청 사이에 변경이 발생할 수 있으며, 실제 수용 단계에서 다시 거부할 수 있다.

라우팅 fixture는 **전달 전에** 준비된 worker를 고르고 한 번만 전달한다. 운영 proxy도 code callback·logout·backchannel을 실패 후 임의로 자동 재전달하지 않도록 구성한다. 거부된 미소비 transaction은 준비된 worker에서 한 번 처리할 수 있지만, code exchange까지 진행한 callback을 자동 재시도하면 단회 소비 계약과 충돌한다. 전달 시 공개 Host/Origin을 보존하고 client cookie/CSRF를 private bearer로 바꾸는 경계는 BFF에 둔다.


## 검증

소스에서 SDK 의존성을 설치한 뒤 공개 합성 단위 테스트를 실행할 수 있습니다. 실제 배포의 신원 공급자와 저장소, 서비스 종료 동작은 해당 환경에서 확인하세요. [테스트 안내](../CONTRIBUTING.md)
