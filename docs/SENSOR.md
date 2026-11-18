# HTTP 센서 연결

기본 수신 API는 `POST http://127.0.0.1:9081/v1/events`입니다. `Authorization: Bearer <센서 토큰>`과 `Content-Type: application/json`을 사용합니다. 토큰은 기본 웹 콘솔의 **연결 설정 → 센서 인증 토큰 확인** 또는 비공개 `config.json`에서 운영자가 확인합니다.

센서가 보내는 `sensor_id`, `asset_id`, `tenant_id`는 등록한 설정 범위와 일치해야 합니다. 입력은 애플리케이션·WAF에서 정규화한 관측이며 콘솔이 서비스 트래픽을 자동으로 수집하는 것은 아닙니다. 세션·리소스 식별은 원문 비밀 대신 센서 측 HMAC을 사용합니다.

필수 계약은 `internal/event/event.go`와 관련 budget 타입입니다. 필수 필드는 다음과 같습니다.

`schema_version`, `event_id`, `event_time`, `ingest_time`, `sensor_id`, `tenant_id`, `asset_id`, `event_type`, `request_id`, `method`, `route_template`, `status`, `response_bytes`, `duration_ms`, `identity_confidence`, `trusted_proxy`, `authorization_result`, `known_route`, `data_quality`, `ua_hint`, `detector_family`.

- `schema_version`은 `1.0`, `event_type`은 `http`입니다. 시간은 RFC3339 UTC이며 실제 입력의 이벤트 시각은 수신 시각 기준 1시간 이내여야 합니다.
- authenticated 관측은 검증된 `principal_id`, `session_hmac`를 포함합니다. `authorization_result`는 `allow`, `deny`, `unknown`을 구분합니다.
- 경로·권한·리소스·검증 family 등 필요한 관측이 빠지면 관련 규칙을 평가할 수 없습니다. 경보가 없다는 사실만으로 안전을 판정하지 않습니다.
- `202`는 입력 처리 결과를 반환합니다. 인증은 `401`, scope 오류는 `403`, 잘못된 입력은 `400`, 용량 거부는 `429`, 저장 불가 등은 `503`으로 구분합니다.

여러 이벤트는 `POST /v1/events/batch`에 JSON 배열로 보낼 수 있습니다. 입력 한도와 role-specific sensor 계약은 해당 handler를 따릅니다. 호스트 관측은 별도 `POST /v1/host-events`와 고유 `RA_HOST_SENSOR_TOKEN`을 사용합니다.

파일 분석은 각 레코드의 `ingest_time`을 명시적 분석 시각으로 삼아 같은 입력 계약을 검증합니다. 과거 JSONL도 시간순이면 별도 분석할 수 있으며, 실시간 증거 원장이나 정책에는 쓰지 않습니다. 파일당 1 MiB·1,024건, 레코드당 16 KiB로 제한합니다.
