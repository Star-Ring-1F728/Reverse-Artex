# G09 feature v2 — 서명된 권한·행위 관측, 새 학습과 봉인 평가

`action-observation/2`와 `case-context-features/2`를 추가했다. 실제 HTTP 수집기의 단건·batch·group, 커밋 증거 복원, 24차원 추출, 검토 서명된 학습, 후보 동결, 새 holdout 생성·봉인, 라벨 없는 추론과 별도 채점을 연결한다. v1의 14차원 계약과 JSON/hash를 보존하며 자동 padding이나 v1 모델 덮어쓰기를 하지 않는다.

이 경로는 v2 후보와 품질 측정을 구현한다. 기존 production pointer에 v2를 자동 설치하지 않으며 기본 운영 정책은 OFF다. 이 환경의 자료는 소유한 서비스에서 생성한 통제 실험으로, 외부 독립 관리자·운영 자료의 대표성을 입증하지 않는다.

## 서명된 관측 계약

센서 관측은 event ID, tenant/asset/sensor, 인증 principal/session HMAC, route/method/resource HMAC, 실제 authorization/status/validation family/canary, data quality, event time에 묶인다. 센서의 Ed25519 서명이 이 사실들과 canonical Event 전체 SHA를 인증한다. Context 자신과 수집기가 재지정하는 ingest time만 hash에서 제외하며 UA·known-route·경로·예산 등 기존 feature의 근거를 바꾸어도 서명 검증이 실패한다. raw 인증 토큰·본문·정답 라벨·모델 출력은 관측에 넣지 않는다.

별도 issuer의 `scoped-test-permission/2`는 principal/session, tenant/asset/sensor, route/method/resource, 허용된 테스트 행위, 발급·만료 시각을 서명한다. 행위는 authorization_probe/input_validation/canary_audit이며 만료는 최대 1시간이다. 수신자는 공개 키·역할·scope·시간·철회를 검증한다. 같은 공개키를 표현만 달리해 두 역할에 등록할 수 없다. 권한은 테스트 범위를 설명하며 원래 resource authorization을 바꾸거나 공격/정상 정답을 지정하지 않는다.

센서 서명이 위조되거나 실제 이벤트와 binding이 다르면 수집 전에 거부한다. 센서가 인증한 만료·위조·철회·범위 불일치 **권한 주장**은 실제 위험 관측으로 남기며 유효 권한으로 세지 않는다. 하나의 테스트 권한이 다른 위험 종류까지 덮지 않게 한다. 예를 들어 authorization probe 권한으로 추가 validation 위험을 숨길 수 없다.

`reverse-artex -context-trust PUBLIC_TRUST_JSON ...`는 새 opt-in 증거 profile을 만든다. 이 profile은 모든 HTTP 이벤트에 인증된 complete 맥락을 요구한다. 공개 pin은 recovery metadata에 고정되며 기존 증거에서 profile을 제거/교체하면 복원을 거부한다. 기본 profile은 v1 이벤트를 계속 받는다. v2 추출기는 맥락 없는 legacy/partial/host-only 증거를 0으로 채우지 않고 거부한다. 현재 v2의 인증 대상은 authenticated HTTP 관측이며 익명/host-only의 확장은 별도다.

## 24차원 feature

첫 14개는 기존 사건 증거·경보·규칙 집계다. 추가 10개는 검증된 referenced HTTP 관측의 다음 count다.

- 유효 테스트 범위 밖의 민감 행위 합계(authorization deny/validation reject/private canary의 합집합)
- authorization deny, validation reject, private canary 각각의 수
- 유효한 scoped test permission 수
- 범위 밖 authorization deny/validation reject/private canary 각각의 수
- 유효 범위 안 민감 행위 수
- 승인된 2xx 요청 수

모델은 이 정수 배열만 받는다. principal·session·case ID·family/source group 이름·라벨은 예측 feature가 아니다. 각 referenced raw line의 SHA와 실제 센서 서명을 다시 검증한 뒤 계산하고 context coverage가 100%인 행만 v2 입력으로 받는다.

## 학습과 품질 계약

`learning-context`는 train/run/score를 분리한다. train은 `purpose=training`, 최소 확정 클래스 각 30건, 3 family·3 source group, input/gold SHA에 묶인 label_reviewer 서명을 요구한다. 불확실·상충 라벨의 제외 수를 남긴다. 미탐 우선·오탐 차선으로 단일 경계를 탐색하며 ID·개별 정답을 모델에 저장하지 않는다. 2026-11-12 [공격 피드백 개선](ATTACK-FEEDBACK-LEARNING.md)부터 정렬 탐색과 오류가 엄격히 줄어드는 최대 네 OR 규칙 후보를 지원한다. 아래의 과거 실행 결과는 당시 stump 버전의 기록이며 새 runtime에는 별도 재평가가 필요하다.

후보의 model/feature/runtime/training-source/input/gold/검토/trust/evidence pin을 동결한다. runtime pin은 관측·Event binding·strict JSON·공유 confidence 계산과 v2 구현을 포함한다. candidate의 deployment_allowed는 false다.

후보를 동결한 뒤 purpose=holdout 자료를 새로 생성한다. source snapshot·전체 증거 멤버십이 학습과 겹치면 서명을 다시 붙여도 거부한다. 같은 recipe·맥락 trust와 생성 시각을 확인하고, custodian 봉인에는 plan/input/gold/source/membership SHA와 전체 분모·family/source group 수를 넣는다. 이전 feature v1 품질 cohort를 재사용하지 않는다.

run은 gold/검토/training/scorer 옵션을 파일을 열기 전에 거부한다. score만 봉인된 gold를 읽는다. 누락·실패·변조·timeout·unknown은 분모/coverage에 남긴다. 기본 기준은 전체 60 이상·각 클래스 30 이상·3 family/source group 이상·coverage 100%·단측 95% Wilson 미탐/오탐 상한 각각 10% 이하·참고 기준 대비 엄격한 개선 및 family별 비회귀다. 완화된 기준으로 plan을 다시 만들면 거부한다. 참고 기준은 all_alerts_suspicious이며 실제 운영 활성 모델이 있음을 뜻하지 않는다.

## 실제 통제 실험과 OS 경계

recipe를 source/binary와 함께 자료 생성 전에 고정한다. 학습 180건(각 클래스 90), 새 평가 240건(각 클래스 120), 3개 family를 사용한다. 정상 요청, 유효 scoped QA, 정상 사용자의 실수, 미승인 테스트와 만료·위조·자원 불일치·철회 권한을 포함한다. 학습에는 family당 정상 실수 1건, 평가에는 2건이 사전 배정된다. 이는 권한 맥락이 정답의 단순 복사본이 되지 않도록 실제 같은 위험 관측을 가진 정상 사례도 남기는 통제 조건이다.

source target은 로그인 토큰에서 얻은 identity/ownership과 실제 요청으로 사실을 생성한다. target의 identity table에는 gold/공격 여부가 없다. 정답은 사전 배정한 행위 권한·정상 실수이며 detector 출력이나 HTTP 상태로 만들지 않는다. 사건 선택은 최대 증거 수·동률 ID 순이며 누락을 대체하지 않는다. 각 split은 새 비공개 entropy·세션·요청·resource와 별도 실제 collector evidence snapshot을 사용한다.

custodian UID 10002, trainer 10004, runtime 10001, scorer 10003을 사용한다. trainer는 학습 gold만 읽고 종료한다. 그 후 후보를 동결하고 평가 gold를 생성한다. generator에는 후보 파라미터를 전달하지 않는다. runtime에는 평가 gold mount가 없으며 scorer만 같은 inode를 읽는다. capability bounding/effective/ambient 0, no_new_privs 1, chroot와 mount/network/PID namespace를 사용한다. 실제 gold와 custodian/evaluator 키를 probe UID로 열어 EACCES를 확인하고, readable control 성공·root 전환 거부·host mount 부재·supervisor root 접근 거부를 함께 검사한다.

raw 입력·개별 gold·private key·seed는 native vault에 남으며 Windows로 내보내지 않는다. 공개 산출물은 frozen recipe/candidate/plan, public pins, 집계 생성 요약·봉인·결과·서명·역할 영수증이다. 호스트 관리자와 같은 세션에서 만든 권한·검토 키는 외부 독립성의 증거가 아니다. signed attestation에도 independence=false, production approval=false를 유지한다.


## 센서 통합 공개 pin 예제

`config.action-context-trust.example.json`은 서로 다른 sensor/issuer 공개 키를 넣는 배포용 형식 예제다. placeholder 상태에서는 검증에 실패하고 기본 설정에서 자동 활성화하지 않는다. 운영자가 tenant/asset/sensor와 실제 공개 pin을 설정한 뒤 명시적으로 `-context-trust`에 전달한다. 실험에서 생성한 키를 운영 신뢰로 자동 승계하지 않는다.

Go producer는 `Event.ContextBinding()`, `actioncontext.PermitBytes()`, `actioncontext.ObservationBytes()`가 제공하는 정확한 서명 bytes를 사용한다. domain은 각각 `reverse-artex/scoped-test-permission/2\n`, `reverse-artex/action-observation/2\n`이며 Go typed JSON canonical bytes에 prefix를 붙인다. 문서의 `\n`은 실제 줄바꿈 1 byte다. 다른 언어 producer도 field order·UTC timestamp·JSON escape를 포함한 이 bytes 규약과 맞아야 한다. 개인키는 producer/issuer에 보관하며 receiver 설정에는 공개 키만 둔다.


최종 회귀는 Go 테스트 1,628 pass / 9 skip / 0 fail, package 49 pass / 14 skip / 0 fail, vet exit 0이다. Linux 3개와 Windows 2개 빌드가 통과했다. 외부 DB/Python/CLI 등 환경 의존 검사는 skip에 포함된다. 타깃은 외부 패키지 import 0으로 오프라인 빌드됐으며, go.mod에 선언된 7개 모듈 전체 graph 조회는 캐시 metadata 부족으로 실패한 기록을 별도로 보존했다. 실제 사용한 타깃 빌드나 품질 실행의 실패를 뜻하지 않는다.
