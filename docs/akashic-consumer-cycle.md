# Hoplites의 Acropolis 소비자 첫 사이클

## 목적과 역할

신규 아티팩트 담당자가 구성요소의 역할, 적용 조건, 판단 근거와 다음 작업을 파악하도록 한다. Acropolis는 지식을 보존하고 Hoplites는 조사·조치·보고서를 수행한다. 정적 원문은 기존 DB/파일에 남기고 판단에 필요한 사실·해석·결정·미해결 질문과 근거 참조만 연결한다.

## 실제 입력과 대상

Node ARM64 manifest `sha256:24b8bc17702002d2ed0c1da9ad66c3ee507cc279d0856726662ff2b6fc35c149`의 gcc-12-base 12.2.0-14+deb12u1을 대상으로 했다. Node 조사 작업의 `artifacts/license-scope-fixed-node-002/normalized.cdx.json`, `license-scopes.json`, `rootfs.tar`를 사용한다. 원본 BOM, sources, stages 근거와 DT 검증은 기존 증거 저장소에 보존한다. 각 입력의 SHA-256을 묶음과 보고서에 고정한다.

`hoplites_knowledge.py prepare --rootfs`는 tar를 디스크에 풀지 않고 실제 dpkg 설치 목록과 status를 읽는다. owner의 패키지·아키텍처·버전·설치 상태를 대조하고 파일 목록과 역방향 의존 선언을 기록한다. 연결된 tar 항목, 중복 항목, 크기 초과를 거부한다. 의존 선언은 의존성 해결기 결과나 삭제 안전성 판정이 아니다. 원문 hash의 장기 blob resolver 및 NAS 보존은 아직 구현하지 않았다.

실제 목록에는 공통 문서와 상위 디렉터리만 있으며 컴파일러 실행 파일 경로는 없다. libgcc-s1과 libstdc++6의 같은 버전 의존 선언을 확인했다. 이 역할 관찰을 문서별 라이선스 적용 판단과 구분한다.

## 객체와 관계

아티팩트는 manifest+platform, 컴포넌트는 PURL+artifact 조건으로 식별한다. bom-ref는 입력 내부 연결이며 DT UUID는 소비 시스템 연결이다. evidence/statement/decision/question과 supports/contradicts/supersedes를 구분한다. 작성 주체·버전, 확인/추정/미해결, 적용 조건, 원문 참조·해시와 추정 이유·한계를 보존한다.

선언 식, 실제 포함, 적용 판단과 이행 상태는 독립적으로 유지한다. source scope payload를 content에 보존하는 것은 첫 소비자 매핑이며 최종 도메인 ontology payload의 설계 확정이 아니다. 스캐너 해시 오표기는 조건이 아니라는 관찰로 보존한다. 이를 별도의 라이선스 적용 과제로 반복 생성하지 않는다. 원래 scope의 미확인·검토 작업은 evidence payload에 남긴다.

같은 PURL이라도 다른 이미지·버전이나 평가할 수 없는 추가 조건이 있으면 자동 재사용하지 않는다. 제외된 조건 기록 ID를 보고서에 남긴다. 지원 근거는 다른 subject에 있어도 전이적으로 따라가되 조건을 보존한다.

## 확정된 로컬 서비스 계약

Acropolis 담당 작업의 `akashic/docs/knowledge-tenants.md`와 `services/knowledge/gateway.py`를 읽고 연결했다. provider workspace는 `/private/tmp/acropolis-knowledge-evidence-cycle/akashic`이다. provider 파일은 이 작업에서 수정하지 않는다.

* HTTP endpoint: `http://127.0.0.1:64908/v1/tenants/hoplites/knowledge`. 실제 포트는 provider의 `.cache/hoplites-tenant-service/endpoint.json`을 읽는다.
* POST JSON 명령: apply/get/subject/history. apply는 request_id/expected_version/operations를 받는다. get/subject의 특정 버전이 없으면 현재 버전으로 대체하지 않는다.
* 서비스가 관리자가 발급한 Bearer 자격증명을 tenant와 principal, read/write 권한에 결합한다. 요청 author나 tenant 문자열은 권한 증명이 아니다.
* 응답은 ok/tenant/principal/result이며 소비자가 고정 tenant=hoplites와 자격증명의 principal을 대조한다. 응답 성공만으로 사실성·법률 판단·이행을 완료로 표시하지 않는다.
* 호출 자격증명 파일은 provider `.cache/hoplites-tenant-service/hoplites.credential.json`이다. 파일 내용을 인자·로그·산출물·tracked 파일에 넣지 않는다. 소유자와 private permission을 확인한다.

현재 연결은 로컬 loopback 서비스 계정이다. 외부 서버·redirect·다른 tenant 경로·URL 자격증명을 소비자가 거부한다. SSO/Axiom 동적 PDP, TLS 기반 원격 연결, NAS 운영 배포, 원문 blob 인가는 이 사이클의 완료 범위가 아니다.

## 소비자 실행과 실패 보존

`acropolis_consumer.py`는 적재 묶음, endpoint 파일, 자격증명 파일과 명시적 expected_version을 받는다. provider는 기존 자료를 version=1에 먼저 적재했고 소비자는 현재 버전 1을 확인한 뒤 추가 조사 자료를 version=2에 적재했다. 빈 저장소나 expected_version=0을 가정하지 않는다.

쓰기 전 request를 새 출력 디렉터리에 보존한다. 자동 재시도하지 않는다. 동일 요청을 재전달할 때 최초 request_id와 expected_version을 유지해야 한다. 전송 실패 시 쓰기 결과를 unknown으로 유지하고, 403 거부는 rejected로 기록한다. 실패는 partial로 남기며 완료 보고서를 생성하지 않는다. 파일·디렉터리·기존 보고서를 덮어쓰지 않는다.

성공 후 반환 버전을 명시해 조회하고, history의 receipt가 실제 요청과 write 결과를 그대로 보존했는지 대조한다. 원본 기록·관계가 조회 결과에 있는지 확인한 뒤 report.json과 자체 포함 HTML을 생성한다. 인증 연결 전 묶음은 offline-draft, 실제 로컬 서비스 조회본은 local-authenticated로 구분한다. 후자는 운영 배포나 법률적 완료를 뜻하지 않는다.

보고서에는 역할과 의존 이유, 대상별 선언·포함·적용·이행 상태, 다음 작업, 판단·근거·관계, artifact/rule/input hash/knowledge version을 표시한다. 일반 질문에 제공되지 않은 라이선스 상태 필드를 만들어 붙이지 않는다. 모든 출처·내용은 HTML에서 escape하며 스크립트나 외부 요청을 삽입하지 않는다.

## 실제 결과와 검증

산출물은 이 worktree의 아래 경로에 보존했다.

| 경로 | 관찰 |
| --- | --- |
| `artifacts/acropolis-consumer-gcc12-003/write-bundle.json` | 실제 scope·설치 목록·역방향 의존 자료의 추가 적재 묶음 |
| `artifacts/acropolis-consumer-gcc12-live-001/request.json` | 실제 재전달 식별자와 expected_version=1 |
| `artifacts/acropolis-consumer-gcc12-live-001/apply-response.json` | tenant=hoplites, principal=hoplites-service, version=2 |
| `artifacts/acropolis-consumer-gcc12-live-001/snapshot-response.json` | version=2의 실제 인증된 전체 조회 |
| `artifacts/acropolis-consumer-gcc12-live-001/history-response.json` | 원본 요청·쓰기 결과 receipt 일치 |
| `artifacts/acropolis-consumer-gcc12-live-001/report.json` | 특정 버전·조건·근거·미해결을 고정한 보고서 입력 |
| `artifacts/acropolis-consumer-gcc12-live-001/report-final.html` | 브라우저에서 확인한 담당자 조사 보고서 |
| `artifacts/acropolis-consumer-gcc12-live-001/live-verification.json` | 실제 서비스의 동일 버전 JSON 재현, 미인증/교차 tenant 조회·이력 403 |
| `artifacts/acropolis-consumer-gcc12-live-001/integration-check-final.json` | 격리 실제 HTTP/RocksDB 소비자 사이클의 6개 검사 PASS |

격리 소비자 검사는 실제 적재·조회·receipt, 후속 버전 저장 뒤 이전 JSON/HTML의 동일성, 동일 요청의 최초 버전 재전달, 미인증/교차 tenant 읽기·쓰기·이력 거부, 권한 철회, 거부된 쓰기의 실패 보존을 확인했다. 테스트 자료는 실제 조사 결과로 발행하지 않는다. provider 소스는 그대로 두고 임시 private DB만 사용한다.

전체 Python 단위·파일 I/O 시험은 110개 통과했다. formatting/static/syntax/SQL/config/documentation gate도 통과했다. 브라우저에서는 실제 package 역할, 의존 패키지, 적용 미확인과 다음 조치, 근거·버전 표시를 확인했다. 라이선스 자체의 적용·이행 판정, 담당자의 업무 상태 변경 UI와 제품 서버 구축은 추가 업무다.
