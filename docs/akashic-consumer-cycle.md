# Hoplites의 Acropolis 소비자 첫 사이클

## 목적과 역할

신규 아티팩트 담당자가 구성요소의 역할, 적용 조건, 판단 근거와 다음 작업을 파악하도록 한다. Acropolis는 지식을 보존하고 Hoplites는 조사·조치·보고서를 수행한다. 정적 원문은 기존 DB/파일에 남기고 판단에 필요한 사실·해석·결정·미해결 질문과 근거 참조만 연결한다.

## 실제 입력과 첫 대상

Node ARM64 manifest `sha256:24b8bc17702002d2ed0c1da9ad66c3ee507cc279d0856726662ff2b6fc35c149`의 gcc-12-base 12.2.0-14+deb12u1을 대상으로 한다. 기존 Node 작업의 `artifacts/license-scope-fixed-node-002/normalized.cdx.json`과 `license-scopes.json`을 사용한다. 원본 BOM, rootfs, sources, stages 근거와 DT 검증은 기존 증거 저장소에 보존한다. 각 입력 해시를 묶음에 고정한다.

## 객체와 관계

아티팩트는 manifest+platform, 컴포넌트는 PURL+artifact 조건으로 식별한다. bom-ref는 입력 내부 연결이며 DT UUID는 소비 시스템 연결이다. evidence/statement/decision/question과 supports/contradicts/supersedes를 구분한다. 작성 주체·버전, 확인/추정/미해결, 적용 조건과 원문 참조·해시, 추정 이유·한계를 보존한다. 선언 식, 실제 포함, 적용 판단과 이행 상태는 독립적으로 유지한다. licence scope 원본 payload를 content에 보존하는 것은 임시 매핑이며 최종 도메인 ontology payload 계약은 미확정이다.

## 읽기·쓰기·인증 계약

운영 namespace의 tenant는 `hoplites`다. 서버가 인증된 소비 principal의 tenant와 권한을 검증하고 write/read/version/history를 각각 허용해야 한다. 요청의 author 또는 tenant 문자열은 인증의 대체물이 아니다. 인증 제공자, 토큰 audience/issuer, 실제 endpoint, 정책 평가·집행 경로와 tenant 생성은 Acropolis 담당 작업에서 확정한다.

쓰기의 request_id와 expected_version, 동일 요청 재전달, stale/conflicting 요청 거부를 요구한다. 읽기는 특정 snapshot version을 필수 지정하고 없는 버전을 latest로 대체하지 않는다. subject 조회는 전이적인 근거도 반환해야 한다. 과거 버전·receipt·근거 blob에 동일한 tenant 인가를 적용해야 한다.

운영 연결 완료에는 실제 Hoplites tenant 생성, 인가된 principal의 읽기/쓰기/버전 조회 성공과 미인증·tenant 누락/불일치·교차 tenant·권한 철회의 거부 증거가 필요하다. 이 시험은 현재 미실행이다. 로컬 JSON의 namespace 검사는 인증된 서비스 격리를 입증하지 않는다.

## 로컬 구현과 완료 범위

`scripts/hoplites_knowledge.py`는 실제 BOM과 scope 자료를 골라 검토용 쓰기 묶음을 생성한다. source evidence의 관찰과 법적 적용 판단을 분리하고 review_actions와 미해결을 유지한다. 서버 호출은 하지 않는다. 공개 Akashic 로컬 시제품의 apply/get JSON 모양을 사용하되 운영 계약 확정으로 간주하지 않는다.

보고서 입력은 특정 snapshot version, snapshot hash, 쓰기 입력 hash, artifact/rule version을 고정한다. source·조건·이력·미해결과 다음 조치를 정적으로 출력한다. 새 snapshot을 받은 뒤에도 기존 버전 보고서 재생성 결과가 같아야 한다. 조회가 최신으로 조용히 바뀌거나 다른 tenant의 데이터를 받으면 거부해야 한다. 인증 연결 전 산출물은 offline-draft이며 운영 승인·라이선스 이행 완료가 아니다.

Acropolis 인계 위치는 `/private/tmp/acropolis-knowledge-evidence-cycle`이다. 그 저장소 편집은 Acropolis 담당 채팅이 맡는다. 이 작업은 Hoplites 소비자 구현만 진행한다.

## 현재 검증과 산출물

실제 gcc-12-base 자료의 로컬 적재 검토 묶음은 `artifacts/acropolis-consumer-gcc12-001/write-bundle.json`이다. 근거 관찰 1건, 미해결 질문 2건과 supports 2건을 보존한다. 확인된 evidence는 입력을 관찰했다는 뜻이며, scope의 포함 추정·적용 미확인·이행 미검증을 확인됨으로 승격하지 않는다.

write_template의 expected_version은 null이다. 실제 운영 기준 버전을 서버에서 확인하고 소비자 연결 계약이 확정된 후 설정해야 한다. 이 묶음은 그대로 서버에 보낼 수 있는 승인된 요청이 아니다. 원문 locator는 입력 hash를 가리키는 URN이며 실제 blob resolver와 인가 계약은 미확정이다.

로컬 report 입력은 tenant/version/graph(records, links)를 가진 명시적 export다. 서버 인증 receipt로 간주하지 않는다. 보고서는 정확한 원본 기록·관계·조건의 일치와 버전·namespace를 검사하고, 원래 질문·근거 및 뒤에 추가된 판단을 함께 보존한다. 기존 출력 파일은 덮어쓰지 않는다. 새 버전 조회를 이전 보고서 버전으로 오인하는 경우 거부한다.

추가 시험 4개는 상태·다음 작업 보존, 버전 1 재현/버전 불일치 거부, namespace 누락·불일치와 근거 변경 거부, 실제 파일 입출력/중복 JSON/기존 출력 보존을 확인한다. 전체 Python 시험 105개와 formatting/static/syntax/SQL/config/documentation 검사는 통과했다. 서비스의 교차 tenant 차단, 실제 tenant 생성·인가, 원문 blob 읽기, 실제 서버 적재·조회와 정적 사용자 보고서 화면은 아직 검증하지 않았다.
