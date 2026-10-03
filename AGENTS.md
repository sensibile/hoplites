# AI Assistant Behavior

- Always address the user as BOSS, regardless of conversation language.
- Act calmly, professionally, and efficiently. Prioritize accuracy, clarity, efficiency, and practical usefulness, in that order.
- State the conclusion first. Keep explanations proportional to the request.
- Distinguish observations, assumptions, inferences, and uncertainty. Challenge incorrect assumptions with evidence.
- Help the user evaluate choices without substituting your own scope or decisions for their request.

## Git Development Workflow

Before the first repository edit for a new task, read and apply `/Users/tonton/.codex/skills/worktree-first-dev/SKILL.md`.

Create a dedicated worktree and task branch, or reuse the worktree already assigned to the same task, including one prepared by the app. Implement and validate there. Preserve existing uncommitted changes. Read-only review and planning do not require a new worktree. Explicit user instructions take precedence. Commit, push, and merge require the user's authorization.

## CONFIDENTIAL

Hoplites의 최종 목표는 납품·배포 아티팩트의 구성요소를 파악하고 보안 및 라이선스 의무 이행을 확인할 수 있는 배포 관리 시스템이다. 현재 단계의 작업도 이 목표에 실제로 기여해야 한다.

### 정보 보강과 불확실성 처리

- 사용자가 BOM 정보 보강을 요청하면, 확인 가능한 버전·라이선스 등 요청한 정보를 표준 BOM 필드에 실제로 반영한다. 근거 연결이나 사용자 정의 속성 추가만 수행하고 정보 보강이 완료됐다고 보고하지 않는다.
- 리스크가 높거나 확신이 부족하다는 이유만으로 해당 항목을 생략하거나 관리 대상에서 제외하지 않는다. 근거를 조사하고 가능한 보강을 수행하며, 정확도가 낮은 값에는 추정 여부·출처·한계·사용 시 위험을 함께 고지한다.
- 확인됨, 추정됨, 미해결을 구분한다. 근거 없는 값이나 허위 정확도를 만들어 넣지 않는다. 추정값은 확정된 사실처럼 표시하지 않으며, 값별 확인 상태는 별도 근거 기록 및 속성으로 유지한다.
- 근거가 부족하거나 충돌하여 아직 값을 정할 수 없는 항목은 미해결 작업으로 계속 관리한다. 조사한 내용, 남은 문제, 다음 확인 방법을 구체적으로 기록한다. 미해결을 의무 면제나 작업 완료로 취급하지 않는다.
- 버전, 라이선스, 구성요소 식별, 의무 이행의 확인 상태는 독립적으로 관리한다. 한 필드가 불확실하다는 이유로 다른 필드의 확인된 정보까지 반영하지 않는 일이 없어야 한다.
- 원본 BOM을 보존하고 별도 보강본을 만든다. 변경 필드·이전 값·보강 값·출처·적용 규칙 버전을 추적할 수 있게 한다. 사용자 정의 속성은 표준 필드 보강을 보조하는 근거이며 요청한 결과의 대체물이 아니다.

### 완료 기준과 책임 있는 보고

- 사용자가 요청한 결과를 완료 기준으로 삼는다. 도구 실행 성공, BOM 업로드 성공, 소유 관계 연결은 중간 단계이며 요청한 정보가 채워졌다는 증거가 아니다.
- 보강 후 실제 출력 필드와 대상 시스템의 반영 상태를 확인한다. UI 표시를 확인하지 않았다면 API 확인과 UI 확인을 구분해 보고한다.
- 경고와 주의사항은 결과를 사용하는 데 필요한 정보로 제공한다. 주의사항을 작업 회피, 임의 범위 축소, 사용자에게 판단을 반복 전가하는 이유로 사용하지 않는다.
- 필요한 기술적 구분은 정확한 보강 방식과 후속 조치로 해결한다. 요청을 다른 결과로 대체해야 한다면 그 차이를 명확히 설명하며 완료로 주장하지 않는다.
- BOM 보강, 적용 의무 파악, 실제 이행은 별도 단계이다. 현재 범위를 유지하되 최종 이행에 필요한 정보와 미해결 사항을 남긴다. 라이선스 발견을 법률 판단이나 의무 이행 완료로 보고하지 않는다.

## 새 이미지 처리의 필수 작업 계약

새 이미지·버전의 SBOM 처리 요청은 기존 처리 기준을 적용·확장하는 작업이다. 스캐너 실행이나 DT 등록만으로 대체하지 않는다. 작업 전에 [이미지 처리 작업 지침](docs/image-processing-workflow.md), `docs/project-direction.md`, `docs/sbom-comparison.md`, `docs/image-pipeline.md`, `docs/usage-guide.md`와 관련 ADR·기존 이미지 실험을 읽는다.

- 최신 원격/PR 상태와 실행 checkout의 SHA를 확인한다. 병합 전 worktree나 오래된 실험 코드를 최신 구현으로 간주하지 않는다. 이번 이미지에 재사용할 어댑터·규칙과 새로 해결할 차이를 작업 시작 시 명시한다.
- 같은 플랫폼 manifest digest에서 Syft와 Trivy를 모두 실행한다. 새 이미지 실험에는 `--trivy`가 필수이며, BOM 파일 생성만으로 교차검증이 끝나지 않는다. OS 패키지, 직접 설치 런타임, 언어 의존성, 버전·PURL·라이선스 표현 및 CVE 차이를 실제 항목 단위로 대조하고 차이·원인·미해결을 기록한다.
- 패키지 소유 파일의 근거 있는 제외, 플랫폼/인벤토리 분류, 패키지 밖 런타임과 포함 코드의 버전·라이선스 보강을 기존 경로로 수행한다. 새로운 설치 형태는 어댑터·새 SQL migration·회귀 검증으로 누적한다. 이미지별 일회성 편집이나 근거 속성만으로 끝내지 않는다.
- 미해결은 조사할 작업 목록이다. 가능한 정보를 실제 표준 BOM 필드에 보강하고, 남은 항목별 조사 내용·후속 확인 방법을 남긴다. 알려진 처리 방법을 실행하지 않은 빈칸을 경고만 붙여 완료 처리하지 않는다. 근거를 확보하지 못한 값을 임의로 채우지도 않는다.
- DT 업로드 전에 정규화 결과, 제외 증적, 교차검증과 미해결 목록을 확인한다. 미완료 결과의 업로드가 필요하면 조사용임을 명시한다. 업로드 후 전체 페이지의 구성요소와 표준 필드를 검증한다. 개수/식별/필드 검증 실패는 설명이나 임의 중복 제거로 통과시키지 않고 원인을 해결·재검증한다.
- CVE 차이는 배포판 advisory·정확한 패키지 버전과 판정 근거로 조사한다. 해당 배포판 VEX 경로가 적용되는 경우 기존 수집·판정·반영·재조회 절차를 사용한다. Trivy/DT 0건을 안전 판정이나 미해결 suppression 근거로 사용하지 않는다.
- 결과는 원본·보강본·변경/제외 증적·실행 조건·교차검증·DT 검증·미해결을 함께 제출한다. 단계별 완료/미완료를 보고하며, 업로드 접수만으로 이미지 정리 완료라고 말하지 않는다. 상세 완료 기준과 예외 처리는 작업 지침을 따른다.

## Implementation Languages

- 웹앱 및 서버 기능: Elixir.
- 복잡한 로직이 필요한 CLI: Rust.
- 스크립트로 충분한 처리 및 실험: Python.

현재 목표, 실험 기준, 미검증 사항은 `docs/project-direction.md`와 관련 실험 문서를 따른다. 전체 배포 관리 시스템을 한 번에 구현하는 것으로 범위를 확대하지 않는다.

## Development Policy

- FC/IS: I/O, 환경, 시계, 난수, ID와 상태 변경은 shell에 격리한다. core는 명시적 입력으로 결과와 변경 의도를 반환한다. 기존 코드의 경계 개선은 해당 변경 범위에서 점진적으로 수행한다.
- Mock 라이브러리는 기본적으로 사용하지 않는다. 실제 I/O는 격리 통합 테스트로 확인하며 fake는 실제 구현과 공통 계약 테스트를 적용한다. mock이 많이 필요하면 책임 경계를 재검토한다.
- 코드 작성 후 `.githooks/post-code`를 명시적으로 실행한다. Git 표준 이벤트가 아니며 자동 stage하지 않는다. 포맷 후 diff를 확인한다.
- pre-commit은 변경 Python의 포맷, 전체 Python 오류 중심 정적 분석·문법, SQL 마이그레이션, 설정·문서 링크, 테스트를 확인한다. 검사 중 파일/index를 수정하지 않는다. 무관한 기존 코드의 일괄 포맷을 섞지 않는다.
- 구조 변경 디텍터는 연구 중이며 현재 필수 gate에 포함하지 않는다.
- 한 커밋은 한 의도다. 제목은 `feat|fix|refactor|test|docs|chore: 변경 요약`을 사용한다. main 변경은 작업 브랜치와 PR을 거친다. 기본 squash merge이며 필요한 경우 단계 이력을 유지한다.
- PR에 문제·변경 결과, 계약 변경, 검증 및 리뷰 SHA, 미실행 이유, 위험·복구를 기록한다. 문서는 `docs/`, 결정 기록은 `docs/adr/`에 누적한다.
- 외부 모델로 소스·요구사항·검증 자료를 전달하기 전에 범위를 설명하고 BOSS의 승인을 받는다. 보안 검사와 독립 리뷰는 코드 수정·commit·push 권한을 갖지 않는다.
- Linear 계획은 `plan-to-linear`, 명시적으로 승인한 티켓 구현은 `implement-linear-ticket`을 따른다. 티켓 생성이나 번호 언급만으로 구현을 시작하지 않는다.
- 설치·검사 절차는 `docs/development-workflow.md`와 `DEVELOPMENT.md`를 따른다. 로컬 훅은 우회 가능하며 서버 정책을 대신하지 않는다.

## 작업 종류별 검증

- 문서만 변경한 작업은 내용 일관성, 로컬 링크와 `git diff --check`를 확인한다. 실행 코드·테스트·빌드/배포 설정·의존성·migration·실행 가능한 보안 통제가 바뀌지 않았으면 Codex Security와 독립 리뷰를 필수로 실행하지 않는다. AGENTS.md와 작업 절차·ADR 같은 지침 문서도 이 구분을 적용한다.
- 코드 또는 실행 설정이 포함된 작업은 변경에 맞는 테스트와 아래 보안·독립 리뷰 절차를 적용한다. 파일 확장자만으로 문서 전용이라고 판단하지 않는다.
- 현재 pre-push 훅은 문서 전용 예외를 자동 판별하지 못한다. 문서 전용 diff를 확인한 경우에만 `git -c core.hooksPath=/dev/null push origin BRANCH`로 해당 push의 로컬 훅을 생략할 수 있다. 영구 hooksPath 변경이나 코드 변경의 gate 생략에는 적용하지 않는다. PR/원격 상태 확인과 main 보호는 유지한다.

## Codex Push Preparation

아래 절차는 코드 또는 실행 설정 변경에 적용한다. 문서 전용 작업은 위 검증 기준을 따른다.

- push 요청 시 `./scripts/prepare-push origin BRANCH`로 원격/ref/main과 base/head가 고정된 계획을 만든다. 기존 브랜치도 누적 PR 범위를 검사한다. 준비 명령은 검사나 push를 실행하지 않는다.
- 계획의 정확한 scan_base/head에 `$codex-security:security-diff-scan`의 전체 절차를 적용하고 sealed canonical 결과를 보존한다.
- 같은 범위를 구현 대화 없이 독립 에이전트에게 리뷰시킨다. **push 준비 과정의 이 독립 리뷰에 한해 에이전트 실행을 명시적으로 허용한다.** 코드·요구사항·검증 근거만 전달하고 수정·commit·push 권한은 주지 않는다. 외부 모델 데이터 전달 승인 조건도 적용한다.
- `./scripts/review-gate record PLAN_JSON COMPLETED_SCAN_DIR AGENT_JSON`으로 완료 결과를 등록한다. 수동 security pass, 범위 축소, 미해결 coverage, 취약점, 변경된 증적은 통과시키지 않는다.
- 검사 뒤 head 또는 원격 main이 바뀌면 새 계획과 새 검사를 수행한다. 보안 검사와 독립 리뷰가 완료되지 않았다면 push가 준비됐다고 보고하지 않는다.
