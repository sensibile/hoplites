# 리모트 저장소 운영

이 문서는 `sensibile/hoplites` PR을 Claude Code 세션이 맡을 때의 리뷰·머지 절차와 Codex 리뷰 gate를 기록한다. 위임 범위와 서버 정책의 원본은 AGENTS.md의 "리모트 저장소 위임 범위"다. 이 문서는 GitHub 권한을 부여하거나 제한하지 않는다. 실제 강제는 GitHub ruleset이 한다. 결정 배경은 [ADR 0011](adr/0011-codex-review-gate.md)에 있다.

gate 구현은 `sensibile/taeguk` main `062d95d`의 `scripts/codex_review_gate.py`, `tests/test_codex_review_gate.py`, `.github/workflows/codex-review-gate.yml`을 가져왔다. 스크립트는 Ruff 포맷만 적용했으며 AST가 원본과 같다. 테스트는 저장소 이름과 import 방식만 바꿨다. workflow는 이 저장소 관례대로 `actions/checkout`을 커밋 SHA로 고정했다. 아래 근거의 PR 번호는 따로 적지 않으면 `sensibile/taeguk` PR이다.

## PR 플로우

1. 작업 worktree와 `<type>/<slug>` 브랜치에서 변경하고 `.githooks/post-code`, pre-commit 검사 등 [개발 설정 가이드](development-workflow.md)의 해당 검증을 실행한다.
2. 코드·실행 설정 변경은 push 전에 AGENTS.md의 Codex Push Preparation gate를 통과한다. 절차는 [개발 훅 운영](../DEVELOPMENT.md)의 `./scripts/prepare-push`, `$codex-security:security-diff-scan`, 독립 리뷰, `./scripts/review-gate record`다. 문서 전용 변경은 [문서 작업 규칙](documentation-policy.md)을 따른다.
3. PR은 제목과 본문에 `@codex` 문자열 없이 연다. 그러면 Codex가 PR 생성 리뷰를 스스로 시작한다. 세션은 2분 동안 그 head에 대한 리뷰 요약 댓글(`codex-review-state`)이 붙는지 확인하고, 붙지 않을 때만 BOSS 계정으로 `@codex review` 댓글을 남긴다(2026-10-25 BOSS 결정). 근거: 본문에 `@codex`가 없던 PR #9~#12는 생성 후 10~20초 안에 리뷰 요약이 붙었다. 본문에 있던 PR #13~#16에는 리뷰 요약 대신 멘션으로 호출된 Codex 클라우드 작업의 반응이 붙었고, gate가 판정할 요약과 결과 표식(`codex-review-receipt`)은 남지 않았다. 리뷰(PR 생성, 새 커밋 push, `@codex review` 댓글)는 클라우드 환경이 없던 PR #9~#12에서도 돌았으므로 Codex 리뷰에는 클라우드 환경이 필요하지 않다. Codex는 코드 표기(백틱) 안의 `@codex`도 멘션으로 읽는다(PR #15를 닫으며 남긴 댓글). "Codex review"나 `codex-review` 같은 문구는 트리거가 아니다(PR #9, #11). 그래서 PR 제목, 본문, 댓글에는 리뷰를 요청하는 댓글 말고는 `@codex` 문자열을 쓰지 않는다. 가리킬 때는 "Codex 리뷰 요청"처럼 풀어 쓴다.
4. `Codex review gate` workflow는 PR head 커밋에 대한 Codex 리뷰 결과를 commit status `codex-review`로 남기는 판정만 한다. 리뷰를 요청하거나 머지하지 않으며 시간 기준 통과 규칙도 없다. 판정 규칙은 아래 "gate 판정"에 있다.
5. 리뷰 요청은 PR을 맡은 Claude Code 세션이 BOSS 계정(세션의 `gh` 인증 계정)으로 한다(2026-10-25 BOSS 결정). Codex는 `github-actions[bot]`의 요청에는 응답하지 않았고(PR #3, `sensibile/archon` PR #12), 사람 계정 요청에는 13초에서 2분 안에 응답했다(PR #3, #6, #13, #15, `sensibile/archon` PR #12). 세션은 PR을 만들고 2분 안에 리뷰 요약이 붙지 않았을 때(3단계), 새 커밋을 push했을 때, gate가 무효 표시 댓글을 남겼을 때 그 head에 `@codex review`를 한 번 남긴다. 그 head에 대한 Codex 결과 댓글이 이미 있거나 리뷰가 `running`이면 남기지 않는다. 요청 뒤 10분 넘게 Codex가 시작하지 않거나 `running`에서 멈추면 한 번 더 요청하고, 그래도 응답이 없으면 BOSS에게 보고한다. 멈춤은 Auto-fix 이벤트로 전달되지 않으므로 세션이 직접 다시 확인한다. 응답이 없다고 리뷰 없이 머지하지 않는다.
6. 머지도 PR을 맡은 세션이 한다. 세션은 PR head의 `codex-review`가 success이고 그 head에 미해결 리뷰 thread가 없을 때 `gh pr merge <번호> --squash --auto --match-head-commit <리뷰한 head SHA>`로 auto-merge를 켠다. 머지는 리뷰한 커밋으로 고정되고, 나머지 필수 체크가 통과하면 GitHub가 머지한다. draft PR이나 `no-auto-merge` label이 붙은 PR에는 켜지 않는다. 이 opt-out은 세션이 지키는 운영 규칙이며 GitHub 머지 조건이 아니다. 이미 켠 뒤에 멈추려면 PR을 draft로 바꾸거나 auto-merge를 직접 해제한다. Auto-fix가 켜져 있으면 Codex 결과 댓글과 CI 결과가 세션에 전달되어 세션이 이어서 판단한다. 이 전달은 관측된 동작이며 보장된 기능이 아니다. 세션이 없는 PR은 `codex-review`가 success여도 사람이 머지할 때까지 대기한다.

## gate 판정

근거는 `chatgpt-codex-connector[bot]` 요약 댓글의 `codex-review-state` 상태다. head 커밋에 대한 리뷰가 `completed`이고 미해소 지적이 없으면(`has_unresolved_findings: false`) success, 미해소 지적이 있으면 failure, 그 밖에는 pending이다. Codex가 지적 없이 끝난 리뷰에 `has_unresolved_findings: null`을 남기는 경우가 있다(PR #3). 2026-10-24 BOSS 승인에 따라 이때는 두 조건을 모두 만족할 때만 success로 본다. 같은 head 커밋에 대한 Codex의 최신 결과 댓글이 "Didn't find any major issues"이고, Codex가 시작한 미해결 리뷰 thread가 0개여야 한다. 둘 중 하나라도 확인할 수 없으면 pending이다.

- 리뷰 thread를 해결하는 이벤트로는 gate가 다시 실행되지 않는다. thread를 해결한 뒤에는 다음 이벤트가 있어야 다시 판정한다.
- 시간이 지나도 판정은 바뀌지 않는다. Codex가 그 head를 리뷰하지 않으면 status는 pending에 머물고 PR은 머지되지 않는다. 새 커밋을 push하면 pending으로 돌아간다.
- Codex 요약 댓글이 삭제되거나 PR base가 바뀌면 gate가 이전 리뷰를 무효로 표시하는 댓글(head 표식 포함)을 남긴다. 무효 표시 이후 Codex가 요약을 갱신해야 다시 판정한다.
- 2026-10-25 BOSS 결정으로 시간 기준 규칙(10분 간격 재요청, 3회 무응답 시 통과), gate의 `@codex review` 요청, 주기 실행, gate의 auto-merge를 두지 않는다. Codex가 `github-actions[bot]`의 요청에 응답하지 않아 시간 기준 규칙이 사실상 "판정이 멈추면 약 40분 뒤 리뷰 없이 통과"로 작동했기 때문이다.

요약 댓글의 상태 표식은 Codex의 공개 API가 아니다. 형식이 바뀌어 읽을 수 없으면 gate는 pending으로 남고 필수 체크가 막혀 머지되지 않는다. 이 경우 Codex 결과를 직접 확인하고 BOSS 확인을 받아 처리한다.

gate workflow는 `pull_request_target`과 `issue_comment`로만 실행된다. 두 이벤트 모두 기본 브랜치의 workflow와 스크립트를 실행하므로 PR이 자기 판정 코드를 바꿀 수 없다. `gate` job 권한은 `statuses: write` 외에는 read이고, 무효 표식을 남기는 `record` job만 `issues: write`를 갖는다. 다만 push 권한이 있는 사람은 다른 workflow로 `GITHUB_TOKEN` status를 게시할 수 있다. gate는 저장소 writer를 신뢰하는 전제의 자동화이며 writer에 대한 보안 경계가 아니다. fork PR과 기본 브랜치가 아닌 base로 향하는 PR은 처리하지 않는다. commit status는 PR이 아니라 커밋 SHA에 붙으므로, 같은 head를 공유하는 다른 base PR의 결과가 `main` PR 판정을 덮어쓰지 않게 하기 위해서다.

workflow는 job 두 개로 나뉜다. `record` job은 직렬화하지 않으며, 리뷰를 무효로 만드는 이벤트를 PR 댓글 표식으로 남기는 일만 한다. `gate` job은 PR별로 직렬화되어 판정을 차례로 게시하고, 이벤트 내용이 아니라 PR의 현재 상태(댓글, head, base)로만 판정한다. GitHub concurrency는 대기 중인 job을 나중 job으로 교체하지만, 교체한 job은 더 늦게 대기열에 들어왔으므로 같거나 더 새로운 상태를 읽는다. 판정은 success를 게시하기 직전에 한 번 더 확인한다.

## GitHub 설정

- 필수 체크: `documentation-policy`와 commit status `codex-review`(integration 15368, GitHub Actions). 기본 브랜치에 없는 workflow는 댓글 이벤트에 반응하지 않으므로 gate가 `main`에 들어간 뒤 지정했다. 2026-10-26 gate PR(#14, 머지 `c377af2`) 뒤 ruleset `main protection`(id 25695862)에 추가하고 API 조회로 두 체크와 strict 미사용을 확인했다. label `no-auto-merge`도 같은 날 만들었다. gate PR 자체에는 gate가 아직 기본 브랜치에 없어 `codex-review` status가 게시되지 않았다. 그래서 세션이 그 head의 Codex 요약 상태(`completed`, `has_unresolved_findings: false`)와 미해결 thread 0개를 직접 확인한 뒤 head를 고정해 머지했다. 당시 ruleset은 `codex-review`를 요구하지 않았다. `codex-review`는 gate 스크립트의 status context 이름에 의존한다. 이름을 바꾸면 ruleset도 함께 갱신한다.
- `codex-review-gate-tests` workflow가 PR마다 gate 테스트를 실행한다. 필수 체크로 지정하지 않았다. 같은 테스트는 pre-commit의 전체 테스트에도 포함된다.
- label `no-auto-merge`: 세션이 auto-merge를 켜지 않을 PR 표시.
- 최신 base 요구(strict)는 사용하지 않는다. 따라서 `main`이 앞서 나가도 auto-merge는 PR을 갱신하지 않고 머지하며, squash 결과는 PR 단계에서 검사한 merge ref와 다를 수 있다. 충돌이 나면 GitHub가 머지하지 않는다. 세션이 PR 브랜치를 갱신하면 head가 바뀌므로 5단계대로 리뷰를 다시 요청한다.
