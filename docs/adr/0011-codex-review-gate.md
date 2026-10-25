# 0011 Codex 리뷰 gate는 판정만 하고 리뷰 요청·머지는 세션이 한다

- 상태: 적용
- 날짜: 2026-10-26

## 배경

`sensibile/taeguk`은 PR head의 Codex 리뷰 결과를 commit status로 남기는 gate를 운영했다. 처음에는 gate가 `github-actions[bot]`으로 Codex 리뷰를 요청하고, 10분 간격 재요청과 3회 무응답 시 통과 규칙을 두었다. Codex는 bot 계정 요청을 무시했으므로, 이 규칙은 사실상 약 40분 뒤 리뷰 없이 통과로 작동했다. 사람 계정 요청에는 13초~2분 안에 응답했다. 또한 PR 본문의 `@codex` 문자열은 백틱 안에 있어도 리뷰 대신 Codex 클라우드 작업을 불렀다. 2026-10-25 BOSS가 gate를 status 판정 전용으로 줄이기로 결정했고(taeguk #16, #17), 2026-10-26 hoplites에도 적용하라고 지시했다.

## 결정

- taeguk main `062d95d`의 gate 스크립트·테스트·workflow를 가져와 `codex-review` commit status를 게시한다. gate는 Codex 리뷰를 요청하지 않고, 머지하지 않으며, 시간 기준 통과 규칙이 없다.
- 리뷰 요청과 머지는 PR을 맡은 Claude Code 세션이 BOSS 계정으로 한다. PR 제목·본문·댓글에는 리뷰 요청 댓글 말고는 `@codex` 문자열을 쓰지 않는다.
- gate가 `main`에 들어간 뒤 ruleset `main protection`의 필수 체크에 `codex-review`를 추가한다. strict는 기존 결정대로 사용하지 않는다.

세부 절차는 [리모트 저장소 운영](../repository-operations.md)에 있다.

## 대안과 영향

gate가 bot 계정으로 리뷰를 요청하는 방식은 Codex가 응답하지 않아 쓸 수 없다. 시간 기준 통과는 리뷰 없는 머지를 허용한다. 개인 token을 secret으로 넣어 bot 대신 요청하는 방식은 secret 변경이 BOSS 승인 사항이고 범위 밖이다.

영향: Codex가 응답하지 않으면 PR은 pending에 머물며 머지되지 않는다. 세션이 없는 PR은 사람이 리뷰 요청과 머지를 해야 한다. Codex 요약 댓글의 상태 표식은 공개 API가 아니므로 형식이 바뀌면 gate가 pending으로 막힌다. 이 gate는 저장소 writer를 신뢰하는 자동화이며 writer에 대한 보안 경계가 아니다.

## 검증 근거

- 가져온 스크립트는 Ruff 포맷 후 AST가 원본과 같다. 테스트 22개를 로컬과 `codex-review-gate-tests` workflow에서 실행한다.
- ruleset 반영과 gate의 실제 status 게시는 gate PR 머지 뒤 API로 확인하고 그 결과를 PR 기록에 남긴다.
