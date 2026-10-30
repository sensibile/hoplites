# SAST 방향 A-0: 비배포판 CVE의 납품물 코드 포함 판정

- 상태: open
- 작성: 2026-10-30, Claude(vex-code-presence 세션) 초안
- 확인: 없음. accepted는 BOSS 확인 후에만 기록한다.

## BOSS 원래 표현

이 세션은 BOSS의 원문을 직접 받지 않았다. 상위 세션이 전달한 지시는 다음과 같다. BOSS의 원문은 상위 세션 기록에 있다.

> BOSS의 지시로 SAST 방향의 첫 단계 A-0을 수행한다.

상위 세션이 기록한 합의 배경(2026-10-30)은 다음과 같다. 해석은 A(SCA CVE의 도달성 판정), B(자사 소스 SAST), C(엔진+LLM 트리아지·룰 합성)로 나눴고, 순서는 A-0 → C → A 본편 → B다.

## 문제

비배포판 CVE(npm·pip 번들, 직접 설치 런타임)는 배포판 VEX로 판정할 수 없어 미분석으로 쌓인다. 현재 이미지는 앱 진입점이 없는 베이스 이미지라서 도달 불가 판정은 근거 없는 안전 판정이 된다.

## 기대 결과

릴리스 승인자와 보안 검토자가 "이 이미지의 비배포판 CVE 중 무엇이 실제 납품물에 포함된 취약 코드인가"를 결정적 근거로 확인한다. 결과는 CycloneDX VEX(`code_not_present`는 confirmed 근거가 있을 때만, 나머지는 `in_triage`)와 근거 sidecar로 기존 DT 경로에 반영한다.

## 영향받는 사용자·시스템

릴리스 승인자, 보안 검토자, DT 프로젝트의 분석 상태, `run_project_vex.py`·`apply_dtrack_vex.py` 경로.

## 제약

- 베이스 이미지에 `code_not_reachable`을 쓰지 않는다.
- 외부 모델에 자료를 보낼 때는 BOSS 승인을 먼저 받는다.
- 코드 push는 Codex Push Preparation gate를 통과해야 한다.

## 미해결 질문

- DT 기준 판정 대상이 Node 13건뿐이다. 실제 공백은 런타임 CVE 탐지다. C(엔진+LLM)나 탐지 범위 확대를 앞당길지 BOSS가 판단해야 한다.
- Trivy에만 있는 비배포판 CVE(Node 13, Python 9)를 DT에 finding으로 연결할 방법(analyzer 구성 또는 BOM 보강)이 정해지지 않았다.
- 판정 결과 `in_triage`(confirmed-present)를 배포 승인에서 어떻게 다룰지는 아직 정해지지 않았다. 차단할지, 업그레이드 조건부로 할지가 남아 있다.

## 연결

- 결정: [ADR 0012](../docs/adr/0012-code-presence-vex.md)
- 실험 기록: [코드 포함 판정 VEX](../docs/code-presence-vex.md)
- 요구사항 ID: 아직 없음(accepted 이후 REQ-007 기록으로 만든다).
