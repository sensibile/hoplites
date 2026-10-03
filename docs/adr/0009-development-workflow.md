# ADR 0009: 공통 개발 정책과 검증 훅

- 상태: 채택
- 날짜: 2026-10-03

## 배경

이미지 정규화·DT 파이프라인 이후 기능을 확장하면서 Acropolis와 같은 개발 정책, commit 검사, 보안·독립 리뷰 증적을 적용할 필요가 있다. 기존 Hoplites의 CONFIDENTIAL 보강 원칙과 언어 기준은 유지해야 한다.

## 결정

Acropolis 로컬 개발 지침·PR 템플릿·훅·sealed review gate를 가져온다. submodule 검사는 Hoplites Python·SQL·문서 검사로 대체한다. 변경 Python만 포맷하고 전체 Python 오류 중심 분석과 기존 unittest를 실행한다. 검사 중 index를 수정하지 않는다.

기존·새 브랜치 모두 원격 main의 merge-base부터 최종 head까지 누적 PR 범위로 검사한다. 계획 뒤 main 또는 head가 바뀌면 증적을 갱신한다. 독립 리뷰를 수행할 에이전트 실행은 승인된 push 준비 절차에서만 허용한다.

## 결과와 한계

개발 설정은 worktree별 의존성과 공통 Git hooksPath 설치가 필요하다. 로컬 훅은 서버 보안 검사를 대신하지 않는다. 합성 gate 검증은 실제 보안 검사·독립 리뷰로 취급하지 않는다. server main 보호 항목과 로컬 검사 보장 범위는 [개발 가이드](../development-workflow.md)에 기록한다.
