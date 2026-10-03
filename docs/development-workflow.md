# 개발 작업 설정

2026-10-03, 로컬 `/Users/tonton/Documents/workspace/acropolis`의 개발 지침·훅·sealed review gate·PR 템플릿을 기준으로 Hoplites에 적용했다. 가져온 기준 파일 일부는 Acropolis에서 아직 untracked 상태였으며, 원격에 배포된 설정이라고 가정하지 않았다. Acropolis 파일은 수정하지 않았다.

## 설치

전용 worktree의 저장소 루트에서 실행한다. Python 3.10 이상과 `uv` 또는 `venv/pip`를 사용한다.

```sh
uv venv --python python3 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
./scripts/install-hooks
```

`uv`가 없으면 다음으로 대체한다.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
./scripts/install-hooks
```

`.venv`는 로컬 전용이다. Ruff 버전은 `requirements-dev.txt`로 고정하고 검사 시 대조한다. 새 worktree에서는 가상환경을 별도로 준비한다.

훅 설치는 Git 공통 설정의 `core.hooksPath`를 현재 worktree의 `.githooks` 절대 경로로 연결한다. 모든 linked worktree가 같은 훅 진입점을 사용하지만, 검사는 **실제 명령을 실행한 checkout**의 스크립트·설정을 사용한다. 다른 hooksPath가 있으면 덮어쓰지 않는다. 이 설정 이전 버전의 checkout에서 스크립트가 없으면 실패하므로, 해당 checkout도 개발 설정이 포함된 버전으로 진행해야 한다. 설치한 worktree를 옮기거나 삭제하기 전에 유지할 checkout에서 hooksPath를 확인하고 다시 연결한다.

## 작업 순서

1. 원격 source/target SHA와 관련 PR 상태를 확인하고 `worktree-first-dev`로 작업 공간을 준비한다.
2. core에는 명시적 입력과 결과를, shell에는 I/O·환경·상태 변경을 둔다. 실제 I/O 통합 검증과 fake 계약 검증을 구분한다.
3. 코드 작성 후 아래 명령으로 변경 Python만 포맷한다. 결과 diff를 확인하고 의도한 파일을 직접 stage한다.

```sh
.githooks/post-code
python3 scripts/check-config
```

4. 승인받은 commit은 한 의도로 만들고 `feat|fix|refactor|test|docs|chore:` 제목을 사용한다.
5. push 승인 후 계획 → 보안 검사 → 독립 리뷰 → sealed 결과 등록 → push → PR 순서를 따른다. 상세 명령과 증적 형식은 [DEVELOPMENT.md](../DEVELOPMENT.md)에 있다.

`post-code`는 Git의 자동 이벤트가 아니다. 에이전트·편집기가 명시적으로 호출하며 자동 staging을 하지 않는다. 기존 Python 전체를 일괄 포맷하지 않고 현재 `HEAD` 대비 변경한 파일과 새 Python 파일만 처리한다.

## 커밋 전 검사

pre-commit은 unstaged tracked 변경과 non-ignored untracked 파일을 차단한다. 부분 stage 상태에서 검사 결과가 commit과 달라지는 일을 막으며, 검사 중 파일·index를 수정하지 않는다.

- 변경 Python의 Ruff 포맷 검증
- 전체 Python의 오류 중심 Ruff 정적 검사와 Python 3.10 문법 검사
- SQL 마이그레이션 전체를 메모리 SQLite에 순서대로 적용
- 배포 JSON·쉘 스크립트 문법·문서의 로컬 파일 링크 확인
- 기존 unittest 실행

새 개발 설정 자체가 아직 untracked인 단계에서는 pre-commit이 차단되는 것이 정상이다. 로컬 검사와 아래 disposable 테스트를 먼저 실행하고, commit 승인 후 의도한 파일을 stage한다.

```sh
python3 scripts/test-development-hooks
python3 scripts/test-push-gate
```

두 테스트는 임시 저장소만 변경한다. push gate 테스트의 canonical 결과는 공식 예제에서 만든 **합성 fixture**이며 실제 Hoplites 보안 검사나 독립 리뷰가 아니다.

## 가져온 정책과 Hoplites 조정

| 설정 | 적용 |
| --- | --- |
| FC/IS·mock 최소화·한 의도 commit | AGENTS.md 공통 지침 |
| 작성 후 포맷·커밋 전 검사 | Ruff 및 기존 Python/SQL/문서 검사로 대체 |
| sealed 보안·독립 리뷰 pre-push | Acropolis gate를 가져와 누적 PR 범위와 main 변경 검증 추가 |
| PR 템플릿 | SBOM 표준 필드·변경/제외 증적·미해결 확인 항목 추가 |
| main 서버 보호 | 관리자 적용, force push·삭제 금지, 대화 해결 요구 |
| submodule 검사 | 현재 Hoplites에 submodule이 없어 제외 |
| 구조 변경 디텍터 | 연구 단계이므로 필수 gate에서 제외 |
| Linear 계획·구현 | 설치된 공통 skill 사용; 프로젝트나 티켓은 자동 생성하지 않음 |

`CONFIDENTIAL`의 표준 BOM 보강·불확실성·증적 원칙과 Elixir/Rust/Python 언어 기준은 유지했다. release 승인, 배포, SAST 등 후보 도구의 전체 도입을 이번 설정 완료로 주장하지 않는다.

## 보장 범위

로컬 훅은 우회 가능하다. sealed 결과는 내용 일관성과 범위를 검사하며 모델 실행을 암호학적으로 증명하지 않는다. 독립 리뷰 JSON은 실제 리뷰어의 attestation이다. 외부 모델로 소스·요구사항·검증 근거를 전달하기 전 BOSS의 데이터 전달 승인을 확인한다.

현재 main 서버 보호에는 required CI status나 required approving review를 추가하지 않았다. 가져온 Acropolis 서버 설정도 이 항목들은 비어 있었다. 서버 보호와 로컬 보안·독립 리뷰 gate의 보장 범위를 구분한다. CI·서버에서 동일 검사를 강제하는 작업은 별도다.
