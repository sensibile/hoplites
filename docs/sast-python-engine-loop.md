# SAST 엔진·에이전트 루프 첫 실험 (Python, 5개 CWE)

2026-10-30. SAST 방향 C 단계("엔진 결과를 LLM 에이전트가 트리아지·보완하는 계층")의 첫 실험이다. 엔진 기준선, 에이전트 탐색 증가분, 합성 룰 편입 후 재측정을 비공개 정답 세트 두 개로 측정했다. 결정은 [ADR-0013](adr/0013-sast-engine-agent-loop.md), 의도 초안은 [intent/2026-10-30-sast-agent-loop.md](../intent/2026-10-30-sast-agent-loop.md)에 있다.

**결론: 무료 엔진 3종(Bandit, opengrep + opengrep-rules, Joern + 기준 모델)을 합쳐도 독립 holdout 세트에서 취약 15건 중 9건만 탐지했다. CWE-22와 CWE-918은 0/3이었다. 같은 조건에서 에이전트 가설 15건은 모두 정답 사례 위치와 일치했고 수정본 오경보는 0건이었다. 단 confirmed 판정은 정답을 아는 운영자(이 세션)가 가설을 정답 사례에 대응시킨 뒤 그 사례의 기존 PoC를 재사용한 결과다. 가설에서 독립적으로 만든 PoC가 아니므로 confirmed 15/15는 "가설 위치가 정답 사례와 일치한다"는 판정 이상의 근거가 아니다. dev 세트의 confirmed 케이스로 합성한 opengrep 룰 11개는 dev gate를 모두 통과했다(dev 단독 19/19, 오경보 0). 그러나 holdout에서는 단독 6/15에 그쳤고 엔진 합집합에 더한 탐지 증가는 0건이었다. 합성 룰의 dev 수치는 과적합이다. 현재 근거로는 "CWE-78·89·502는 엔진 조합으로 대부분 탐지되지만 수정본 오경보가 많고, CWE-22·918은 엔진에 맡길 수 없다"까지만 말할 수 있다. 에이전트 수치는 정답 작성자와 같은 모델 계열이라 과대평가 가능성이 크며, 신뢰 판단에 쓰려면 다른 작성자의 세트로 다시 재야 한다.**

## 작업 계약

| 항목 | 내용 |
| --- | --- |
| 결과 사용자 | hoplites의 보안 검토자 |
| 내릴 판단 | 어떤 엔진·룰·에이전트 조합을 어떤 CWE에 신뢰할 수 있는가 |
| 필요한 출력 | CWE·흐름 유형별 탐지율·수정본 오경보·paired 정밀도 매트릭스(엔진 기준선, 에이전트 증가분, 합성 룰 편입 후), 엔진 간 불일치, 남은 구멍과 다음 실험 |
| 완료 근거 | 사전 고정한 정답 대비 측정값, 원본 SARIF·정규화 결과·실행 조건, PoC 실행 결과, gate 판정 기록, 회귀 테스트 |
| 완료로 보지 않는 것 | 스캔 성공, 0건 결과, 에이전트의 "비취약" 판정, dev 세트에서만 측정한 합성 룰 수치 |
| 적용 규칙 | REQ-001 1.2, REQ-007 1.1(의도 초안), MET-001(측정 정의), VER-003(상태 구분), DEV-003(작업 전용 worktree) |
| 외부 모델 | 사용하지 않았다. 정답 holdout 작성·에이전트 탐색은 이 세션과 같은 Claude(claude-opus-5-5) 서브에이전트로 수행했다. Codex 등으로는 아무것도 보내지 않았다 |

## 기존 opengrep-cwe 작업 조사

`/Users/tonton/Documents/workspace/hoplites-worktrees/opengrep-cwe`(`feat/opengrep-cwe`, 원격 미push, PR 없음, 작업 트리 깨끗함)는 읽기만 했다. 커밋 3개(`2f7122d`, `a5a1ba8`, `ae4d816`)로 TypeScript/JavaScript 대상 opengrep 자체 CWE 룰 19개, Juice Shop 개발 평가(13/13), NodeGoat 독립 평가(9종 중 2종)를 남겼다.

- 재사용: opengrep 1.32.0 선택과 cosign 서명 검증 절차(같은 SHA-256 `e161746…97e2f` 확인), 원본 SARIF/JSON 보존과 정규화 분리, 룰 메타데이터의 `hoplites-rule-version`, 스캔 전 정답 고정, "완화 매칭 기준은 사후에 만들면 공식 수치에 넣지 않는다"는 원칙, opengrep-rules(`f1d2b56`, LGPL-2.1 + Commons Clause, archived)를 저장소에 넣지 않고 비교 기준으로만 쓰는 방식.
- 이 실험이 그 작업에서 얻은 교훈을 확인했다: 개발 데이터에 맞춘 룰은 독립 대상에서 크게 떨어진다(이번 holdout에서도 같은 현상).
- 겹침·충돌: 그 브랜치의 ADR 번호 0011은 main의 `0011-codex-review-gate.md`와 충돌한다. 대상 언어가 달라 코드 충돌은 없다. 이어받지 않았고 수정하지 않았다. 병합하려면 ADR 번호 변경이 필요하다(후속).

## 정답 세트

공개 저장소(`sensibile/hoplites`는 PUBLIC)에 넣으면 이후 평가가 오염되므로 정답 세트는 원격이 없는 로컬 git 저장소 `/Users/tonton/Documents/workspace/hoplites-sast-seed`에 둔다. 이 문서에는 집계값과 해시만 남긴다. 실행 산출물 전체(원본 SARIF, 정규화 결과, 측정·gate JSON)는 그 저장소의 `runs/2026-10-30`에 보존했다(커밋 `2e1dfa5`).

| 세트 | 작성 | 앱 | 취약 | 수정본 쌍 | 쌍 없는 음성 | 흐름(취약 기준) | spec SHA-256 |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| dev | 이 세션(claude-opus-5-5) | 청구 관리 Flask 앱, 16파일 | 19 | 19 | 2 | intra 9, inter-function 3, inter-file 6, second-order 1 | `daf54bc7…c954d2` |
| holdout | 격리 서브에이전트(claude-opus-5-5). 룰 동결 전까지 이 세션은 코드를 보지 않았다 | 다른 도메인 Flask 앱, 24파일 | 15 | 15 | 3 | intra 5, inter-function 4, inter-file 5, second-order 1 | `46a5acbc…082874` |

- 각 사례는 sink를 줄 번호가 아니라 "함수 이름 + 호출 이름"으로 지정하고 `scripts/sast_truth.py`가 AST로 해석한다. 코드에 표식을 남기지 않아 에이전트가 정답을 읽을 수 없다. 한 함수에 같은 호출이 둘이면 해석이 실패한다.
- 모든 사례는 PoC unittest로 검증했다. 취약 사례는 공격 성공(행 추가 반환, 마커 파일 생성, 기준 디렉터리 밖 파일 읽기·쓰기, 127.0.0.1 수신 서버 요청 도달, 역직렬화 gadget 실행)을, 수정본은 같은 공격의 실패를 확인한다. dev 40/40, holdout 33/33 통과.
- holdout 작성자에게 dev의 sink API 목록을 주고 절반 이상을 다른 API·구조로 쓰게 했다(보고: 15건 중 12건).
- 공개 벤치마크(OWASP Benchmark, Juliet)는 이번에 실행하지 않았다(NOT_RUN). 엔진 기준선 참고용 후속 항목이다.

## 실행 조건

| 항목 | 값 |
| --- | --- |
| Bandit | 1.9.4(`bandit[sarif]`), 기본 플러그인 전체. 고정본 [requirements-sast.lock](../requirements-sast.lock)(`--exclude-newer 2026-10-16`, 해시 고정) |
| opengrep | 1.32.0 `opengrep_osx_arm64`, SHA-256 `e161746226bccef5b85c57611946fa21dc3b00a2dc2591343d6160af99397e2f`, cosign `verify-blob` 통과 |
| opengrep-rules | `f1d2b562b414783763fd02a6ed2736eaed622efa`의 `python/` 334개. 저장소 밖 캐시에서만 사용 |
| Joern | v4.0.656 `joern-cli-macos-arm64.zip`, 릴리스 SHA-512 일치. Temurin 21.0.13. 상위 래퍼는 macOS에서 GNU `greadlink`가 필요해 `bin/` 런처를 직접 호출한다 |
| Joern 모델 | [model-v0.json](../policies/sast/python/joern/model-v0.json), 첫 Joern 스캔 전에 커밋 `8951c81`로 사전 등록 |
| `joern-scan` 기본 쿼리 DB | NOT_RUN. 릴리스 번들의 쿼리 DB가 비어 있고 설치에 별도 다운로드(`--updatedb`)가 필요하다 |
| Python | 3.13.18. 이 버전의 `tarfile.extractall` 기본 필터는 `fully_trusted`라 D-22-3 계열이 실제로 취약하다 |
| 에이전트 | claude-opus-5-5 서브에이전트, 프롬프트 [explore-prompt-v1.md](../policies/sast/python/agent/explore-prompt-v1.md)(SHA-256 `e8bfcb2a…dffd1167`). 입력은 정답·PoC를 뺀 `app/` 사본뿐이다. 코드 실행 금지 |
| 합성 룰 동결 | 커밋 `e0b9cad`. holdout 측정과 holdout 코드 열람은 이 커밋 이후다 |

## 측정 정의 v1 (수집·계산·판정 분리)

- 수집: `sast_engines.py`가 엔진별 원본(SARIF·JSON·Joern flow)을 그대로 두고 명령·버전·바이너리/룰/대상 트리 해시를 `manifest.json`에 기록한다. `sast_normalize.py`가 SARIF에서 CWE(엔진이 보고한 태그만), 위치, 첫 흐름 경로를 뽑는다. 에이전트 가설은 `sast_agent.py`가 같은 형식으로 바꾼다.
- 계산: `sast_measure.py`. 단위는 사례다.
  - 탐지(strict): 같은 파일에서 결과 줄 범위가 sink 호출 범위와 겹치고 CWE가 허용 집합(89 / 78·77 / 22·23·36·73 / 918 / 502)에 들 때.
  - location-only: 같은 위치, CWE 무관(엔진의 CWE 표기 차이를 보기 위한 보조값).
  - 탐지율 = 탐지된 취약 사례 / 취약 사례. 수정본 오경보 = strict로 울린 수정본·음성 사례 / 수정본·음성 사례. paired 정밀도 = 탐지 / (탐지 + 오경보). 분모 0이면 UNKNOWN.
  - 정답 밖 결과: 어떤 사례 sink에도 겹치지 않는 결과. 범위 CWE 결과는 따로 센다. 판정 전까지 오탐도 정탐도 아니다(미판정).
  - 사후 보조 지표 `posthoc_function_scope`: sink와 같은 함수 안의 결과도 인정한다. Bandit B608이 `execute` 줄이 아니라 SQL 문자열 조립 줄에 보고하는 것을 첫 실행에서 보고 추가했다. 공식 수치와 gate에 쓰지 않는다.
- 판정: `sast_rule_gate.py`(아래 승격 gate). 측정 결과를 다시 계산하지 않는다.
- 한계: 사례 수가 작다(취약 19/15). 한 사례 차이가 dev 5%p, holdout 7%p다. 위치 매칭은 sink 중심이라 source에서 보고하는 엔진은 불리하다.

## 엔진 기준선

dev(취약 19, 수정본·음성 21). 셀은 탐지/취약 수, 괄호는 수정본 오경보 수.

| 구성 | CWE-22 | CWE-78 | CWE-89 | CWE-502 | CWE-918 | 탐지 | 오경보 | paired 정밀도 | 정답 밖(범위 CWE) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Bandit | 1/4 (0) | 3/3 (4) | 2/4 (1) | 3/4 (1) | 0/4 (0) | 9/19 | 6/21 | 0.60 | 7 |
| Joern + 모델 v0 | 3/4 (3) | 2/3 (2) | 2/4 (2) | 2/4 (0) | 3/4 (3) | 12/19 | 10/21 | 0.55 | 0 |
| opengrep + opengrep-rules | 1/4 (1) | 3/3 (1) | 4/4 (2) | 4/4 (1) | 3/4 (2) | 15/19 | 7/21 | 0.68 | 0 |
| 같은 구성 + `--taint-intrafile` | 1/4 (1) | 3/3 (1) | 4/4 (2) | 4/4 (1) | 3/4 (2) | 15/19 | 7/21 | 0.68 | 1 |
| 엔진 합집합 | 3/4 (3) | 3/3 (4) | 4/4 (3) | 4/4 (1) | 3/4 (3) | 17/19 | 14/21 | 0.55 | 8 |

holdout(취약 15, 수정본·음성 18).

| 구성 | CWE-22 | CWE-78 | CWE-89 | CWE-502 | CWE-918 | 탐지 | 오경보 | paired 정밀도 | 정답 밖(범위 CWE) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Bandit | 0/3 (0) | 3/3 (4) | 2/3 (0) | 2/3 (1) | 0/3 (0) | 7/15 | 5/18 | 0.58 | 7 |
| Joern + 모델 v0 | 0/3 (0) | 2/3 (3) | 1/3 (1) | 1/3 (0) | 0/3 (0) | 4/15 | 4/18 | 0.50 | 1 |
| opengrep + opengrep-rules(intrafile) | 0/3 (0) | 3/3 (2) | 2/3 (1) | 3/3 (1) | 0/3 (0) | 8/15 | 4/18 | 0.67 | 1 |
| 엔진 합집합 | 0/3 (0) | 3/3 (4) | 3/3 (2) | 3/3 (1) | 0/3 (0) | 9/15 | 7/18 | 0.56 | 9 |

흐름 유형별(엔진 합집합): dev inter-file 4/6, holdout inter-file 3/5. Joern은 두 세트 모두 inter-file 0이었다. pysrc2cpg + dataflowengineoss가 파일 경계를 넘는 Python 호출을 이번 설정에서 잇지 못했다(원인 미확인).

엔진 간 불일치(조사 대상): dev 24건(취약 12, 수정본 12), holdout 10건(취약 5, 수정본 5). 사례별 목록은 seed 저장소 `runs/2026-10-30/*/baseline/measure.json`의 `disagreements`에 있다. 유형은 다음과 같다.

- 같은 sink를 CWE만 다르게 보고: Bandit `yaml.load`는 CWE-20, `urlopen`(B310)은 CWE-22, opengrep-rules의 `urlopen` 계열은 CWE-939로 보고해 strict에서 빠진다.
- 패턴 룰과 taint 룰의 차이: opengrep-rules의 audit 룰(`avoid-pickle`, `subprocess-shell-true`, `sqlalchemy-execute-raw-query`)은 입력 경로와 무관하게 울려 inter-file 취약을 잡지만 수정본·상수 사용에도 울린다. 그래서 inter-file "탐지"의 상당수는 흐름 추적의 결과가 아니다.
- sanitizer 인식 차이: Joern v0와 opengrep-rules는 allowlist, `safe_join`, `shlex.quote`, 바인딩 파라미터를 대부분 인식하지 못해 수정본에 울린다. Bandit은 `subprocess` 인자 목록 호출에도 B603/B607로 울린다.
- `--taint-intrafile`은 두 세트 모두 탐지 차이를 만들지 않았다(정답 밖 결과만 0→1).

## 에이전트 탐색 증가분

가설은 모두 `inferred`로 기록하고, 가설의 진입점으로 공격을 보내 성공한 PoC만 `confirmed`로 올렸다. 이번에는 dev 19건, holdout 15건 모두 가설의 진입점·sink가 정답 사례와 일치해, 정답을 아는 운영자(이 세션, claude-opus-5-5)가 가설을 정답 사례에 대응시키고 그 사례의 PoC를 그대로 실행했다(seed `*/poc/agent-confirmations.json`, `test_agent.py`). 이 대응은 MET-001의 판정 단계이며 독립 증거가 아니다. 정답과 일치하지 않는 가설이 없었으므로, 가설만 보고 PoC를 새로 쓰는 경로는 이번에 시험되지 않았다. "비취약" 판정은 `coverage.json`에 coverage 기록으로만 남겼다(dev 25건, holdout 28건).

| 세트 | 가설(inferred) | confirmed | 수정본 오경보 | 엔진 합집합 | 엔진 + 에이전트 | 에이전트만 잡은 사례 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| dev | 19 | 19 | 0 | 17/19 | 19/19 | D-22-2(파일 간 `send_file`), D-918-2(파일 간 `urlopen`) |
| holdout | 15 | 15 | 0 | 9/15 | 15/15 | CWE-22 3건, CWE-918 3건 전부 |

- 엔진만 울린 사례는 모두 수정본·음성이었다(dev 14, holdout 7). 엔진이 잡고 에이전트가 놓친 취약 사례는 없다.
- 해석 한계: confirmed는 정답 PoC 재사용이다(위). 정답 작성자(dev는 이 세션, holdout은 서브에이전트)와 탐색 에이전트가 같은 모델이다. 앱 규모가 작고(16·24파일) 취약 패턴이 교과서적이다. 실제 코드에서의 에이전트 탐지율·정밀도 근거로 쓰지 않는다.
- dev 에이전트는 coverage 기록에서 D-918-1F(정확한 호스트 allowlist 뒤 `requests.get`)가 리다이렉트를 따라가는 잔여 위험을 적었다. 정답은 이 경로를 "수정본"으로 두었다. 허용 호스트가 신뢰된다는 가정에 기댄 판정이므로 미해결로 남긴다.

## 룰 합성과 승격 gate

dev의 confirmed 19건에서 opengrep taint 룰을 합성했다([policies/sast/python/opengrep](../policies/sast/python/opengrep)). 합성자는 이 세션(claude-opus-5-5), 절차 ID는 `hoplites-sast-rule-synthesis/1`이다. 각 룰 메타데이터에 출처 가설, 탐색 프롬프트, 모델, `hoplites-regression-cases`를 기록하고, 탐지·비탐지 예제를 `opengrep test`로 검증한다. 예제는 일부러 취약한 Python이라 `*.pyfixture`로 저장한다. `.py`로 두면 저장소 CodeQL이 앱 코드로 보고 경고 22건(critical·high)을 내서 main ruleset이 머지를 막았다. `scripts/sast_rule_test.py`가 임시 디렉터리에 `.py`로 복사해 `opengrep test`를 실행한다. 확장자만 바꾸면 `opengrep test`가 예제를 건너뛰고 통과로 보고하므로, 이 실행기는 "All tests passed"가 없으면 실패로 처리한다. 그 22건의 정·오탐은 분석하지 않았고 측정에도 넣지 않았다. CodeQL 비교는 라이선스 확인 뒤 별도로 한다.

- `request/`(6룰, `--taint-intrafile`로 실행): Flask `request.*` source → SQL 텍스트(바인딩 없는 `execute`), 셸 문자열, 파일 경로(`open`, `send_file`), 외부 요청 URL, 역직렬화 sink. 별도 패턴 룰로 filter 없는 tar 추출.
- `helper-param/`(5룰, intrafile 없이 실행): 라우트가 아닌 함수의 매개변수 → 같은 함수 안의 sink. 파일 간 흐름의 마지막 구간을 잡는다.
- 처음에는 두 source를 한 룰에 넣었다. `--taint-intrafile`과 결합하자 헬퍼 반환값 전체가 오염돼 D-918-4F 오경보와 정답 밖 CWE-22 2건이 생겼고 gate 3번에 걸렸다. 그래서 두 디렉터리로 나눴다.

gate(`sast_rule_gate.py`, v1)는 dev에서 세 가지를 모두 요구한다: (1) 룰이 주장하는 confirmed 사례를 탐지한다, (2) 그 사례의 수정본과 다른 수정본에 울리지 않는다, (3) 기준 구성(opengrep + opengrep-rules intrafile)에 더했을 때 paired 정밀도가 떨어지지 않고, 수정본 오경보가 늘지 않으며, 정답 밖 범위 CWE 결과가 새로 생기지 않는다.

| 대상 | 결과 |
| --- | --- |
| opengrep 합성 룰 11개 | 11/11 통과. 기준 15/19·오경보 7·정밀도 0.68 → 편입 후 19/19·오경보 7·정밀도 0.73, 새 정답 밖 결과 0 |
| Joern 모델 v1(sanitizer 4개 추가) | 불합격. 7개 sink 룰 중 2개만 통과했다. 4개는 수정본에 울렸고 `cwe-918.urlopen`은 회귀 사례가 없다. v0를 Joern 기준으로 유지한다([model-v1.json](../policies/sast/python/joern/model-v1.json)에 판정 기록) |

## 편입 후 재측정 (엔진만)

| 세트 | 구성 | 탐지 | 수정본 오경보 | paired 정밀도 |
| --- | --- | ---: | ---: | ---: |
| dev | 합성 룰 단독 | 19/19 | 0/21 | 1.00 |
| dev | opengrep-rules + 합성 룰 | 19/19 | 7/21 | 0.73 |
| dev | 엔진 합집합 + 합성 룰 | 19/19 | 14/21 | 0.58 |
| holdout | 합성 룰 단독 | 6/15 (78 3/3, 89 1/3, 502 2/3, 22 0/3, 918 0/3) | 0/18 | 1.00 |
| holdout | opengrep-rules + 합성 룰 | 8/15 | 4/18 | 0.67 |
| holdout | 엔진 합집합 + 합성 룰 | 9/15 | 7/18 | 0.56 |

holdout에서 합성 룰이 엔진 합집합에 더한 탐지는 0건이다. 합성 룰의 가치는 이번 근거로는 "오경보 없이 울리는 결과"(holdout 정밀도 1.00, 6건)에 한정된다. 기존 엔진의 오경보를 줄이지는 않는다(합집합이므로).

## 남은 구멍

| 구멍 | 근거 | 다음 확인 방법 |
| --- | --- | --- |
| CWE-22를 엔진이 못 잡음 | holdout 0/3(모든 엔진·합성 룰). sink가 `Path.read_bytes`/`write_bytes`, 수동 zip 멤버 쓰기, `shutil.copyfile`, Flask `<path:>` 경로 인자 | sink 카탈로그에 pathlib·shutil·zip 수동 추출 추가, 경로 인자 source 지원 후 새 holdout으로 측정 |
| CWE-918을 엔진이 못 잡음 | holdout 0/3. sink가 `http.client` 연결 객체, `requests.Session().request`, `urllib.request.build_opener().open` | 세션·opener·저수준 클라이언트 sink 추가, 클래스 속성으로 보관된 세션 추적 확인 |
| Flask 경로 인자(view args) source 없음 | 합성 룰·Joern 모델 모두 미지원. holdout에 경로 인자 사례 다수 | `isalnum` 같은 검증을 sanitizer로 인식할 방법과 함께 설계(검증 없이 넣으면 dev의 `_snapshot_path` 같은 오경보가 생긴다) |
| 파일 간 흐름 | Joern 0/6·0/5, opengrep은 패턴 룰로만 일부 탐지. opengrep v2 interfile 프리릴리스는 이름상 Python 제외(`nopython`) | Joern 파일 간 호출 해석 원인 조사(import 해석 옵션), CodeQL 라이선스 확인 후 비교 |
| 수정본 오경보 | 엔진 합집합 오경보 dev 14/21, holdout 7/18. Bandit·audit 룰이 sanitizer와 무관하게 울림 | 에이전트 트리아지로 오경보를 coverage로 분류하는 단계 측정(이번에 하지 않음) |
| CWE 표기 불일치 | Bandit `yaml.load`=CWE-20, B310=CWE-22, opengrep-rules `urlopen`=CWE-939 | 엔진 룰별 CWE 재매핑 표를 사전 정의하고 strict 매칭에 적용할지 결정 |
| 에이전트 평가 독립성 | 작성자·탐색자 같은 모델, 작은 앱, confirmed가 정답 PoC 재사용 | 다른 모델 계열·사람이 작성한 비공개 세트, 실제 납품 코드 표본. PoC는 정답을 모르는 실행자가 가설만 보고 작성 |
| dev D-918-1F 잔여 위험 | 리다이렉트 추종(에이전트 coverage 기록) | 정답 정의에 리다이렉트 정책 포함 여부 결정 |
| 공개 벤치마크 기준선 | NOT_RUN | OWASP Benchmark Python 등은 엔진 기준선 참고로만 실행 |
| 정답 밖 결과 판정 | dev 8건, holdout 9건(엔진 합집합 범위 CWE) 미판정. 대부분 Bandit import 경고(B403·B404)와 SQL 조립 줄 | 판정 기록 파일을 두고 사람 확인 |

## 다음 실험 제안

1. 새 holdout(다른 작성자, 가능하면 사람 또는 다른 모델 계열)을 먼저 만들고, 이번 holdout의 confirmed 15건으로 sink 카탈로그·경로 인자 source를 합성한 뒤 새 holdout으로 일반화를 잰다. 이번 holdout은 그 순간 개발용이 된다.
2. 에이전트 트리아지 단계: 엔진 결과(특히 수정본 오경보)를 에이전트가 판정하게 하고, 판정 정확도와 "비취약" 판정의 오류율을 PoC로 잰다. 에이전트 부정 판정은 coverage로만 남긴다.
3. Joern 파일 간 흐름 원인 조사 후 재측정. CodeQL은 비공개 상용 코드 라이선스 조건을 먼저 확인한다.
4. 엔진 CWE 재매핑 표를 다음 측정 전에 고정한다.

## 단계별 상태

| 단계 | 상태 | 근거·이유 |
| --- | --- | --- |
| opengrep-cwe 조사 | PASS | 위 절 |
| 정답 세트(dev·holdout, 양성·음성 쌍, 파일 간·함수 간 포함) | PASS | PoC 40/40, 33/33 |
| 엔진 SARIF 보존·정규화 | PASS | seed `runs/2026-10-30`, 각 `manifest.json`. 엔진 보고 오류·SARIF 알림은 모든 실행에서 0건(사후 재확인, 이후 실행은 `manifest.json`의 `scan_problems`에 기록) |
| 엔진 기준선 매트릭스·불일치 | PASS | 위 표. 불일치 사례별 원인 조사는 유형 분류까지만 함 |
| `joern-scan` 기본 쿼리 | NOT_RUN | 쿼리 DB 별도 다운로드 필요 |
| 공개 벤치마크 기준선 | NOT_RUN | 범위상 후속 |
| 에이전트 inferred·confirmed·증가분 | PASS(측정) / 해석 제한 | confirmed는 운영자 대응 후 정답 PoC 재사용, 같은 모델 계열 |
| 룰 합성·gate·회귀 케이스 | PASS(opengrep) / FAIL(Joern v1, 편입 안 함) | gate JSON |
| 편입 후 재측정 | PASS | holdout 증가 0 |
| 정답 밖 결과 판정 | UNKNOWN | 미판정 |
| 의도 기록 | open 초안 | BOSS 확인 전 |

## 재현

도구는 저장소 밖 `~/.cache/hoplites-sast`에 둔다(opengrep, Joern, opengrep-rules, venv). 정답 세트는 `HOPLITES_SAST_SEED=/Users/tonton/Documents/workspace/hoplites-sast-seed`.

```sh
uv venv ~/.cache/hoplites-sast/venv -p 3.13
VIRTUAL_ENV=~/.cache/hoplites-sast/venv uv pip sync --require-hashes requirements-sast.lock
scripts/sast_baseline.sh "$HOPLITES_SAST_SEED/dev" artifacts/sast-python/dev/baseline
python3 scripts/sast_measure.py --truth artifacts/sast-python/dev/baseline/truth.json \
  --findings artifacts/sast-python/dev/baseline/*/findings.json \
  --union "engines=bandit,opengrep-rules-intrafile,joern-model" --output artifacts/sast-python/dev/baseline/measure.json
scripts/sast_synth_measure.sh "$HOPLITES_SAST_SEED/dev" artifacts/sast-python/dev synth-1
python3 scripts/sast_rule_test.py policies/sast/python/opengrep/request --opengrep ~/.cache/hoplites-sast/opengrep/opengrep_osx_arm64 --taint-intrafile
python3 scripts/sast_rule_test.py policies/sast/python/opengrep/helper-param --opengrep ~/.cache/hoplites-sast/opengrep/opengrep_osx_arm64
```

에이전트 단계는 프롬프트 v1의 `{INPUT_DIR}`·`{OUTPUT_FILE}`만 치환해 실행하고, `scripts/sast_poc_run.py`와 `scripts/sast_agent.py`로 confirmed 여부를 기록한다. gate는 `scripts/sast_rule_gate.py`를 PyYAML이 있는 SAST venv로 실행한다. 출력 파일·디렉터리는 덮어쓰지 않는다(모든 스크립트가 기존 출력이 있으면 실패한다).
