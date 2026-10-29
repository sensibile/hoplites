# 비배포판 CVE의 코드 포함 판정 VEX

2026-10-30. SAST 방향의 첫 단계 A-0이다. 결과는 릴리스 승인자와 보안 검토자가 사용한다. 그들이 내릴 판단은 "이 이미지의 비배포판 CVE 중 무엇이 실제 납품물에 포함된 취약 코드인가"다. 결정과 근거 등급은 [ADR 0012](adr/0012-code-presence-vex.md)에 있다. 이 문서는 집계, 실제 반영, 미해결을 기록한다.

## 1. 비배포판 CVE 집계

관측 시점은 2026-10-30이다. DT API로 suppressed를 포함한 전체 finding을 읽었다. 그리고 각 이미지의 `image-save.tar`(DT 프로젝트와 같은 digest)를 Trivy 0.75.0(`aquasec/trivy@sha256:af6acf9a…`, `--scanners vuln`)으로 다시 검사했다. 표는 `(PURL, 취약점 ID)` 행 단위다.

| 이미지 (DT 프로젝트) | DT 배포판 | DT 비배포판 | Trivy 언어 패키지 | 합집합 | Trivy에만 |
| --- | ---: | ---: | ---: | ---: | ---: |
| node bookworm-slim | 0 | 13 | 26 | 26 | 13 |
| python 3.13-slim | 6 | 0 | 9 | 9 | 9 |
| eclipse-temurin 21 noble | 39 | 0 | 0 | 0 | 0 |
| elixir alpine | 0 | 0 | 0 | 0 | 0 |
| ubuntu noble | 0 | 0 | 0 | 0 | 0 |

| 이미지 | 생태계 | 구성요소 | DT | Trivy | 집계 시점 DT 상태 |
| --- | --- | --- | ---: | ---: | --- |
| node | npm | undici 6.27.0 | 11 | 11 | 분석 없음, 미suppress |
| node | npm | brace-expansion 5.0.7 | 2 | 5 | 분석 없음, 미suppress |
| node | npm | ip-address 10.2.0 | 0 | 8 | DT finding 없음 |
| node | npm | tar 7.5.19 | 0 | 1 | DT finding 없음 |
| node | npm | postcss-selector-parser 7.1.4 | 0 | 1 | DT finding 없음 |
| python | pypi | urllib3 2.7.0, setuptools 70.3.0, msgpack 1.1.2, certifi 2026.6.17 | 0 | 9 | DT finding 없음 |

관측 사항은 다음과 같다.

- Node의 비배포판 항목은 모두 npm CLI가 함께 배포하는 패키지다(`/usr/local/lib/node_modules/npm/node_modules/`). Python 항목은 pip 계열 pypi 패키지다.
- 직접 설치 런타임(node 24.21.0, CPython 3.13.16, OpenJDK, Erlang/OTP)의 CVE는 두 도구 모두 0건이다. Trivy는 런타임 바이너리를 언어 패키지로 검사하지 않는다. DT는 CPE가 있어도 finding이 없다. 이 0건은 탐지 공백이며 안전 판정이 아니다.
- Python의 pip 계열 4개는 SBOM에 CPE와 위치 속성이 없어 DT가 매칭하지 못한 것으로 보인다(추정). Node의 Trivy-only 항목은 CPE가 있는데도 DT finding이 없다. 원인은 DT feed와 analyzer 구성이며 미확인이다. 이전 실험의 DT NVD 조회 404 기록과 일치한다.
- 따라서 DT 기준으로 이번 판정을 반영할 수 있는 항목은 13건뿐이다. 비배포판의 큰 공백은 판정 수단이 아니라 탐지 범위에 있다.

원본은 worktree의 `artifacts/code-presence-aggregate-001/`에 있다(`dt-findings-20261030.json`, `trivy-20261030/*.json`, `aggregate.json`).

## 2. 실제 반영: Node 이미지

| 항목 | 값 |
| --- | --- |
| 이미지 | `docker.io/library/node@sha256:24b8bc17702002d2ed0c1da9ad66c3ee507cc279d0856726662ff2b6fc35c149`, linux/arm64 |
| DT 프로젝트 | `4912a5fb-840d-492f-9a0d-73a0b1c45f20` |
| SBOM / rootfs | `license-scope-fixed-node-002`의 `normalized.cdx.json`(SHA-256 `aa099db7…`)과 `rootfs.tar`(`327ccc60…`, summary의 고정 hash와 대조) |
| 규칙 | `migrations/0011_code_presence_rules.sql`: CVE 13건, 대상 19개 |
| 근거 snapshot | `artifacts/code-presence-sources-20261030/`: GHSA 13, 수정 커밋 13, undici v6.27.0 파일 13, 태그·커밋 순서 11 |
| 결과 | `artifacts/node-code-presence-001/run/`: `code-presence.vex.json`, `decisions.json`, `dt-apply/`, `dt-requery.json` |

판정 근거는 다음과 같다.

- undici 11건: 수정 커밋마다 v6.x 브랜치에 포함된 커밋을 골랐다. GitHub compare 결과는 `v6.27.0...커밋` = ahead, behind 0이다. 즉 수정은 6.27.0 릴리스보다 뒤에 있다. 그 커밋이 고친 모듈 13개 모두 납품물의 바이트가 `v6.27.0` 태그의 파일과 동일했다. 따라서 납품된 코드는 수정 전 코드다. 등급은 confirmed-present다.
- brace-expansion 2건: 수정은 `src/index.ts`를 고쳤고, 납품물에는 그 컴파일 산출물(`dist/commonjs/index.js`, `dist/esm/index.js`)만 있다. 이 연결은 `package.json` exports가 require/import를 두 산출물로 매핑한다는 점을 근거로 한다. 두 파일 모두 취약 함수 `function expand_(`가 있다. 수정이 추가한 식별자(CVE-2026-14257의 `EXPANSION_MAX_LENGTH`, CVE-2026-69152의 `length + c.length > maxLength`)는 없다. 등급은 confirmed-present다.
- 결과적으로 13건 모두 `in_triage`이며 `code_not_present`는 0건이다. v1은 부재를 확정하는 근거가 없어 `code_not_present`를 내보내지 않는다(ADR 0012). "취약 코드가 납품물에 있다"는 사실은 확인됐다. 사용 경로의 도달성은 베이스 이미지라서 평가하지 않았다.

### DT 검증

- `apply_dtrack_vex.py`: VEX 업로드 이벤트 COMPLETED, 13건의 state·detail·suppression이 분석 API에서 일치했다.
- 별도 재조회(`dt-requery.json`): finding API의 suppressed 포함 13건과 active 13건이 모두 `IN_TRIAGE`, `isSuppressed=false`, justification `NOT_SET`이다. 분석 API의 detail이 VEX와 일치하고 감사 이력 주체는 `CycloneDX VEX`다. 원래 finding과 severity는 유지된다.
- metrics refresh 후 vulnerabilities 13, suppressed 0이다. `findingsAudited=0`은 DT가 IN_TRIAGE를 미감사로 집계한 결과로 보인다(추정, DT 집계 규칙은 미확인).
- UI는 확인하지 않았다. 검증은 API로만 했다.
- `not_affected`+`code_not_present`는 v1에서 생성되지 않는다. DT 적용기의 justification 검증 코드만 추가했다.

## 3. 미해결과 다음 확인

| 항목 | 현재 상태 | 조사한 내용 | 다음 확인 방법 |
| --- | --- | --- | --- |
| undici 11건, brace-expansion 2건 | confirmed-present, in_triage | 위 판정 근거 | npm CLI 상위 버전으로 교체할지 검토한다(배포 판단). 실제 앱 이미지라면 진입점 기준 도달성 평가를 별도로 수행한다(A 본편). |
| Node Trivy-only 13건(ip-address 8, brace-expansion 3, tar 1, postcss-selector-parser 1) | DT finding 없음, 미판정 | Trivy GHSA 출처, 설치 경로 | DT의 GHSA/OSV analyzer 구성을 확인한다. finding이 생기면 같은 규칙 방식으로 추가한다. |
| Python pip 계열 9건 | DT finding 없음, 미판정 | SBOM에 CPE·위치 없음 | pip vendored 패키지의 위치·식별을 정규화에 보강한다. 이어서 pypi 어댑터(파일 경로 기준 패키지 root)를 추가한다. |
| 직접 설치 런타임 CVE(node, CPython, OpenJDK, OTP) | 두 도구 0건, 탐지 공백 | 탐지 결과 없음 | 런타임 버전별 vendor advisory를 수집한다. finding 출처를 확보한 뒤 ELF 심볼·빌드 설정 규칙(`elf-symbol`)을 적용한다. |
| 빌드 설정 근거(config.gypi 등) | 등급만 정의, 미구현 | ADR 0012 | 필요한 CVE가 생기면 inferred 전용으로 구현한다. |
| 코드 부재 확정(`code_not_present`) | v1 미구현, 부재는 inferred-absent까지만 | 독립 리뷰 2회 지적: 리터럴 표지·파일 목록만으로는 번들·minify된 코드를 배제하지 못함 | 파일별 해시가 있는 수정 전 릴리스 목록과 수정 파일 매핑을 갖춘 근거 종류를 설계한다. 이를 BOSS가 확인한 뒤 구현한다. |

## 재사용 명령

```sh
python3 scripts/build_code_presence_vex.py \
  --export <DT VEX export> --sbom <업로드한 정규화 SBOM> \
  --rootfs <rootfs.tar> --rootfs-sha256 <실행 기록의 rootfs hash> \
  --sources <근거 snapshot 디렉터리> \
  --output <새 경로>/code-presence.vex.json --evidence <새 경로>/decisions.json
python3 scripts/apply_dtrack_vex.py --vex <새 경로>/code-presence.vex.json \
  --project <DT 프로젝트 UUID> --output-dir <새 경로>/dt-apply --refresh-metrics
```

배포판 VEX와 함께 실행할 때는 `run_project_vex.py`에 `--code-presence-sources`와 `--rootfs-sha256`을 추가한다. 두 결과가 병합된 `project.vex.json`이 반영된다. 새 CVE는 advisory·수정 커밋·릴리스 파일 snapshot을 받아 새 migration으로 규칙을 추가한다. 이미 적용한 migration은 고치지 않는다.
