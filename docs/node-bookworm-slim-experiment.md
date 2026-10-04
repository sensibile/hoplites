# Node Bookworm slim 이미지 처리 실험


> 아래는 최초 실험 기록이다. 라이선스 적용 범위 표현은 [적용 범위 교정](license-scope-correction.md)으로 대체되었으며, 이전 AND 식은 현재 판단으로 사용하지 않는다.

2026-10-04, linux/arm64. 배포 담당자가 포함 소프트웨어와 보안·라이선스 후속 조치를 판단하기 위한 실험이다. 실제 애플리케이션 배포, 배포 승인, 라이선스 의무 이행은 이번 범위 밖이다.

## 실행 기반과 대상

- 시작 시 원격 main `7fe1b33349ab0875830b599948ca53d7246e08ad` 및 PR #1–4의 MERGED 상태를 실시간 확인했다.
- worktree: `/Users/tonton/Documents/workspace/hoplites/worktrees/node-image-validation`, branch: `feat/node-image-validation`.
- 구현 코드: `1a5d182`. 스캔은 이 커밋과 같은 정규화 구현의 작업 파일에서 실행했고 최종 번들에는 커밋 시점의 스크립트를 다시 보존한다.
- 입력: `node:24-bookworm-slim`. 선택한 버전의 관측이며 다른 Node 이미지/버전을 대표하지 않는다.
- index: `sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`.
- 플랫폼 manifest: `sha256:24b8bc17702002d2ed0c1da9ad66c3ee507cc279d0856726662ff2b6fc35c149`.
- Node 24.21.0, npm 11.19.0, Yarn 1.22.22, Corepack 0.36.0, Debian 12.15.
- Syft 1.54.0 / Trivy 0.75.0. 스캐너 index/child digest와 실행 명령은 각 실행의 `scanners.json`, `commands.json`에 있다. Trivy는 `vuln,license`를 사용했다.

기존 dpkg/copyright/파일 hash 경로를 재사용했다. 기존 Node 보강 어댑터는 없었으며 Debian Bookworm VEX는 미지원이다. 첫 실행은 업로드하지 않았고, 재실행은 위 플랫폼 digest로 고정했다. 대상 이미지의 앱/entrypoint는 실행하지 않았다.

공식 [고정 Dockerfile](https://github.com/nodejs/docker-node/blob/93a7bafc324a85ac1ee461604cff87cffacb6d7a/24/bookworm-slim/Dockerfile)은 Node tarball을 `/usr/local`, Yarn을 `/opt`에 설치한다. 해당 원문과 조회 SHA-256을 증적에 보존했다. Dockerfile의 서명 검증 절차가 실제 이 이미지 빌드에서 수행됐음을 독립 검증한 것은 아니다.

## 정규화·정보 보강

| 구분 | 첫 실행 | 보완 후 |
| --- | ---: | ---: |
| Syft 원본 | 3,370 | 3,370 |
| 정규화 | 642 | 236 |
| 정규화의 파일 | 406 | 0 |
| OS 패키지 | 88 | 88 |
| npm 생태계 패키지 | 146 | 146 |
| 직접 설치 Node 런타임 | 1 | 1 |
| OS 집합 | 1 | 1 |

Node 설치 헤더의 major/minor/patch와 scanner version을 대조했다. 배포된 `/usr/local/LICENSE`에서 프로젝트 MIT 조건을 확인해 표준 `licenses.expression`을 채웠다. 함께 배포된 제3자 고지 44개는 각각 해시 기반 LicenseRef와 원문 구간·이름·소스 위치로 연결했다. 표현은 MIT와 완전한 소스 고지 집합의 AND이며 **실제 바이너리에 모두 적용된다고 확정한 식은 아니다**. 소스의 빌드·테스트 항목도 포함되므로 바이너리 적용 범위와 각 고지의 canonical SPDX 대응은 미해결이다. Node 전체를 MIT 하나로 단순화하지 않았다.

`qrcode-terminal`의 `Apache 2.0` 자유 텍스트는 설치된 package.json과 LICENSE의 Apache 2.0 원문을 확인해 `license.id: Apache-2.0`으로 보강했다. Node 헤더와 npm package.json/라이선스 원문을 보존한다. npm 146개 설치 package.json 위치는 Syft 146개 위치와 모두 대응했고 이름·버전이 일치했다. Yarn/Corepack의 번들 내부 의존성을 모두 개별 식별한 결과는 아니다.

새 Node 어댑터는 검증한 Node 헤더/배포 경로와 설치 npm package.json에 연결하고, 중첩 패키지는 가장 가까운 확인된 패키지를 소유자로 사용한다. 파일 hash가 일치하는 경우만 패키지 뷰에서 제외한다. 원본 구성요소와 dependency remapping은 sidecar에 남긴다. 배포 디렉터리 연결은 upstream 빌드 bytes 동등성 증명이 아니다.

dpkg의 `/bin`·`/lib` 등 디렉터리 링크와 `/usr` 경로를 rootfs로 해석하도록 보완했다. 파일 자체의 심볼릭 링크가 대상 소프트웨어의 소유권을 만들지 않도록 구분한다. 예를 들어 libc-bin의 `/usr/bin/ld.so` 링크가 libc6의 실제 loader를 소유한다고 판단하지 않는다. 모호성/버전 충돌/hash 불일치는 임의 제외하지 않는다. 기존 SQL migration은 수정하지 않았으며 새 설치 형태를 Python 어댑터로 누적했다.

## Syft·Trivy 항목 비교

Trivy 235개는 OS 패키지 88개, npm 패키지 146개, OS 1개다. 생태계·PURL namespace/path·버전·아키텍처로 235개 모두 정규화 Syft와 대응한다. Syft에만 있는 1개는 `pkg:generic/node@24.21.0`이다. 이름만 비교하면 scoped npm 26개에서 잘못된 차이가 생긴다. Trivy의 `group`+`name`과 Syft의 전체 scoped name은 같은 PURL로 연결했다.

- 원본 Syft의 파일 3,134개가 원본 개수 차이를 설명한다. 각 제외 항목은 패키지/Node 소유 근거와 SHA-256으로 연결했다.
- Debian 88개 이름·버전·아키텍처는 설치 DB 및 두 BOM에서 일치한다.
- 66개 PURL 문자열 차이는 Syft의 `upstream` qualifier 추가 여부다. 항목별 원문 PURL은 비교 보고서에 보존한다.
- 원본 라이선스 JSON 차이는 81개, 보강본 차이는 89개다. 보강본은 Debian 88개 및 qrcode-terminal 1개다. Debian 차이는 배포 copyright의 소스 파일 식과 scanner의 패키지 라이선스 목록 사이의 표현/범위 차이로 기록하며 정확도 점수로 취급하지 않는다.
- Debian LicenseRef 162개는 162개 라이선스나 고유 소프트웨어의 수가 아니다. 공용 영역 선언·버전 없는 GPL/LGPL·예외·복합 선택·자유 서술 등 서로 다른 보존 레코드다. 각 label/문서 hash와 원문을 `stages/debian-package-view-evidence.json` 및 `sources/debian`에서 확인할 수 있다. 표준 SPDX 대응과 바이너리 범위 조사는 남아 있다.

## 취약점과 DT 검증

[DT 프로젝트](http://localhost:18081/projects/4912a5fb-840d-492f-9a0d-73a0b1c45f20)는 처리 COMPLETED, expected/actual 236/236, 식별·버전·PURL·단일 ID/표현 비교 오류 0건을 반환했다. 미해결 라이선스를 포함한 조사용 결과이며 납품 준비 완료 표시가 아니다. 중복 소프트웨어 식별의 강제 병합은 하지 않았다. 웹 UI는 로그인 화면까지만 확인했으므로 실제 구성요소 및 라이선스 표시 검증은 미완료다.

Trivy CycloneDX는 취약점 ID 126개와 affected 연결 255개다. ID에는 CVE 외 TEMP/DLA 식별도 포함된다. 같은 scanner/digest의 추가 JSON 검사는 Debian 235개·npm 20개의 구성요소별 발견 행을 제공했다. 해당 JSON의 생성 시각과 stderr에 기록된 DB 조건을 보존한다. DT 스냅샷에는 NVD 발견 8개가 있었고 npm의 같은 구성요소/CVE 8개가 모두 Trivy에서도 대응했다.

Trivy에만 있는 npm 12개는 로컬 DT의 해당 NVD record 조회에서 모두 404였다. GHSA 출처, 실제 설치 버전, 수정 버전 및 upstream advisory URL을 각 행에 보존했다. DT의 mirror 운영/데이터 동기화 완료는 확인하지 않았고 404를 취약점 부재로 해석하지 않는다.

Debian 235개 행은 공식 [Debian security tracker](https://security-tracker.debian.org/tracker/) JSON의 소스 패키지/Bookworm 데이터와 연결했다. 233개는 open, 1개는 resolved와 수정 버전, DLA 식별 1개는 해당 CVE 데이터에서 매칭되지 않았다. resolved 행의 libpcre2-8-0 설치 소스 버전 `10.42-1+deb12u1`은 vendor 수정 `10.42-1+deb12u2`보다 낮으므로 이 이미지의 해결 근거가 아니다. DT 스냅샷에 Debian 출처 발견이 없다는 사실은 확인했지만 서버 analyzer/feed 차이의 정확한 원인은 미확인이다. 바이너리별 exploitability는 판정하지 않았다.

Debian Bookworm에는 기존 Ubuntu VEX를 적용하지 않았으며 suppression 변경도 하지 않았다. Node binary runtime은 Trivy BOM에서 미검출돼 해당 경로의 CVE coverage가 부족하다. 분석 0건이나 일부 대응을 안전 판정으로 사용하지 않는다.

## 검증·증적과 남은 작업

64개 unittest, Ruff 포맷/정적 검사, Python 문법, SQL migration, 설정·로컬 문서 링크, 개발/문서 gate fixture 및 `git diff --check`를 통과했다. Node marker/패키지 identity 충돌, hash 불일치, 중첩 소유, scoped PURL 및 usr 디렉터리/파일 링크 구분을 회귀 검증했다.

저장된 Python slim 원본/rootfs를 시작 코드와 수정 코드에서 재처리했다. 378 → 116개이며 모든 비파일 소프트웨어 필드는 동일하다. 262개 파일을 추가 연결했다. 과거 Python 보강 어댑터 전체나 현재 Python DT를 재검증한 결과는 아니다. `python-regression.json`에 fixture 절대 경로와 비교 범위를 보존했다.

실행 산출물은 worktree의 Git 제외 `artifacts/` 아래에 있다.

- `node-review-001`: 첫 입력 tag/index, 원본/실패하지 않은 초기 결과. 첫 미해결을 보존했다.
- `node-local-002`: 어댑터 개발 중 로컬 재처리. loader 소유 모호성이 남았던 결과를 보존했다.
- `node-review-003`: 같은 digest의 수정본 Syft/Trivy와 업로드 전 비교.
- `node-dt-004`: 같은 digest의 등록 결과, DT 검증·발견 스냅샷, 항목 비교, 공식 advisory, 상세 Trivy와 최종 `submission-final/`.

| 단계 | 상태 및 근거 |
| --- | --- |
| 수집 | 완료: 고정 digest/platform의 Syft·Trivy·image/rootfs hash |
| 정규화·보강 | 부분 완료: 표준 Node/qrcode 필드와 소유 정규화, Debian 162개 LicenseRef 및 Node 고지 적용 범위 미해결 |
| 교차검증 | 완료: 패키지·필드·CVE 행별 차이와 확인/미확인 원인을 보존 |
| 제출 증적 | 완료: 최종 번들 원문·코드·비교·DT·미해결과 SHA-256 manifest 재검증 |
| DT API | 완료: 236/236 및 mismatch 0 |
| DT UI | 미완료: 로그인 필요, 화면의 구성요소/라이선스 표시 확인 필요 |
| CVE/VEX | 비교 완료, 판정 미완료: Debian VEX 미지원·Node binary coverage·DT feed 원인 조사 필요 |
| 목적 적합성 | 부분 완료: 파일을 별도 제품으로 관리하지 않으며 235개 패키지와 Node를 보존, 번들 내부 및 라이선스/보안 후속 작업 남음 |
| 실제 의무 이행/배포 승인 | 범위 밖 |

`unresolved-review.json`은 항목/버전 또는 LicenseRef, 조사 내용, 원문, 다음 확인과 담당 미지정 상태를 연결한다. 다음 작업은 Debian label/예외의 근거 있는 canonical 규칙, Node 44개 고지의 실제 빌드 포함/버전/라이선스, Yarn/Corepack 번들 내부, Debian advisory adapter와 DT feed, UI 표시 확인이다. 알려진 빈칸을 경고만 붙여 완료 처리하지 않는다. 현재 결과는 **부분 완료**다.

구현은 로컬 커밋으로 보존했다. 코드 push/PR/merge는 수행하지 않았으며 push 범위의 Codex Security·독립 리뷰도 아직 실행하지 않았다. 원격 전달 완료를 주장하지 않는다.
