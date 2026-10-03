# Python slim 보완 결과

이 문서는 첫 보완 실행의 기록이다. 추가 조사·최신 DT 재검증 결과는 [후속 보완 보고서](python-slim-followup.md)에 있다.

2026-10-03, linux/arm64. 이전 DT 등록 결과의 보강·교차검증·재검증 작업이다. 정보 보강 및 DT 필드 검증은 수행했으며, 모든 라이선스의 canonical 식별과 CVE 적용성·실제 라이선스 의무 이행은 완료되지 않았다.

## 실행 기준과 재현

최신 원격 main `c03f2545bf860c719ecc5a757eb2a3c1458c0e1e`, 기존 PR #1 MERGED를 직접 확인했다. 전용 worktree `/Users/tonton/Documents/workspace/hoplites/worktrees/python-slim-completion`, branch `codex/python-slim-completion`에서 작업했다. 커밋·push·merge는 하지 않았다. 작업 당시 별도 정책 worktree의 새 이미지 처리 지침도 읽고 적용했다.

고정 이미지: `docker.io/library/python@sha256:110e8d1de526341568b8fcdb1773b0d47ad63309df21980c6028803226a2dab0`. 이전 실험과 같은 플랫폼 manifest이며 tag를 재해석해 다른 이미지로 바꾸지 않았다. Python 3.13.16, pip 26.2.1. Syft 1.54.0 및 Trivy 0.75.0의 고정 index/child digest와 실제 이미지 ID는 `scanners.json`에 있다.

```sh
python3 scripts/image_pipeline.py \
  docker.io/library/python@sha256:110e8d1de526341568b8fcdb1773b0d47ad63309df21980c6028803226a2dab0 \
  --platform linux/arm64 --trivy --output-dir artifacts/python-slim-review-new
python3 scripts/compare_image_boms.py \
  --original artifacts/python-slim-review-new/original.cdx.json \
  --normalized artifacts/python-slim-review-new/normalized.cdx.json \
  --trivy artifacts/python-slim-review-new/trivy.cdx.json \
  --output artifacts/python-slim-review-new/cross-validation.json
```

DT 업로드는 로컬 결과 검토 후 기존 `upload` 경로로 별도 수행했다. 미해결은 조사용 결과로 표시했다. 기존 실패와 중간 결과는 덮어쓰지 않았다.

## 보강과 파일 소유권

새 migration `0007_python_shipped_licenses.sql`은 이미지에 실제 배포된 라이선스 문서 22개의 정확한 SHA-256, 버전, 경로, 검토한 표현을 고정한다. [Python-2.0.1 SPDX 정의](https://spdx.org/licenses/Python-2.0.1.html)와 배포 원문을 대조했다. Python 표준 `licenses.expression`에 `Python-2.0.1 AND BSD-0-Clause`를 넣었다. BSD 항목은 배포 공지에 포함된 문서 코드 조건의 보수적 집계이며, 모든 런타임 파일에 두 조건이 동시에 적용된다고 확정한 것이 아니다. 정확한 버전은 설치 `patchlevel.h`로 확인한다.

pip의 표준 MIT 조건과 vendored 의존성 18개의 버전·PURL·라이선스를 실제 BOM에 넣었다. 버전은 설치된 `vendor.txt`의 선언이며 pip 수정본과 upstream 배포의 바이트 동등성을 증명하지 않는다. `packaging`의 배포 선택 관계는 `Apache-2.0 OR BSD-2-Clause`로 보존했다. pip → vendored 구성요소 의존 관계를 추가했다.

`RECORD`의 SHA-256·크기를 실제 rootfs 파일과 대조하고 원본 파일 구성요소의 SHA-256도 확인한 경우만 소유 구성요소에 연결한다. 원본 레코드·해시·위치·변경과 의존 관계 재연결을 sidecar에 남긴다. Python은 식별된 인터프리터 위치·버전 표식·라이선스 파일만 직접 연결하며, 임의의 stdlib 경로 전체를 소유한다고 가정하지 않는다.

Debian usrmerge에서는 실제 부모 디렉터리 symlink를 해석해 `/bin`과 `/usr/bin` 등 소유 경로를 대조한다. 패키지가 가진 leaf symlink의 대상 bytes를 그 패키지 소유로 옮기지 않는다. hash 불일치와 소유권 모호성은 제외 근거로 사용하지 않는다.

Simple Launcher 6개는 서로 다른 Windows 실행 파일이다. `RECORD`로 실제 파일·해시를 확인하고 `file_name`과 `sha256` qualifier를 가진 별도 generic PURL 및 표준 SHA-256을 부여했다. bom-ref·원래 이름·PE 버전·위치는 유지한다. 같은 이름·버전이라는 이유로 합치거나 삭제하지 않는다. 각 파일의 BSD-2-Clause는 [distlib 0.4.2 launcher 소스](https://github.com/pypa/distlib/blob/0.4.2/PC/launcher.c)의 고정 해시에 근거한 추정으로 기록한다. 실행 파일과 해당 소스의 완전한 동등성은 미검증이다.

## 수집과 교차검증

| 항목 | Syft 원본 | 보강본 | Trivy |
| --- | ---: | ---: | ---: |
| Debian 패키지 | 97 | 97 | 97 |
| pip·vendored 의존성 | 1 | 19 | 19 |
| Python 런타임 | 1 | 1 | 0 |
| Launcher | 6 | 6 | 0 |
| OS | 1 | 1 | 1 |
| 파일 | 3,206 | 1 | 0 |
| 총합 | 3,312 | 125 | 117 |

패키지 생태계·이름·버전·아키텍처를 대조했다. 보강본과 Trivy의 공통 식별 항목 117개는 전부 일치하고 Trivy에만 남은 항목은 없다. Python과 Launcher 6개는 Syft만 식별했다. 파일 개수 차이는 근거 있는 제외 sidecar로 추적한다. 남은 파일은 checksum을 갖지 않는 pip RECORD 자체로, 설치 인벤토리로 유지했다.

원본/Trivy 공통 99개 중 88개, 보강본/Trivy 공통 117개 중 116개에서 라이선스 JSON 표현이 다르다. 이는 정확도 점수가 아니다. Debian copyright의 source 문단 집계와 scanner 개별 목록, 라이선스 관계·표현 차이가 포함된다. `cross-validation.json`은 항목별 양쪽 전체 레코드와 PURL/라이선스 차이를 보존한다. 소스 copyright 집계의 바이너리 적용성은 추정이며 Trivy 목록에서 AND/OR를 임의 복원하지 않는다.

## DT 재검증

기존 로컬 프로젝트 `hoplites-python-slim-arm64`, UUID `d1ca28b2-54ca-432b-a953-67f5d46c62fe`에 같은 digest 버전으로 보강본을 반영했다. 이벤트 COMPLETED와 전체 pagination 조회에서 expected/actual 125/125, 식별·버전·표준 라이선스 필드 mismatch 0개를 확인했다. 표준 SHA-256도 재조회·대조했다. Launcher 6개를 각각 보존하여 기존 378/373 개수 실패 원인을 해결했다.

업로드 대상이 사용자 로컬 DT인지 불명확하다는 자동 승인 검토 거절이 한 차례 있었다. 읽기 전용 Docker 조회로 저장소 Compose와 일치하는 `hoplites-dtrack-apiserver-1`, `127.0.0.1:18080`을 확인한 후 재검토가 승인되어 수행했다. UI는 로그인 화면으로 이동하여 표시 자체는 미확인이다. API 검증을 UI 검증으로 주장하지 않는다.

## CVE 조사와 남은 상태

Trivy 원본은 CVE/advisory 128개, 영향 구성요소 조합 267건을 보고했다. Debian 공식 security tracker의 source package와 정확한 설치 source version을 대조했고, 261건은 bookworm open 상태로 확인했다. 공개 advisory 전체 응답·조회 hash와 항목별 원문을 보존했다. 0건을 안전 판정으로 해석하지 않는다.

Python 생태계 6건은 GitHub 공식 advisory 응답과 실제 설치 코드 파일을 대조했다. setuptools 70.3.0은 pkg_resources subset이며 두 advisory가 지목하는 setuptools 모듈은 설치되어 있지 않다. msgpack은 pure-Python fallback이 설치되어 있고 `_cmsgpack` 확장을 발견하지 못했다. 이 세 건은 전체 upstream 패키지의 버전 범위를 subset에 그대로 적용할 수 없어 적용성 조사 상태로 남긴다. urllib3 2.7.0 관련 세 건은 advisory의 영향 버전 범위에 들고 관련 파일도 설치되어 있어 finding을 유지한다. vendoring patch·실제 호출 조건 검증은 남았다.

DT findings 조회는 현재 0건이다. scanner/DB/분석 설정·동기화로 인한 차이의 원인은 확정하지 못했다. Trivy는 vuln/license를 명시적으로 실행했고, Syft BOM 생성은 CVE 검사가 아니다. Debian에는 현재 Ubuntu VEX 어댑터를 적용하지 않았고 suppression/VEX 상태를 변경하지 않았다.

미해결 172건: Debian canonical SPDX 표현 171건, RECORD 인벤토리 1건. `unresolved-work.json`에 구성요소·버전·PURL/bom-ref, 출처, source label/hash, 확인 상태와 다음 조사 방법을 기록했다. LicenseRef는 정확한 배포 원문을 표준 expression에 보존하는 방식이며 의무 면제나 라이선스 정규화 완료를 뜻하지 않는다. CPython 내부 제3자 코드의 완전한 적용성 감사와 실제 수령인 고지·소스 제공 이행도 미검증이다.

## 검증과 제출

65개 unittest 및 변경 Python 포맷·전체 오류 중심 정적 분석·Python 3.10 문법·SQL migration·설정·문서 링크 검사가 통과했다. 실제 저장된 Ubuntu/Temurin 원본·rootfs에 수정 어댑터를 적용했고, 비파일 구성요소 전체 레코드와 각각 93/139개 결과가 유지됐다. 증거는 `regression.json`이다.

최종 실행 경로: worktree의 `artifacts/python-slim-final-002/`. `submission-reviewed/`에는 원본/보강/Trivy BOM, 단계별 변경·제외, 원문·버전 표식·RECORD·vendor 목록, 교차검증·CVE 조사·DT 검증·미해결·회귀 결과, 규칙·스크립트·개발 diff와 SHA-256 manifest를 보존한다. rootfs/image-save는 번들 밖에 hash로 연결한다. 이전 실패 증적의 위치와 hash는 `completion-report.json`에 연결한다. 산출물은 gitignore되며 영속 제출 시 해당 디렉터리와 별도 아카이브를 함께 보존해야 한다.

| 단계 | 상태 |
| --- | --- |
| 동일 digest 원본·비교본 수집 | 완료 |
| Python/pip/vendor 보강·소유 파일 정규화 | 수행 완료, canonical 표현·내부 적용성 부분 미해결 |
| 항목별 Syft/Trivy 대조 | 완료, 라이선스/CVE 차이의 최종 적용성 미해결 |
| 제출 번들 hash 검증 | 완료 |
| DT 이벤트·개수·필드·hash | 완료, UI 미확인 |
| CVE/VEX | 조사 완료 범위 기록, Debian VEX 미지원·적용성/DT 차이 미해결 |
| 실제 라이선스 의무 이행 | 범위 밖 |

후속 작업은 exact copyright 본문별 canonical 매핑, CPython embedded code 감사, vendored CVE 코드·패치 확인 및 Debian advisory/VEX 어댑터와 DT 분석 차이 확인이다. 이미지 변경·버전 업그레이드·finding suppression은 이번 작업에서 수행하지 않았다.
