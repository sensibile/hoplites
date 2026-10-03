# Python slim 후속 보완 결과

2026-10-03, linux/arm64. 동일 고정 manifest의 실제 BOM 필드를 추가 보강하고 로컬 DT 재업로드까지 검증했다. 모든 라이선스 canonical 식별, CVE 실행 조건 검증, 수령인에 대한 라이선스 의무 이행을 완료했다는 뜻은 아니다. 첫 실행과 실패 증거는 그대로 보존했다.

## 기준과 변경

원격 main `ea02bf90c3db078a4980792af0d9593c60951bce`, PR #2 MERGED를 직접 확인하고 최신 AGENTS.md와 이미지·개발 지침을 읽었다. 기존 task worktree `worktrees/python-slim-completion`, branch `codex/python-slim-completion`, HEAD `c03f2545bf860c719ecc5a757eb2a3c1458c0e1e`를 재사용했다. 두 기준 사이 변경은 지침·문서뿐이며 실행 코드 변경은 없다. 기존 미커밋 변경을 보존했다. 커밋·push·PR·merge는 수행하지 않았다.

이미지는 `docker.io/library/python@sha256:110e8d1de526341568b8fcdb1773b0d47ad63309df21980c6028803226a2dab0`, Python 3.13.16, pip 26.2.1이다. 최신 실행은 `artifacts/python-slim-followup-final-001/`이며 원본 3,312개, 보강본 125개, Trivy 117개다. 공통 식별 117개가 일치하고 Trivy에만 있는 패키지는 없다. Python과 서로 다른 Launcher 6개 및 RECORD 설치 인벤토리는 보강본에 유지했다.

## 라이선스와 인벤토리

`0008_debian_reviewed_terms.sql`에 배포 copyright 문서 SHA-256과 원래 label을 키로 하는 31개 매핑을 추가했다. SPDX 3.28.0 정의와 실제 grant·disclaimer·exception 문단을 대조하여 51개 구성요소/label 항목을 canonical expression으로 바꿨다. 전역 alias로 불확실한 이름을 치환하지 않는다. BSLA, TCP-wrappers, Bison 2.2, invariant 없는 GFDL, FSF permissive 및 정확한 짧은 Autoconf exception 문구 등이 해당한다. 짧은 Autoconf 예외를 서로 다른 긴 2.0/3.0 예외로 바꾸지 않는다. 원문·검토 문단·해시는 `followup-audit/debian-license-review.json`과 보존한 source 문서에 있다.

`0009_cpython_embedded_terms.sql` 및 `audit_cpython_terms.py`로 내부 코드 10개를 조사했다. 이미지 `PYTHON_SHA256`과 일치하는 Python 3.13.16 공식 tar의 SHA-256은 `f4b1bfb3c79b5bb11b8d228a12504163b4c0dab4d679828d8f5f26b6cb6ab35d`이다. source/notice 해시, 설치 파일 해시, 실제 `_sysconfigdata` build metadata를 연결했다. Python BOM의 표준 `licenses.expression`에 random BSD-3-Clause, mpdecimal BSD-2-Clause, HACL SHA2·Expat MIT, pysqlite Zlib, blake2 CC0-1.0 및 네 원문 LicenseRef를 반영했다. source와 동일한 Python 파일은 byte 일치를 확인했다. compiled module은 설치 위치·빌드 지시·source archive 연결에 근거한 추정이며 재빌드 byte 동등성을 주장하지 않는다. 내부 코드 전체를 빠짐없이 감사한 결과도 아니다.

RECORD는 원본 scanner SHA-256과 rootfs 실제 bytes를 확인하고 설치 인벤토리/소유 pip 속성을 부여했다. 자기 자신에 대한 checksum을 만들어내지 않고 파일 구성요소를 유지했다. 기존 ownership 미해결 항목에서는 분리했다.

남은 canonical 조사 124건은 Debian 120건과 CPython cookies/xmlrpc/trace/uu-codec 4건이다. 원문은 표준 LicenseRef 표현으로 유지한다. `unresolved-work.json`에 구성요소·버전·PURL·bom-ref·원문 해시·문단 및 다음 조사 근거를 보존했다. free-form 전체 문서, public-domain 선언, 커스텀 exception 및 원문 scope를 검토해야 한다. LicenseRef 보존은 의무 면제나 완료 판정이 아니다.

## CVE와 DT 차이

Trivy의 영향 조합은 267건이다. 동일한 Debian 공식 tracker snapshot과 정확한 설치 source version을 다시 대조한 결과 bookworm open 261건을 유지한다.

pip wheel과 공식 upstream 배포의 hash를 검증한 뒤 설치 vendored 파일을 비교했다. urllib3 2.7.0 connection/connectionpool 코드는 namespace 변경 외 upstream과 같고, response의 차이는 Brotli import 제거다. 세 advisory가 지목하는 함수 AST가 영향 upstream과 같아서 수정 확인 근거는 없으며 finding을 유지한다. 실제 exploit 실행은 하지 않았다.

setuptools 70.3.0은 pkg_resources subset이며 두 advisory의 package_index/egg_info 모듈은 설치되어 있지 않다. msgpack은 `_cmsgpack` C extension이 없고 fallback 경로가 설치되어 있다. 이는 지목한 취약 코드 경로의 부재에 대한 좁은 근거다. 전체 패키지 안전 판정이나 DT suppression으로 확대하지 않았다. wheel/sdist metadata·해시·source diff·설치 경로·advisory 연결은 `followup-audit/vendor-source-comparison.json` 및 `vendor-cve-code-assessment.json`에 있다. 다운로드한 코드는 실행하지 않았다.

DT PostgreSQL을 읽기 전용으로 확인했다. internal analyzer와 NVD mirror는 켜져 있지만 GitHub/OSV mirror와 Trivy analyzer는 꺼져 있다. NVD vulnerability 400,908개가 있어 DB 전체 부재는 원인이 아니다. Trivy CVE에 대응하는 NVD software row와 DT 구성요소 식별자를 대조한 267건의 공백은 CPE vendor/product 불일치 117건, NVD 영향 software row 부재 148건, CPE/PURL 양쪽 매칭 자료 부재 2건이다. 예를 들어 tar:tar와 gnu:tar가 다르다. 대상 NVD software row의 PURL은 0개다. 이는 실제 설정·데이터에서 확인한 매칭 공백이며 analyzer 내부 실행 전체를 trace한 인과 증명은 아니다. 설정을 바꾸거나 finding을 만들기 위해 CPE를 추측하지 않았다.

## Debian VEX

`build_debian_project_vex.py`를 추가하고 `run_project_vex.py`가 실제 rootfs distro에 따라 Debian과 Ubuntu를 선택하도록 했다. Debian은 hash로 확인한 공식 tracker, 실제 dpkg source version·epoch·아키텍처·PURL 및 bookworm을 대조한다. `os-release`의 12와 scanner의 12.15 차이는 rootfs `etc/debian_version`으로 정확히 연결한다. 알려지지 않은 point release를 허용하지 않는다.

실제 DT export에는 findings가 0개여서 적용할 VEX도 0개였다. 읽기 전용 경로 실행과 재조회 결과를 보존했다. 별도로 Trivy affected ref를 공통 패키지 식별자로 보강 BOM에 연결한 draft에서는 Debian 261건 모두 `in_triage`, 비Debian 6건은 미해결로 남았다. 직접 Trivy PURL을 넣거나 point release 확인 전의 실패 결과도 별도 파일에 보존했다. open·fixed_version=0·알 수 없는 근거는 자동 suppression하지 않는다. 정확한 양수 fixed endpoint 이상이며 vendor resolved인 경우만 resolved가 된다. 이번 실행에서 VEX 적용·suppression·분석 설정 변경은 없다.

## 검증과 보존

새 보강본을 기존 로컬 DT `hoplites-python-slim-arm64`, UUID `d1ca28b2-54ca-432b-a953-67f5d46c62fe`에 같은 digest 버전으로 재업로드했다. 이벤트 COMPLETED, 전체 pagination 125/125, 이름·버전·PURL·표준 라이선스·SHA-256 불일치 0개다. 이후 findings도 0개다. UI는 로그인 문제로 미검증이며 API 검증과 구분한다.

76개 unittest, 변경 Python 포맷, 정적 분석, Python 3.10 문법, SQL migration, 설정 및 문서 링크 검사가 통과했다. RECORD 인벤토리 hash 변조와 실제 Debian point release 불일치 거절도 테스트했다. 저장된 Ubuntu/Temurin 원본과 rootfs를 현재 어댑터로 재실행한 결과 각각 93/139개와 식별·라이선스 외 필드를 유지했다. 동일 copyright 해시로 검토된 표현만 각각 12개 변경되었고 전체 before/after를 `regression.json`에 기록했다.

`submission-reviewed/`에 BOM·원문·검토·CVE/DT/VEX·회귀·미해결·코드·규칙·개발 patch와 SHA-256 manifest를 보존한다. 큰 rootfs/image-save는 번들 밖의 경로와 해시로 연결한다. 이전 `python-slim-final-002/submission-reviewed/`도 보존했다. 산출물은 gitignore되므로 영속 전달 시 실행 디렉터리와 연결된 대용량 아카이브를 함께 보존해야 한다.
