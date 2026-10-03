# Temurin JRE / Ubuntu 첫 실험

2026-10-03. Elixir/Alpine 다음 비교 대상으로 `eclipse-temurin:21-jre-noble`을 선택했다. Java 버전은 실험 기본값이며 다른 JRE major/배포판을 대표하지 않는다.

- 플랫폼: linux/arm64
- 이미지: `docker.io/library/eclipse-temurin@sha256:ad32e01f3e9051e9f69ee3f41bc4826b580569a9f738368bb64b6d2a148824ff`
- 이미지 release: Temurin `21.0.12.1+1-LTS`, Ubuntu `24.04.5 LTS`
- 도구: Syft 1.54.0 / Trivy 0.75.0. Trivy는 `--scanners license`를 지정했다.
- 루트 파일시스템은 docker create/export로 조사했다. 대상 이미지의 프로그램을 실행하지 않았다.

## 실제 결과

| 구분 | Syft 원본 | Syft 정규화 | Trivy 원본 |
|---|---:|---:|---:|
| Debian 패키지 | 136 | 136 | 136 |
| JRE 애플리케이션 | 1 | 1 | 0 |
| jrt-fs JAR | 1 | 1 | 0 |
| Ubuntu OS | 1 | 1 | 1 |
| 파일 | 3,934 | 0 | 0 |
| 합계 | 4,073 | 139 | 137 |

Debian 패키지 136개의 이름과 버전은 두 도구에서 모두 같았다. 이번 조건에서는 Trivy의 OS 패키지 탐지가 부족하지 않았다. JRE는 apt 패키지가 아니라 공식 Dockerfile이 배포 tarball을 `/opt/java/openjdk`에 풀어 설치하므로 별도 탐지가 필요했다. Syft는 이를 잡았다.

원본 라이선스 필드가 있는 Debian 패키지는 Syft 136개, Trivy 127개였다. 이는 정확도나 의무 범위의 점수가 아니다. Syft의 다중 라이선스 목록과 Debian copyright의 파일별 선택 관계를 따로 조사해야 한다. 실행시간은 각각 10.653초, 57.631초였으나 동시 실행·다운로드·캐시 조건이 통제되지 않아 성능 순위로 사용하지 않는다.

## 파일 제외 근거

모든 제외 파일의 원본 SHA-256을 export rootfs 바이트와 대조했다. 이미지 자체에서는 파일을 삭제하지 않는다.

- 3,488개: `/var/lib/dpkg/info/*.list`의 단일 패키지 소유 관계.
- 334개: 설치된 패키지 이름과 허용된 dpkg 제어 파일 suffix를 대조. maintainer script도 패키지 구성으로 유지한다.
- 111개: release 파일의 공급자·버전을 확인한 JRE 디렉터리 구성. upstream 빌드와 파일별 동등성을 증명한 것은 아니다.
- 1개: `/var/lib/dpkg/status`는 OS에 연결한 패키지 인벤토리 증거.

copyright 경로의 부모 디렉터리 symlink와 multiarch 경로도 해석한다. 파일 hash 불일치·소유자 모호성은 제외하지 않는다. 패키지 인벤토리 또는 버전 불일치는 실패시킨다. 제외 파일 원본 레코드와 재연결 정보는 증적에 남긴다.

## 라이선스 보강과 남은 과제

`normalize_debian_bom.py`는 실제 이미지 copyright의 DEP5 `Files` 문단을 읽고 명시적인 AND/OR를 보존한다. GNU 버전/`+`와 검토한 별칭은 마이그레이션 규칙으로 대응한다. SPDX 공식 ID 목록은 license-list-data v3.28.0에서 고정했다. 소스 패키지 문단들의 라이선스 집합을 표준 `licenses.expression`에 채우되 **바이너리 파일에 적용되는지까지는 추정**으로 표시한다. 소스·빌드·문서 조건이 과다 포함될 수 있다.

불명확한 별칭, 예외, 자유 서술 copyright는 원문에 연결한 안정적인 `LicenseRef`로 기록한다. 현재 정규화에는 Debian/JRE 합계 293개의 서로 다른 LicenseRef가 있다. 이는 293개 라이선스라는 뜻이 아니며 동일한 조건의 중복·독자 명칭·공지 문서가 포함된다. 원문의 정확한 SPDX 대응은 아직 미해결이다. 원본 스캐너 값도 변경 이력에 보존한다.

JRE의 GPLv2/Classpath 주 조건과 배포된 법적 문서들을 집계했다. Classpath 적용은 배포 수준 추정이며 모든 내부 파일에 예외가 적용된다는 확인이 아니다. JRE `legal`의 제3자 문서·assembly exception은 원문 LicenseRef로 보존해 내부 선택 관계를 잃지 않게 했다. `jrt-fs`의 GPLv2/Classpath도 배포 근거 추정이며 모듈 소스 헤더 검증이 남아 있다. 따라서 **탐지·파일 정리·첫 라이선스 보강은 실행했지만 라이선스 정규화 전체가 완료된 상태는 아니다.**

다음 보강은 미해결 label별 원문 정의에서 정확한 ID/예외/선택 관계를 찾아 마이그레이션을 추가하고, 소스 조건과 배포 바이너리 조건을 좁히는 작업이다. LicenseRef를 단순히 지우거나 가장 유사한 SPDX 이름으로 단정하지 않는다. 고지문·소스 제공 등 실제 의무 이행 확인은 별도 단계다.

## Dependency-Track / 증적

- [Syft 정규화 프로젝트](https://frontend.hoplites-dtrack.orb.local/projects/c255977f-69be-47da-af19-04daad1ec269)
- [Trivy 비교 프로젝트](https://frontend.hoplites-dtrack.orb.local/projects/b5967dc3-2ff4-4acd-9f63-56fb226f71ee)

DT API에서 두 업로드 COMPLETED, 각각 139/137개, 이름·버전, 정규화본의 138개 라이선스 표현 일치를 확인했다. OS는 배포 집합으로 유지하고 별도 라이선스를 부여하지 않았다. UI 표시는 별도로 확인하지 않았다. SPDX 표현 및 LicenseRef는 DT에서 상세 라이선스 링크가 없을 수 있다.

실험 파일은 gitignore된 `artifacts/temurin21-noble/`에 있다. `submission-v2/`에는 원본/정규화/비교 BOM, 3,934개 제외 CSV, 변경 이력, dpkg 상태·소유 목록·copyright, JRE legal 원문, 규칙과 스크립트, DT API 결과, 321개 파일 SHA-256 manifest를 넣었다. 전체 정규화를 재실행해 출력 및 근거 일치를 검증했다. rootfs/image-save는 크기 때문에 번들 밖에 보존한다. 해시는 서명이나 배포 의무 이행 증명이 아니다.

```sh
python3 scripts/normalize_debian_bom.py \
  --sbom artifacts/temurin21-noble/syft.cdx.json \
  --rootfs artifacts/temurin21-noble/rootfs.tar \
  --output artifacts/temurin21-noble/normalized-v2.cdx.json \
  --evidence artifacts/temurin21-noble/normalization-v2-evidence.json \
  --sources-dir artifacts/temurin21-noble/normalization-v2-sources
python3 scripts/build_debian_evidence_bundle.py \
  --experiment artifacts/temurin21-noble \
  --output-dir artifacts/temurin21-noble/submission-v2
```

출력이 이미 있으면 새 경로를 사용한다. 번들 빌더의 입력 이름은 이번 실험 v2로 고정된 프로토타입이다. Python 테스트 31개가 통과했다. 소유·hash·버전·symlink·명시적 라이선스 관계·원본 불변성과 정규화 재실행 결과를 검증했다.

공식 자료: [Temurin 컨테이너](https://github.com/adoptium/containers), [Debian copyright format](https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/), [SPDX 3.28.0 목록](https://github.com/spdx/license-list-data/blob/v3.28.0/json/licenses.json).
