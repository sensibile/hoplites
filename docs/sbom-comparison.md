# Syft와 Trivy 이미지 비교 기준

## 목적

여러 이미지에서 어떤 조건에 각 도구의 식별이 유리한지 실험으로 확인합니다. 현재 원본 생성 및 정규화의 기준은 Syft이며 Trivy는 비교 대상으로 유지합니다. 전체 구성요소 개수만으로 품질이나 우열을 판정하지 않습니다.

## 실험 조건

동일한 플랫폼 이미지 digest를 검사하고 이미지 tag, 멀티아키텍처 index와 플랫폼 digest를 구분합니다. 도구 버전, 스캐너 옵션, 실행 시점, 경과 시간, 오류와 네트워크/DB 조건을 기록합니다. 다른 옵션으로 생성한 결과를 동일 조건이라고 주장하지 않습니다.

OS 패키지 DB, lockfile, 빌드 후 잔존 메타데이터 등 실제 식별 근거를 확인하고 알려진 구성요소와 비교합니다. 검출 차이와 원인은 구분하여 원인 미확인 시 unknown으로 기록합니다.

## 평가 항목

| 항목 | 확인할 내용 |
| --- | --- |
| OS 패키지 | 알려진 패키지와 버전의 식별 및 누락 |
| 언어 패키지·런타임 | 애플리케이션 의존성과 직접 설치한 런타임 식별 |
| 메타데이터 | 버전, PURL, 라이선스의 근거와 정확성 |
| 파일 증거 | 패키지와 구분, 소유 관계의 확인 가능성 |
| 업로드 | Dependency-Track 처리 후 값 보존과 페이지별 전체 조회 |
| 실행 비용 | 경과 시간, 실패, 다운로드 및 DB 조건 |

다음 이미지 후보 조건은 Alpine/Debian 계열, 언어 의존성이 포함된 애플리케이션, distroless, 패키지 DB가 없는 바이너리입니다. 후보별 이미지와 실행은 별도로 선택하며 이번 기록은 추가 실행을 의미하지 않습니다.

## 첫 사례: Elixir Alpine

2026-10-03. `elixir:1.18.4-alpine`, linux/arm64.
플랫폼 digest: `sha256:b82a9d4474e7d6bc26db0e0fbf5eadc281d4fa4c905805b7d9e2dac7017c0683`.

| 관측 | Syft 1.54.0 | Trivy 0.75.0 |
| --- | --- | --- |
| CycloneDX 버전 | 1.7 | 1.7 |
| 총 구성요소 | 300 | 27 |
| 파일 | 271 | 0 |
| 라이브러리 | 26 | 26 |
| 애플리케이션 | 2 | 0 |
| OS | 1 | 1 |
| version 존재 | 29 | 27 |
| group 존재 | 0 | 0 |
| licenses 존재 | 25 | 25 |
| BusyBox 패키지 | 1.37.0-r31 / GPL-2.0-only | 1.37.0-r31 / GPL-2.0-only |
| Elixir·Erlang | 1.18.4 / 28.5.0.7 | 이번 실행에서 미검출 |

Syft는 `scan registry:<digest> --platform linux/arm64 -o cyclonedx-json`, Trivy는 `image --image-src remote --platform linux/arm64 --format cyclonedx --scanners license <digest>`로 실행했습니다. 도구별 명령과 기능 범위가 다르며 이 관측을 모든 이미지의 검출 성능으로 일반화하지 않습니다.

Syft의 `/bin/busybox` 파일 항목에는 라이선스가 없지만 별도 `busybox` 패키지에는 존재합니다. 정규화 방향은 파일을 무조건 제거하는 것이 아니라 패키지와 파일 증거를 구분해 연결하는 것입니다. 이번 결과에서 Syft는 런타임을 추가 식별했고 Trivy는 파일 항목 없이 패키지 중심 결과를 생성했습니다.

Dependency-Track에는 두 결과를 별도 프로젝트로 등록해 원본 비교를 보존했습니다. Syft 구성요소 300개를 페이지별로 모두 조회했고 Trivy 구성요소 27개 및 BusyBox 버전·라이선스를 API에서 확인했습니다. 웹 UI 자체를 검사한 결과는 아닙니다.

원본과 응답: Git 제외 `artifacts/elixir-alpine/`, Trivy 등록 증거: `artifacts/elixir-alpine/trivy/`. 실행 시간은 별도 측정하지 않아 성능 비교는 하지 않습니다.

## 패키지 단위 재비교와 라이선스 표현

원본 두 BOM의 APK PURL 구성요소를 이름으로 대조한 결과, 26개 모두 이름과 패키지 버전이 일치했습니다. 라이선스 JSON 표현은 9개에서 달랐습니다.

| 패키지 | Syft | Trivy |
| --- | --- | --- |
| ca-certificates, ca-certificates-bundle | SPDX 식 `MPL-2.0 AND MIT` | `MPL-2.0`, `MIT` 개별 ID 목록 |
| libgcc, libstdc++, liblksctp, lksctp-tools | SPDX 식 `GPL-2.0-or-later AND LGPL-2.1-or-later` | 두 개별 ID 목록 |
| musl-utils | SPDX 식 `MIT AND BSD-2-Clause AND GPL-2.0-or-later` | 세 개별 ID 목록 |
| libncursesw, ncurses-terminfo-base | `license.id: X11` | `license.name: X-11` |

이미지 rootfs의 `/lib/apk/db/installed`에서 위 식과 `X11`을 확인했습니다. 이번 사례에서 Syft는 APK DB의 논리식과 식별자를 그대로 보존하고, Trivy는 7개 패키지에서 AND 관계를 명시하지 않는 목록으로 출력하며 2개는 자유 텍스트 이름으로 출력합니다. 목록에서 라이선스 관계를 임의로 AND 또는 OR로 복원하지 않습니다. 이는 출력 결과의 관측이며 Trivy 내부 변환의 원인을 조사한 결과는 아닙니다.

[SPDX 표현 명세](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/)에서 AND는 동시 적용, OR는 선택, WITH는 예외 결합을 나타냅니다. 정규화는 근거가 있는 식의 연산자를 보존하고, 자유 텍스트 이름을 표준 ID로 바꿀 때는 근거를 기록해야 합니다. `GPL-2.0-only`와 `GPL-2.0-or-later`는 같은 값으로 합치지 않습니다. BusyBox는 두 BOM 모두 `GPL-2.0-only`, 패키지 버전 `1.37.0-r31`로 일치했습니다.

Syft의 파일 271개 중 패키지 소유가 검증된 264개를 패키지 중심 BOM에서 제외한 결과는 36개입니다. Trivy 27개와의 차이는 Elixir·Erlang 2개와 아직 유지한 파일 7개입니다. 따라서 원본의 300 대 27이라는 수치에는 파일과 패키지의 표현 단위 차이가 크게 작용했습니다. 관련 근거와 제외 규칙은 `sbom-normalization.md`와 `evidence-bundle.md`에 기록했습니다.

## 남은 검증

다른 이미지 조건, 직접 설치 런타임에 포함된 제3자 라이선스 매핑, 미해결 파일의 분류, 다른 버전 분리, 취약점 데이터 동기화는 추가 검증이 필요합니다. 이번 라이선스 비교는 저장된 BOM과 APK DB를 대상으로 했으며 Dependency-Track UI의 표시 방식은 직접 검사하지 않았습니다.

## Ubuntu / Temurin 비교 추가

[Temurin JRE 첫 실험](temurin-first-run.md): Syft 4,073개를 139개로 정리했고 Trivy는 137개였다. Debian 136개 이름·버전은 모두 같았다. 차이는 apt 밖에 설치한 JRE와 jrt-fs였다. OS 패키지 탐지와 비패키지 런타임 탐지를 나눠 비교해야 하며 raw component 수만으로 우열을 정하지 않는다. Debian copyright의 별칭·예외 및 JRE legal 문서 SPDX 대응은 여전히 보강 중이다.
