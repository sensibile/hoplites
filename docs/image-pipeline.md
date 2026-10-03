# 이미지 입력부터 DT/VEX까지

2026-10-03. `scripts/image_pipeline.py`는 기존 처리 단계를 하나의 Python 실행 스크립트로 연결한다. 스캐너 자체는 외부 Syft/Trivy이며 이번 CLI는 실행·변환·증적을 조합하는 스크립트다.

처음 실행할 때는 [사용 가이드](usage-guide.md)의 준비·실행·결과 확인 순서를 따른다. 이 문서는 내부 흐름과 규칙 확장 기준을 설명한다.

## 사용

```sh
# 이미지 하나만 지정: 정규화 BOM + 증적, 출력은 artifacts에 자동 생성
python3 scripts/image_pipeline.py eclipse-temurin:21-jre-noble

# DT 업로드와 Ubuntu VEX까지
python3 scripts/image_pipeline.py eclipse-temurin:21-jre-noble \
  --output-dir artifacts/temurin-next \
  --upload --vex --dt-project hoplites-temurin-arm64

# Trivy 비교본에는 CVE 검사도 명시적으로 켠다
python3 scripts/image_pipeline.py alpine:3.24 --trivy --upload
```

기본 플랫폼은 `linux/arm64`. `--platform linux/amd64` 등으로 지정할 수 있다. 지원 플랫폼 descriptor가 없거나 모호하면 실패한다. multi-platform index 태그를 플랫폼별 manifest digest로 고정한다. DT 프로젝트 version은 manifest digest이며 기본 프로젝트 이름은 repository+architecture로 묶는다. 프로젝트 이름을 지정하면 해당 프로젝트에 새 digest 버전이 생성된다. `--vex`에는 `--upload`가 필요하다.

원본과 기존 출력은 덮어쓰지 않는다. 실행 중 실패하면 `summary.json`의 failed 단계와 로그를 남기고, 같은 경로를 덮어쓰지 않고 새 실행으로 진행한다. 완료는 파이프라인 실행 완료이며 미해결 정보나 실제 납품 의무 이행 완료와 다르다.

## 흐름과 산출물

1. registry descriptor 확인 → 플랫폼별 digest 고정 → Docker pull/inspect로 플랫폼 대조.
2. docker image save와 create/export로 rootfs 수집. 생성한 컨테이너는 finally에서 삭제하며 대상 앱/entrypoint를 실행하지 않는다.
3. Syft 1.54.0 CycloneDX 원본 보존. 선택한 manifest digest와 metadata version이 일치해야 한다.
4. 패키지 DB로 어댑터 선택: APK → 파일 보강/패키지 묶음/virtual package 제외; dpkg → 패키지 소유/배포된 copyright 보강. 새 dpkg 이미지는 Java가 없어도 처리한다. copyright가 없으면 원래 스캐너 라이선스를 보존하고 미해결로 기록한다.
5. 확인된 Elixir/Erlang release 규칙을 적용하고, 검토한 OTP의 embedded license audit를 연결한다. Temurin은 `/opt/java/openjdk/release`의 공급자/버전을 확인한 경우 배포 legal 원문을 보강한다.
6. Alpine 설정·인벤토리 분리와 OS 근거 검증. 알고 있는 소유 관계만 제외하며 파일/컴포넌트 제외 이력은 sidecar에 보존한다.
7. `normalized.cdx.json`, 단계별 evidence, `normalization-evidence.json`, `summary.json`, 원문 sources, 제출용 `submission/` 생성.
8. `--upload`: Keychain API 키로 로컬 DT BOM 업로드. COMPLETED 뒤 pagination으로 전체 개수·이름·버전·PURL·단일 라이선스 ID/표현을 읽어 검증한다. 다중 license 목록은 DT가 하나만 보존할 수 있어 별도 평가가 필요하다.
9. `--vex`: dpkg 이미지에 Ubuntu VEX 경로를 연결한다. APK 등 미지원 배포판은 finding을 유지하고 adapter 미지원으로 기록한다. 미해결 VEX를 안전 판정으로 바꾸지 않는다. 후보가 0개이면 VEX apply를 건너뛰고 applied=false로 남긴다.

`--trivy`는 Trivy 0.75.0을 `--scanners vuln,license --format cyclonedx`로 실행한다. 이 BOM은 비교 산출물이며 기본 DT 업로드 대상은 정규화된 Syft BOM이다. Trivy 결과를 DT finding으로 자동 합치지는 않는다. Syft/Trivy 컨테이너의 registry 접근은 현재 공개 이미지로 검증했고 private registry 자격증명 전달은 별도 어댑터가 필요하다.

제출 번들은 원본/정규화 BOM, 단계별 원본 변경/제외 근거, copyright/런타임 공지, 규칙 마이그레이션·스크립트, DT/VEX 변경 전후 및 CSV와 SHA-256 manifest를 포함한다. rootfs/image-save는 크기 때문에 별도 보존하고 해시로 연결한다. SQLite 실행 캐시는 원문 JSON과 SQL schema로 재생성 가능하며 제출 번들에는 바이너리 DB를 넣지 않는다.

## 새 이미지·버전을 추가하는 방법

먼저 동일 CLI로 돌린 뒤 `summary.json`의 `unresolved`와 `stages/*-evidence.json`을 본다. 유형별로 다음처럼 누적한다.

| 발견한 차이 | 누적 위치 | 검증 |
|---|---|---|
| DEP5 명칭/예외의 정확한 SPDX 대응 | 새 SQL migration의 `debian_license_alias` | 원문 정의와 선택 관계, 표현 보존 |
| 새 Elixir/Erlang release | `runtime_enrichment_release`에 새 migration | 정확한 version/PURL, pinned commit URL, license SHA-256, rootfs version marker |
| 새 OTP 내부 코드 조건 | `source_release`, `embedded_license_rule` 및 버전별 audit 지원 | archive SHA, installed source/binary selector, 미해결 terms |
| 새로운 런타임 설치 형태 | 별도 adapter 함수/모듈을 추가하고 `Pipeline.normalize`에 연결 | 실제 release/license 파일, ownership와 hash, 합성/실제 image 회귀 |
| 다른 패키지 매니저/배포판 | 새 inventory/normalization 및 advisory adapter | 설치 DB와 scanner version/name 일치, vendor 버전 비교 |
| vendor 예외 판정 | 검토한 exact-version `distro_vex_decision` migration | 원문 SHA/URL/조회일·정확한 scope, 충돌 처리 |

미검토 런타임 버전, LicenseRef 대응, file owner는 제외하지 않고 남긴다. 모든 이미지에 동일한 배포판/라이선스를 일괄 적용하지 않는다. SQL schema/seed는 레포의 텍스트로 누적하며, URL에서 받은 증거는 검토된 SHA로 확인한 뒤 `.cache/hoplites/blobs/<sha>`에 재사용한다. OTP source cache는 이미지 규칙과 source SHA가 맞는 경우만 재사용한다. 외부 증거가 바뀌어 hash가 틀리면 규칙을 자동 수정하지 않고 검토 대상으로 남긴다.

새 버전 추가에는 기존 run의 rootfs hash를 재사용하지 않는다. 새 실행이 고정한 image와 rootfs를 연결하고, release marker를 확인한 뒤 그 실행용 runtime rules를 생성한다. 이미 적용한 SQL migration은 수정하지 않고 다음 파일을 추가한다. 구조가 바뀌는 adapter 구현은 그 변경과 맞는 테스트/실제 이미지 회귀를 함께 추가한다.

## 실제 연결 검증

| 입력 | Syft 원본 → 정규화 | DT |
|---|---:|---|
| 고정 Elixir/Alpine digest | 300 → 28 | 필드·개수 검증 완료 |
| `eclipse-temurin:21-jre-noble` | 4,073 → 139 | 필드 검증, VEX 33건 반영 |
| `ubuntu:24.04` (Java 없음) | 2,358 → 93 | 공통 dpkg 경로·필드 검증 완료 |
| `alpine:3.24` (런타임 없음) | 95 → 17 | 공통 APK 경로·Trivy CVE 검사·필드 검증 완료 |

Temurin VEX는 resolved 32/not_affected 1, 최종 활성 0/suppressed 33을 API로 확인했다. Elixir의 Megaco 미해결 조건과 Debian/Temurin의 미대응 LicenseRef는 그대로 남아 있다. 기본 Alpine의 VEX adapter는 미지원이므로 자동 적용하지 않았다. 테스트 51개 통과. 실제 UI는 별도로 확인하지 않았으며 라이선스 의무 이행이나 이미지의 무취약점을 주장하지 않는다.
