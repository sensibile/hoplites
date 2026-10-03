현재 직접 설치 런타임의 보강 결과는 [Elixir·Erlang 보강 기록](runtime-enrichment.md)을 참고합니다. 두 앱의 주 라이선스를 표준 필드에 채웠고 현재 DT는 31개 구성요소입니다.

현재 DT에는 파일별 보강본 대신 [패키지 중심 정규화본](sbom-normalization.md)을 반영했습니다. 아래 v2 보강본과 API 확인은 이전 단계의 기록입니다.

# 현재 상태: 표준 필드 보강 v2

2026-10-03 사용자 요구에 맞춰 수정했습니다. 아래 v1 소유 관계 연결만으로는 정보 보강 요청을 충족하지 못했습니다. 현재 규칙은 `apk-enrichment-v2`입니다.

해시가 일치하고 단일 소유 APK 패키지가 확인된 파일의 빈 `version`에 패키지 버전을, 빈 `licenses`에 선언 라이선스를 반영합니다. 패키지 BOM의 구조화된 라이선스 표현을 우선 사용하고 없으면 APK 원문을 license name으로 보존합니다. SPDX ID를 추측하지 않습니다. 파일 수준 적용은 패키지에서 추정한 정보이며 Properties와 보고서에 그 한계를 표시합니다. 기존 값의 충돌은 덮어쓰지 않고 기록합니다.

실제 적용: version 264개·licenses 264개 추가. 원본과 의존 관계 보존. DT 기존 프로젝트 업데이트 COMPLETED. 서버 전체 300개를 조회하여 version 293개, 라이선스 289개를 확인했습니다. `/bin/busybox`의 실제 서버 표준 필드는 version `1.37.0-r31`, resolvedLicense `GPL-2.0-only`입니다. 파일 version은 upstream binary version이 아닌 APK 패키지 버전입니다. 원본 및 v1 산출물은 보존했습니다.

파일 version 변경으로 DT의 BusyBox 파일 UUID가 `deffd07e-69d1-4055-934d-ad7396ec8038`로 바뀌었습니다. UI를 직접 검사한 것은 아니며 표준 필드 확인은 API 기준입니다.

입출력 경로는 기존 명령에서 `enriched-v2.cdx.json`, `enrichment-v2-report.json`로 바꿉니다. 업로드 증거는 Git 제외 `artifacts/elixir-alpine/enriched-v2-upload/`에 있습니다. 테스트 7개는 표준 필드 보강, 기존값 충돌, 라이선스 부족 시 독립적인 버전 보강, 원본 및 반복 결과 보존 등을 검증합니다.

미해결: hash-mismatch 2개, unknown-owner 5개. 원본 BOM 항목을 제거하지 않았고 보고서에 다음 조사 방법을 남겼습니다. rootfs에서 Elixir/Erlang의 LICENSE 또는 COPYRIGHT 경로도 검색했으나 발견하지 못했습니다. 직접 설치 런타임은 APK 범위를 넘으므로 해당 빌드 출처 조사와 추가 규칙이 필요합니다. 라이선스 추정 적용은 법적 의무 이행 완료를 의미하지 않습니다.

## 이전 v1 실험 기록

# Alpine APK 소유 관계 보강 실험

2026-10-03. `scripts/enrich_syft_apk.py`는 Python 표준 라이브러리만 사용합니다. 기존 작업 공간과 고정 Elixir ARM64 digest에 대해 수행했습니다. 원본은 변경하지 않았습니다.

## 입력과 출력

원본 CycloneDX SBOM, 고정 이미지에서 실행 없이 export한 rootfs tar, 이미지 digest를 입력받습니다. tar를 파일시스템에 풀거나 이미지의 프로그램을 실행하지 않습니다. SBOM의 대상 digest를 확인하고 각 파일의 SHA-256을 rootfs의 파일과 비교합니다. Alpine `/lib/apk/db/installed`의 F/R 소유 목록을 읽습니다.

동일 이름·버전의 APK 패키지를 BOM에서 하나만 찾으면 owner bom-ref를 연결합니다. Group, 파일 version 및 파일 licenses는 임의로 채우지 않습니다. `hoplites:apk-owner:*` 속성에 패키지 버전과 선언 라이선스, DB 경로·SHA-256, 규칙 버전 및 상태를 기록합니다. 이것은 파일 자체의 라이선스 확정이나 배포 의무 이행 증거가 아닙니다.

```sh
python3 scripts/enrich_syft_apk.py \
  --sbom artifacts/elixir-alpine/sbom.cdx.json \
  --rootfs artifacts/elixir-alpine/rootfs.tar \
  --image-ref docker.io/library/elixir@sha256:b82a9d4474e7d6bc26db0e0fbf5eadc281d4fa4c905805b7d9e2dac7017c0683 \
  --output artifacts/elixir-alpine/enriched.cdx.json \
  --report artifacts/elixir-alpine/enrichment-report.json
```

## 실제 결과

- 원본 구성요소 300개와 dependencies를 보존했습니다.
- 파일 271개 중 소유 패키지 연결 264개, 해시 불일치 2개, 소유 패키지 미확인 5개입니다.
- `/bin/busybox` → `busybox` 1.37.0-r31, 선언 라이선스 GPL-2.0-only를 연결했습니다.
- `/etc/hostname`과 `/etc/hosts`는 해시 불일치로 보강하지 않았습니다. export는 컨테이너 파일시스템을 사용하므로 이미지에 대한 모든 파일의 정확한 재구성을 가정하지 않습니다.
- APK DB 및 직접 설치된 Elixir/Erlang 파일 4개는 APK 소유 목록에서 찾지 못했습니다.

원본 SHA-256 불변, 구성요소 수 및 의존 관계 보존을 확인했습니다. 합성 테스트 5개로 원본 보존, 반복 보강의 동일성, 해시 불일치, 소유 충돌, 잘못된 대상, BOM 내 패키지 미확인을 검증했습니다.

## 경계

현재 APK 전용입니다. 패키지 DB는 선언된 소유 정보이며 설치 후 변경 여부를 완전히 증명하지 않습니다. tar의 이미지 출처는 호출자가 보장해야 합니다. digest 문자열 일치만으로 tar의 출처를 인증하지 않습니다. 라이선스 텍스트 검사, 원격 정보 보강, Debian/RPM 지원, 서명 검증, 이행 관리는 포함하지 않습니다.

보강본은 로컬 산출물이며 Dependency-Track에 아직 업로드하지 않았습니다. 사용자 정의 속성을 UI가 버전·라이선스 열로 표시한다는 보장도 없습니다. 이 실험은 증거 있는 연결을 보존하는 단계입니다.
