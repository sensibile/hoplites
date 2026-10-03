# 직접 설치한 Elixir·Erlang 보강

후속 [Erlang 내부 라이선스 조사](erlang-internal-licenses.md)에서 내부 코드 식을 부모 Erlang 표준 필드에 추가했습니다. 아래 Apache-2.0은 주 라이선스 보강 단계의 기록이며 현재 DT 값은 복합 식입니다. 포함 파일과의 매핑을 수행했고 Megaco 업스트림 NOASSERTION은 명시적 미확정으로 남겼습니다.

2026-10-03. 규칙 `runtime-enrichment-v1`. 작업 브랜치 `codex/project-skeleton`의 기존 작업 트리를 유지했습니다.

## 확인 근거와 적용

| 런타임 | 버전 | 공식 소스 커밋 | 표준 BOM 라이선스 |
| --- | --- | --- | --- |
| Elixir | 1.18.4 | `7b20c281d521aa7aa2ad2baa1e9ae6c579d79d0c` | Apache-2.0 |
| Erlang/OTP | 28.5.0.7 | `09fb046150ab94104e03ee816b95c8b7e6b04683` | Apache-2.0 |

이미지 digest는 기존 Elixir Alpine 실험과 동일합니다. rootfs의 Elixir `elixir.app` 버전과 Erlang `releases/28/OTP_VERSION`을 확인했습니다. 이미지 환경 변수와 빌드 이력에도 같은 버전 및 공식 소스 다운로드 주소가 기록되어 있습니다. 빌드 이력의 소스 다운로드 SHA-256은 기록했지만 소스 tarball 다운로드·재빌드·바이너리 동등성 검증은 수행하지 않았습니다.

정확한 릴리즈 태그를 커밋으로 고정하고 공식 [Elixir LICENSE](https://github.com/elixir-lang/elixir/blob/7b20c281d521aa7aa2ad2baa1e9ae6c579d79d0c/LICENSE), [NOTICE](https://github.com/elixir-lang/elixir/blob/7b20c281d521aa7aa2ad2baa1e9ae6c579d79d0c/NOTICE), [Erlang LICENSE.txt](https://github.com/erlang/otp/blob/09fb046150ab94104e03ee816b95c8b7e6b04683/LICENSE.txt)를 캐시했습니다. 정규화본의 두 앱 `licenses[].license.id`에 `Apache-2.0`, `url`에 커밋 고정 라이선스 주소를 추가했습니다. 표준 필드를 채우면서 별도 속성과 보고서에 `inferred-from-versioned-upstream`을 기록합니다. 이미 설치된 바이너리와 소스의 완전한 동일성을 증명한 값은 아닙니다.

Syft가 두 앱의 식별 경로로 기록한 파일 4개는 rootfs SHA-256이 원본 파일 구성요소와 일치함을 확인해 앱 항목으로 통합했습니다. 경로 접두사만으로 다른 파일을 통합하지 않습니다. 원본 파일·해시·소유 앱·전후 변경·참조 재연결을 증적에 보존하며, 이미지 파일을 삭제하지 않습니다. 버전·라이선스 충돌, 증적 해시 불일치, 버전 표식 불일치는 실패로 처리합니다.

## 실행과 증적

```sh
python3 scripts/enrich_runtime_bom.py \
  --sbom artifacts/elixir-alpine/normalized-v2-final.cdx.json \
  --rootfs artifacts/elixir-alpine/rootfs.tar \
  --sources artifacts/elixir-alpine/runtime-sources \
  --output artifacts/elixir-alpine/normalized-runtime-v1.cdx.json \
  --evidence artifacts/elixir-alpine/runtime-v1-evidence.json
```

출력·증적 경로는 기존 파일이 없는 새 경로여야 합니다. 실행 중 외부 조회 없이 `runtime-sources/rules.json`과 해시를 확인한 원문 캐시를 사용합니다. 이 캐시는 이번 실험의 증거 입력이며, 영속 지식 저장을 위한 SQLite 마이그레이션 구현을 대체하지 않습니다.

`build_runtime_evidence_bundle.py`는 이전 패키지 정규화 증적의 전체 파일 해시를 확인하고 런타임 보강을 재실행해 결과·보고서를 대조합니다. `submission-runtime-v1-reviewed/`에는 이전 증적, 이번 BOM·보고서, 소스 원문·NOTICE·이미지 빌드 이력, 실행 스크립트와 파일별 SHA-256 manifest를 포함합니다. 원본·이전 업로드본은 보존합니다. rootfs는 별도 보존하며 묶음은 서명된 증명이 아닙니다.

## 검증 결과와 후속 작업

- 표준 라이선스 필드 2개 추가, 런타임 파일 4개 통합. 35개 → 31개.
- 남은 파일 3개는 `/etc/hostname`, `/etc/hosts`, `/lib/apk/db/installed`이며 이번 변경에서 유지했습니다.
- 전체 테스트 21개 통과. 입력 불변, 반복 동일성, 표준 필드 반영, 관계 통합, 충돌·변조·버전 불일치 거부 확인.
- 기존 DT 프로젝트 업로드 COMPLETED. API 전체 구성요소 이름·버전 집합과 런타임 `resolvedLicense.licenseId: Apache-2.0` 확인. 기존 ca-certificates/libgcc의 SPDX 식 보존 확인. 업로드 증적은 `runtime-v1-upload/`에 보존. UI 자체는 직접 검사하지 않았습니다.

프로젝트의 주 라이선스를 보강한 결과이며, Erlang 안의 모든 코드가 Apache-2.0이라고 판정한 결과는 아닙니다. 동일 커밋의 `LICENSES/`에서 12개 별도 라이선스 원문을 캐시했고, 실제 이미지에 포함된 파일·기능과의 적용 관계는 미확인으로 기록했습니다. 다음 단계에서 실제 포함된 코드를 매핑하고 필요한 별도 구성요소·라이선스를 반영해야 합니다. Elixir NOTICE와 양쪽 LICENSE는 확보했지만 실제 납품물에 고지를 배치하거나 의무 이행을 검증한 것은 아닙니다.
