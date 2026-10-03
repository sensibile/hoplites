# 설정·패키지 관리 정보와 OS 항목 처리

2026-10-03. 규칙 `platform-metadata-v1`, 기존 `codex/project-skeleton` 작업 트리에서 구현했습니다.

| 항목 | 확인 근거 | 결과 |
| --- | --- | --- |
| `/etc/hostname` | 원본 이미지 레이어의 `localhost` 설정과 Syft SHA-256 일치 | 소프트웨어 구성요소에서 제외, 원문 증적 보존 |
| `/etc/hosts` | 원본 레이어의 IPv4/IPv6 localhost 매핑과 Syft SHA-256 일치 | 소프트웨어 구성요소에서 제외, 원문 증적 보존 |
| `/lib/apk/db/installed` | 최종 레이어의 APK 패키지 DB 구조와 Syft SHA-256 일치 | 패키지 조사 근거로 보존, 별도 소프트웨어 항목에서 제외 |
| `alpine` | 이미지의 `/etc/alpine-release`와 `/etc/os-release`가 3.24.2로 일치 | OS 구성요소 유지, 라이선스 평가 범위를 속성으로 명시 |

이전 컨테이너 export의 hosts/hostname은 빈 값이었지만 원본 이미지 레이어에서는 원본 Syft 해시와 일치했습니다. 따라서 실제 레이어 파일을 검증해 분류했고, 이 둘의 해시 미확인은 해소했습니다. APK DB의 최종 내용도 이미지 레이어를 적용한 결과로 확인했습니다.

소프트웨어 목록의 파일 항목을 분리한 것이며 납품 이미지의 파일을 삭제한 것은 아닙니다. 파일 경로만으로 임의 제외하지 않고, 원본 레이어에서 SHA-256이 일치하는 파일의 설정/DB 형식을 확인합니다. 예상하지 못한 내용이나 참조 관계는 실패로 처리합니다. 레이어의 whiteout과 os-release의 표준 심볼릭 링크를 처리하고, 주소형 레이어 blob의 SHA-256을 확인합니다.

Alpine은 배포판 집합을 나타내는 OS 식별자이며, 이 항목을 apk-tools 또는 Linux 커널 같은 별도 코드 패키지로 취급하지 않습니다. 포함 소프트웨어 라이선스는 각 패키지에서 관리합니다. 단일 MIT/GPL 값이나 근거 없는 SPDX 값을 채우지 않습니다. `hoplites:os:license-assessment`는 `distribution-aggregate; licenses-managed-per-component`로 저장했습니다. 이 상태는 포함 패키지의 조사나 의무를 면제한다는 뜻이 아닙니다.

```sh
python3 scripts/normalize_platform_metadata.py \
  --sbom artifacts/elixir-alpine/normalized-runtime-v1.cdx.json \
  --image-archive artifacts/elixir-alpine/image-save.tar \
  --output artifacts/elixir-alpine/normalized-platform-v1.cdx.json \
  --evidence artifacts/elixir-alpine/platform-v1-evidence.json
```

Docker image save archive는 이번 이미지 digest의 로컬 저장본입니다. 별도 출처 인증이 아니며 기록한 archive/config/layer 해시로 보존·재실행합니다. 원본 증적과 이전 보강 결과는 변경하지 않았습니다.

결과: 31개 → 28개(소프트웨어 27개 + OS 1개), 파일 항목 0개. 소프트웨어 27개의 라이선스 필드는 모두 존재합니다. 전체 테스트 24개 통과, 기존 증적 38개 파일의 해시와 이번 변환 재실행 결과를 대조했고 확장 증적 `submission-platform-v1/`에는 43개 파일 및 manifest를 보존했습니다. 제외한 구성요소 전체·내용·해시·출처 레이어는 `platform-v1-evidence.json`에 있습니다. image-save.tar는 별도로 보존합니다.

DT 기존 프로젝트 업로드 COMPLETED. API 전체 구성요소 28개 및 이름·버전 집합 일치, 파일 3개 부재, Alpine 버전·평가 범위 속성 저장, 소프트웨어 27개의 라이선스 ID/식 보존을 확인했습니다. 응답은 `platform-v1-upload/`에 보존했고 UI는 직접 검사하지 않았습니다. Erlang 포함 제3자 코드의 라이선스 매핑, 실제 고지 배치 및 의무 이행은 아직 후속 작업입니다. 라이선스 필드 존재만으로 이 단계까지 완료됐다고 판정하지 않습니다.
