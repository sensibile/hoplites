# DT용 패키지 중심 BOM 정규화

2026-10-03. 사용자 요청에 따라 원본의 파일 증거를 보존하면서 소유 패키지가 확인된 파일을 DT용 BOM에서 제외했습니다.

## 규칙

현재 최종 반영본은 [설정·인벤토리 파일 분리](platform-metadata-normalization.md)를 적용한 28개입니다. 아래 31개/35개/36개 결과는 이전 단계의 기록입니다.

후속 [런타임 보강](runtime-enrichment.md)에서 Elixir·Erlang의 표준 라이선스를 채우고 검증한 런타임 파일 4개를 앱 항목으로 통합했습니다. 현재 DT 반영본은 31개이며 아래 36개/35개 결과는 이전 단계의 기록입니다.

`package-view-v1`: 원본 SBOM SHA-256과 소유 관계 보고서의 입력 SHA-256이 일치해야 합니다. 파일 해시 확인과 단일 패키지 소유 근거가 확보되어 linked인 항목 중, BOM 안에 소유 패키지가 존재하고 이름·버전이 일치하는 파일만 제외합니다. 필드 충돌이 기록된 파일은 유지합니다.

제외한 원본 파일 항목과 소유 관계를 별도 JSON 증거 파일에 보존합니다. 의존 관계에서 제외 파일을 참조하면 소유 패키지로 재연결하고 중복 및 자기 참조를 정리합니다. 끊어진 참조나 지원하지 않는 참조 구조는 실패로 처리합니다. 원본 BOM과 앞서 만든 보강본은 변경하지 않습니다.

## 실행

### 파일 없는 APK 가상 패키지 처리

`package-view-v2`는 `--apk-installed`를 추가하면 활성화됩니다. 파일 소유 검증에 사용한 APK DB SHA-256과 대조하고, 이름·버전이 유일하게 일치하는 APK 구성요소 중 `T:virtual meta package`, `S:0`, `I:0`, 소유 파일(`F`/`R`) 부재를 모두 확인한 항목만 제외합니다. 이름의 점 접두사나 라이선스 공백만으로 제외하지 않습니다.

제외한 구성요소 전체, APK DB 필드(의존성 선언 포함), 기존 BOM의 해당 노드 의존성 연결을 `removed_virtual_packages`에 보존합니다. 실제 의존 패키지는 유지합니다. 다른 BOM 노드가 이 묶음을 참조하거나 지원하지 않는 연결 구조가 있으면 묶음을 유지하며, Erlang에 대한 연결을 임의로 만들지 않습니다.

이번 이미지 적용 결과는 36개 → 35개이며 `.erlang-rundeps` 하나가 추가 제외되었습니다. 소유 파일 264개 통합과 미해결 파일 7개 유지는 동일합니다. 결과는 `artifacts/elixir-alpine/normalized-v2-final.cdx.json`, 증적은 `normalization-v2-final-evidence.json` 및 `submission-v2-reviewed/`에 있습니다. 기존 원본·정규화본·증적 묶음은 보존했고, 이 결과는 기존 DT 프로젝트에 업로드해 COMPLETED를 확인했습니다. API 전체 조회 결과 35개, 이름·버전 집합 일치, `.erlang-rundeps` 부재, Elixir·Erlang 유지와 ca-certificates/libgcc의 SPDX 식 보존을 확인했습니다. 업로드·검증 응답은 `artifacts/elixir-alpine/normalized-v2-upload/`에 보존했고 UI는 직접 검사하지 않았습니다. 전체 테스트 17개 통과 및 증적 생성 시 정규화 재실행·해시 대조를 확인했습니다.

재실행은 아래 명령에 `--apk-installed artifacts/elixir-alpine/apk-installed.txt`를 추가하고, DB 해시를 포함하는 `ownership-with-db.json`을 소유 보고서로 사용합니다. 새 출력 경로를 지정하여 기존 증적을 보존합니다.

```sh
python3 scripts/normalize_syft_bom.py \
  --sbom artifacts/elixir-alpine/sbom.cdx.json \
  --ownership artifacts/elixir-alpine/enrichment-v2-report.json \
  --output artifacts/elixir-alpine/normalized.cdx.json \
  --evidence artifacts/elixir-alpine/normalization-evidence.json
```

## 검증 결과

- 원본 300개 → 정규화본 36개.
- 패키지·애플리케이션·OS 29개와 미해결 파일 7개 유지.
- 패키지 소유 파일 264개를 증거 파일로 분리. 원본 구성요소의 누락 없는 보존 확인.
- BusyBox 패키지는 유지하고 `/bin/busybox`와 `ca-certificates.list` 등 연결된 파일은 DT 목록에서 제외.
- Elixir/Erlang 애플리케이션 유지.
- 기존 DT 프로젝트 업데이트 COMPLETED, 서버 전체 구성요소 36개와 정규화본 이름 집합 일치 확인. UI 자체는 검사하지 않았음.
- 테스트 전체 12개 통과. 원본 불변, 정규화 반복 동일성, 관계 재연결, 미확인·충돌 파일 유지, 끊어진 참조 거부 검증.

원본·보강본·정규화본·증거 파일·서버 응답은 Git 제외 artifacts에 남습니다. DT에 파일이 없더라도 납품물에서 그 파일이 제거된 것은 아닙니다. 패키지 수준의 라이선스 관리는 유지되고 파일 증거에서 추적할 수 있습니다. 미해결 파일의 추가 조사와 라이선스 의무 이행은 별도 후속 작업입니다. SQLite 기록 저장 및 마이그레이션은 아직 구현하지 않았습니다.
