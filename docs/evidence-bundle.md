# 정규화 제출 증적

`scripts/build_evidence_bundle.py`로 원본 BOM, 정규화 BOM, 소유 보고서, 통합 증거, rootfs를 입력받아 증적 디렉터리를 생성합니다. 기존 디렉터리는 덮어쓰지 않습니다.

```sh
python3 scripts/build_evidence_bundle.py \
  --original artifacts/elixir-alpine/sbom.cdx.json \
  --normalized artifacts/elixir-alpine/normalized.cdx.json \
  --ownership artifacts/elixir-alpine/enrichment-v2-report.json \
  --evidence artifacts/elixir-alpine/normalization-evidence.json \
  --rootfs artifacts/elixir-alpine/rootfs.tar \
  --output-dir artifacts/elixir-alpine/submission-v1
```

CSV·HTML은 통합 파일 264개의 경로·해시·원본 bom-ref·소유 패키지·버전·선언 라이선스·근거 DB 해시를 표시합니다. JSON은 전체 원본 항목과 소유 보고서를 보존합니다. 원본과 정규화본 및 소유 보고서 해시를 검사하고 정규화 규칙을 재실행해 일치 여부를 확인합니다.

manifest는 묶음 안 파일의 SHA-256과 생성 시각, 이미지·도구·규칙 정보를 기록합니다. 정규화 수행 시각은 과거 실행에서 기록하지 않아 소급해서 만들어 넣지 않습니다. rootfs의 출처를 독립 인증하거나 개별 파일 hash 검증을 이 묶음 생성 단계에서 재실행하지 않습니다. rootfs 해시와 APK DB 사본을 보관하며 원래 rootfs도 별도로 보존해야 전체 검증을 재현할 수 있습니다.

파일 통합은 실제 납품물에서 삭제하거나 라이선스 의무를 제외한 것이 아닙니다. 제출처 수용을 보장하지 않으며 별도의 서명·법률 검토·의무 이행 증거가 필요할 수 있습니다. 공개 이미지 실험 증적이며 회사 자료를 외부 제출할 때는 데이터 범위를 별도 확인합니다.

결정 배경: [ADR 0003](adr/0003-normalization-evidence.md).
