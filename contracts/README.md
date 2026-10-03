# 결과 계약 초안

구현 전에 JSON Schema와 예제를 확정합니다. 현재 문서는 필드와 의미를 합의하기 위한 초안입니다.

## Run

schema_version, run_id, target(type 및 식별자), tool(name 및 version), options(민감정보 제거), started_at, finished_at, status, exit_code, artifacts, diagnostics.

status는 succeeded / failed / timed_out / skipped입니다. 원본 종료 코드의 의미는 어댑터가 해석합니다. 실행 실패를 발견 항목으로 변환하지 않습니다.

## Finding

finding_id, run_id, category, rule_id, severity, native_severity, message, location, component, references, evidence_ref.

severity는 critical / high / medium / low / info / unknown입니다. 변환 규칙과 원본 값을 보관합니다. 위치나 구성요소가 없는 도구는 해당 필드를 생략할 수 있습니다. 비밀 값은 포함하지 않습니다. finding_id는 실행 내 식별자이며 영구 중복 식별자는 별도 설계합니다.

## Artifact

artifact_id, run_id, kind, path, media_type, sha256.

kind는 sbom / raw_report / verification / execution_log 등을 구분합니다. 원본 출력도 비밀 값 포함 여부를 고려하여 보관해야 합니다. 모든 종류의 산출물을 Finding에 억지로 넣지 않습니다.

## Policy result

policy_version, verdict, reasons, evaluated_run_ids.

verdict는 pass / fail / indeterminate입니다. 필수 실행 누락, 실패, 해석 불가능한 출력은 indeterminate 근거가 됩니다. 명시적으로 확인된 정책 위반은 fail입니다. 위반과 불완전한 실행이 동시에 있으면 fail을 표시하고 불완전성도 reasons에 남깁니다.
