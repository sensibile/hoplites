# 요청한 정보 보강의 완료 검증

이 검사는 담당자가 요청한 표준 BOM 정보와 근거·불확실성을 함께 판단하기 위한 것이다. 저장값 일치, 속성 추가, 업로드 성공을 정보 보강 완료로 바꾸지 않는다. 검증 결과는 요청 범위의 보강 완료, 부분 완료, 검증 실패로 나뉜다. 라이선스 법적 판단과 실제 의무 이행은 별도다.

## 실행

`worktrees/node-image-validation` 작업 디렉터리에서 실행하는 예다. 입력과 출력은 실제 검토 대상 파일로 지정하고 새 계약·보고서 경로를 사용한다. 원본과 이전 결과를 덮어쓰지 않는다.

```sh
python3 scripts/validate_enrichment.py init \
  --before artifacts/license-scope-fixed-node-001/normalized.cdx.json \
  --bom artifacts/license-scope-fixed-node-002/normalized.cdx.json \
  --contract /private/tmp/node-enrichment-contract.json \
  --fields licenses
```

생성된 계약은 초안이며 대상 필드 전부가 unreviewed다. 목적의 consumer/decision/required_output, 검토 범위, 필드별 조사 결과를 작성한다. 값은 표준 필드와 정확히 일치해야 한다. 근거 파일은 `--evidence-root` 내부 상대 경로와 SHA-256, 무엇을 뒷받침하는지 설명하는 supports를 기록한다. 확인됨과 추정됨 모두 표준 필드에 실제 값이 필요하다. 추정값은 rationale/limitations/use_risk가 필요하다. **추정값이라는 이유로 실패시키거나 빈칸으로 되돌리지 않는다.**

미해결에는 finding/evidence/attempts/remaining_problem/next_action이 필요하다. 알려진 처리 방법이 있는데 실행하지 않았다면 known_processing_available=true와 미실행 사실을 기록한다. 이를 미해결이라는 설명만으로 완료 처리할 수 없다. 초안 필드를 조사 없이 확인됨으로 바꾸면 안 된다.

```sh
python3 scripts/validate_enrichment.py check \
  --before artifacts/license-scope-fixed-node-001/normalized.cdx.json \
  --bom artifacts/license-scope-fixed-node-002/normalized.cdx.json \
  --contract /private/tmp/node-enrichment-contract.json \
  --evidence-root artifacts/license-scope-fixed-node-002 \
  --report /private/tmp/node-enrichment-review.json
```

종료 코드 0은 계약에 명시한 보강 범위의 검사를 통과한 것, 1은 부분 완료, 2는 검증 실패다. 계약의 claim=complete인데 미해결이나 오류가 있으면 false-completion-claim으로 실패한다. 부분 완료 결과는 조사용으로 보존·업로드할 수 있지만 요청 범위 전체의 보강 완료라고 보고할 수 없다.

## 검사하는 내용

* 입력·출력 SHA-256과 목적·요청 필드·대상 범위를 고정한다.
* 범위 내 모든 출력 대상에 필드별 평가를 요구한다. 원본 관리 대상이 삭제되거나 매핑에서 빠지면 실패한다. 제외는 이유와 실제 근거 파일이 필요하다.
* 표준 필드가 비어 있는데 근거 속성만 있거나, 평가값과 실제 값이 다르거나, 해시를 라이선스 이름으로 쓰면 실패한다.
* 근거 파일의 존재·해시, 추정 근거·한계·사용 위험, 미해결 조사·다음 조치를 검사한다. 파일 누락·변조와 중복 평가도 실패한다.
* license_coverage=delivered-artifact이면 포함 코드의 미확인 범위도 미해결로 남긴다. 본체 MIT 하나로 번들 전체가 완료됐다고 할 수 없다. 프로젝트 선언만 요청한 경우에만 project-declaration을 선택한다. 결과를 통과시키려고 요청 범위를 줄이면 안 된다.

## 자동 경로와 한계

이미지 파이프라인 제출 번들에는 `enrichment-validation.json`이 자동 포함된다. 검토 계약 없이 실행한 경우 보강 완료는 항상 false다. 파이프라인 summary의 status는 execution-completed로 실행 완료만 나타내며 enrichment_status/enrichment_complete를 별도로 기록한다. 검토한 계약으로 생성한 별도 보고서를 보강 완료 판단의 근거로 제출한다. 기존 DT 개수·식별·해시·저장값 검증은 계속 별도로 수행한다.

기계 검사는 조사 기록의 구조, 표준 필드 반영, 대상 누락, 근거 연결과 변조, 완료 주장의 모순을 검사한다. 근거 설명의 사실성, SPDX 해석, 바이너리의 실제 적용 조건, 계약 범위가 사용자의 요청에 맞는지는 담당자 검토가 필요하다. 사람이 사실을 확인하지 않고 계약을 채워 넣는 일을 스크립트가 증명하거나 막을 수는 없다. 이 통과를 법적 타당성이나 이행 완료로 확대하지 않는다.
