# Acropolis·Hoplites 첫 사이클 공동 검증

## 결론과 범위

2026-10-04 BOSS의 “논의 해서 공동 검증 완료까지 진행해줘” 요청으로 두 담당 채팅이 실제 서비스와 소비자 증거를 대조했다. 로컬 인증 서비스의 첫 적재·조회·receipt·버전 보존·보고서 재현 계약에 대한 양쪽 검사는 PASS이며 불일치는 없었다. 이 문서의 내용과 동일 코드·근거 범위에 대해 제공자 측 최종 확인까지 받았다. 합의한 한정 범위의 공동 검증은 완료다.

## 검증 대상 고정

| 대상 | 값 |
| --- | --- |
| tenant / principal | hoplites / hoplites-service |
| 실제 서비스 | 로컬 loopback의 Hoplites 지식 HTTP endpoint |
| 소비자 구현 SHA | f74a720aab40786be61be0957b23d8411aae4a93 |
| 제공자 HEAD | 0a35902b18f7a27c9aff4b85dc610c92f21a4d71 |
| 제공자 미커밋 변경 fingerprint SHA-256 | 2a3726cd5363dbd774ce63da671b674ec53b549e3aeedcf922d3f7f5a4a0dfa7 |
| 적재 기준 / 결과 | expected_version=1 / version=2, changed=true |
| 요청 ID | hoplites-416c16172dfde4d81d7ff44401038307918bc48705d1710ac45d2bf8590141f0 |
| 버전 1 / 2 기록 수 | 3 / 7 |
| 보고서 JSON SHA-256 | 55f8446bcafbb2720400f9ab8e3f3b4841df15e53585cfc499decd031fcdf3ed |
| 소비자 관찰 | 2026-10-04 13:45:04 KST |
| 제공자 관찰 | 2026-10-04 13:46:14 KST |

제공자 코드는 미커밋 상태다. HEAD만으로 구현 범위를 식별하지 않고 HEAD·Git 상태/patch hash·변경 tracked/untracked 파일별 hash를 함께 보존한다. 소비자도 검증한 실행 코드의 파일별 hash를 보존했다. 제공자 fingerprint를 소비자 쪽에서 재계산하고 해당 파일들의 현재 hash를 대조했다. 이력 파일은 실행자의 진술과 자료 일치 증거이며 인증 토큰이나 암호학적 실행 증명이 아니다.

## 양쪽 대조

소비자 담당은 입력 BOM·scope·rootfs의 실제 SHA-256을 다시 계산했다. 현재 서비스의 버전 1·2와 receipt를 읽고, 저장된 소비자 응답 및 보고서 JSON·최종 HTML을 재현했다. 제공자 담당은 같은 요청과 bundle을 읽고 버전 1 그래프에 Put/Link 연산을 독립적으로 적용해 버전 2 그래프와 일치함을 확인했다. HTML 재현은 소비자 renderer를 사용했으며 독립 법률 판단이나 독립 renderer 검증으로 표현하지 않는다.

| 공동 확인 항목 | 관찰 |
| --- | --- |
| 기존 버전 1 보존 | 최초 제공자 조회와 동일 |
| 실제 버전 2·history | 소비자 저장 응답과 동일 |
| 요청·receipt·쓰기 결과 | request_id, expected_version, operations, version, changed 정확히 일치 |
| 버전 1 + 실제 요청의 독립 재구성 | 버전 2 records/links와 동일 |
| 적재 bundle과 commit 연산 | 동일 |
| 보고서 JSON·최종 HTML | 같은 버전에서 bytes 재현 |
| 미인증·교차 tenant get/history/apply | 각각 403 |
| 거부된 쓰기 이후 현재 버전·history | 그대로 유지 |

제공자 대조는 18항목 PASS다. 소비자가 앞서 별도 private 임시 서비스/DB에서 실행한 6항목 실제 HTTP/RocksDB 검사에는 두 실제 tenant, 후속 버전 후 과거 보고서 보존, 최초 요청 재전달, 권한 철회와 실패 보존이 포함된다. 실제 공유 서비스의 교차 tenant 거부와 임시 두 tenant 충돌 시험을 같은 관찰로 합쳐 표현하지 않는다. 공동 대조 중 성공하는 새 쓰기나 기존 데이터 변경은 수행하지 않았다.

## 증거 위치

소비자 worktree는 `/private/tmp/hoplites-acropolis-consumer-cycle`, 제공자 worktree는 `/private/tmp/acropolis-knowledge-evidence-cycle/akashic`이다.

* 소비자 `artifacts/acropolis-joint-verification-001/consumer-recheck.json`: 구현·입력 hash, 재조회·receipt·JSON/HTML 일치.
* 소비자 같은 폴더의 `provider-joint-verification.json`, `provider-provider-fingerprint.json`: 제공자 결과와 fingerprint의 보존본.
* 소비자 같은 폴더의 `joint-summary.json`: 양쪽 동일 식별자·결론·상호 확인 상태.
* 제공자 `artifacts/hoplites-joint-verification-20261004/`: 18항목 결과, fingerprint, 버전 1·2·history와 verify.py.
* 소비자 `artifacts/acropolis-consumer-gcc12-live-001/`: 실제 요청·응답·보고서·6항목 격리 검사와 live 재검증.

구현·업무 분업과 실제 소비자 계약은 [첫 사이클 스펙](akashic-consumer-cycle.md)에 있다. 자격증명은 증거와 문서에 포함하지 않는다.

## 완료에 포함하지 않는 사항

SSO, Axiom 동적 PDP, NAS/운영 장애 내구성, 라이선스의 법률적 적용·이행, 모든 변경·대체·상충 처리의 제품 동작, 제품 UI의 담당자 처리 완료는 검증 범위 밖이다. 이 공동 기능 검증을 Codex Security 또는 독립 코드 리뷰 통과로 간주하지 않는다. 원격 push·PR·merge는 수행하지 않았다.

## 최종 상호 확인

제공자 담당 채팅 `01a104cf-e3fb-7681-80bc-15ed404b0843`이 이 문서와 요약을 읽고 “공동 결론 PASS, 합의한 한정 범위의 공동 검증 완료에 동의합니다”라고 최종 회신했다. 제공자는 현재 제공자 파일별 hash, 소비자 코드별 hash, 결과/fingerprint 보존본 및 snapshot hash를 다시 대조했고 모두 PASS였다. 소비자 담당도 같은 범위와 제외 사항에 동의한다. 원격 전달이나 운영 배포 승인은 요청하거나 수행하지 않았다.

검증한 코드 fingerprint, 요청·입력 hash, 인증·tenant 계약이 달라지면 영향을 받는 항목을 다시 검증한다. 이 완료 기록으로 다른 버전이나 운영 환경의 통과를 추정하지 않는다.
