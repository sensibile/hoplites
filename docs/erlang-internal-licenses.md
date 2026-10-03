# Erlang/OTP 내부 라이선스 매핑

2026-10-03. 기존 `codex/project-skeleton` 작업 트리에서 규칙 `erlang-internal-licenses-v1`을 적용했습니다. 이전의 주 라이선스 Apache-2.0 보강에 내부 코드 선언을 추가한 결과입니다.

## 조사 근거

이미지 빌드 이력의 공식 `otp_src_28.5.0.7.tar.gz`를 확보했고 SHA-256 `ddf17db6d3e9b7a7cfac0d72238ddc8ea040fedc5e3dfad82fc90675319d6c93`과 일치했습니다. 소스 커밋은 `09fb046150ab94104e03ee816b95c8b7e6b04683`입니다. rootfs의 OTP_VERSION은 28.5.0.7이며 앱별 설치 경로·파일 목록·해시를 대조했습니다.

소스의 주석에 있는 SPDX 선언을 수집하고 앱별 직접 설치 경로 및 `.erl`→`.beam`, ASN.1 집합 생성 등의 매핑을 적용했습니다. 추가 라이선스 선언이 있는 소스 354개가 설치 항목과 연결됐습니다. 그중 설치 파일 69개는 원문과 바이트가 일치했고, 나머지 컴파일·변환 연결은 추정입니다. 별도 파일로 매핑하지 못한 선언 312개도 보고서에 보존했습니다. 이 수치에는 별도 네이티브 규칙으로 평가한 소스가 포함될 수 있으므로 312개 전체를 이미지 미포함으로 단정하지 않습니다.

## 적용한 라이선스 범위

| 포함 코드 사례 | 소스 선언/적용 식 | 확인 방식 |
| --- | --- | --- |
| eldap 및 common_test jQuery | MIT | 설치 모듈/자산 대조, 일부 파일 해시 일치 |
| eunit, edoc, syntax_tools | Apache-2.0 OR LGPL-2.1-or-later | 버전 소스 선언과 설치 항목 연결 |
| parsetools 등의 일부 코드 | BSD-2-Clause | 설치 파일/모듈 대조 |
| wx 생성 모듈, gl/glu | Apache-2.0 AND LicenseRef-scancode-wxwindows-free-doc-3 / SGI-B-2.0 | 생성 모듈 설치 경로 대조 |
| SNMP MIB와 public_key ASN.1 | LicenseRef-IETF-MIB, LicenseRef-RSA-PKCS3, LicenseRef-RSA-PKCS5v2-0 | 직접 MIB 및 PKCS/PKCS-FRAME 모듈 매핑 |
| PCRE2 | BSD-3-Clause WITH PCRE2-exception | 소스 LICENCE·빌드 규칙·BEAM 문자열에 근거한 포함 추정 |
| AsmJit, zlib | Zlib | 소스 선언·빌드 규칙·BEAM 문자열에 근거한 포함 추정 |
| Zstandard | BSD-3-Clause OR GPL-2.0-only | 소스의 선택 가능 선언 및 바이너리 연결 추정 |
| Ryu 및 formatting adapter | Apache-2.0 OR BSL-1.0 / Apache-2.0 WITH LLVM-exception AND BSL-1.0 | 소스 선언 및 빌드/바이너리 연결 추정 |

각 코드의 식을 괄호로 보존한 AND 집합을 부모 Erlang 구성요소의 표준 `licenses[].expression`에 반영했습니다. 이는 포함 코드들의 라이선스 집합이며 Erlang 전체를 새 라이선스로 재지정한 것이 아닙니다. OR 선택지를 임의로 선택하지 않았고 WITH 예외를 보존했습니다. 별도 하위 구성요소를 만들어 부모와 중복 집계하지 않아 구성요소 수는 28개입니다. 하위 단위 상세 정보는 보고서·CSV·HTML에서 제공합니다.

## 미확정 항목 처리

Megaco의 `MEDIA-GATEWAY-CONTROL-v1/v2/v3.asn`은 공식 소스 자체가 `SPDX-License-Identifier: NOASSERTION`이며 적절한 저작권 고지가 알려지지 않았다고 설명합니다. 설치된 BER/PER 생성 모듈과 연결되는 이 3개 소스를 누락하지 않았습니다.

표준 식에 `LicenseRef-OTP-Megaco-Unresolved`를 넣고, 속성과 보고서에 **미확정 추적 표식이지 확인된 라이선스가 아님**을 명시했습니다. 저작권·라이선스 원문을 새로 만들어 넣지 않았습니다. 실제 적용 조건은 IETF/ITU 유래 ASN.1의 조건을 업스트림 또는 컴플라이언스 검토로 확인해야 합니다. 따라서 이번 매핑·BOM 반영 작업은 끝났지만 전체 라이선스 확정이나 의무 이행 완료라고 주장하지 않습니다.

## 재사용과 실행

`migrations/0001_erlang_license_rules.sql`은 버전·정확한 소스 아카이브 해시와 검토한 네이티브 규칙 6개를 저장합니다. Python 스크립트는 이 마이그레이션을 메모리 SQLite에 적용해 규칙을 읽습니다. 캐시된 소스와 rootfs를 사용하며 반복 실행에는 외부 조회가 필요 없습니다. 규칙 적용의 소스 해시·버전·바이너리 조건이 달라지면 실패시켜 새 조사로 연결합니다. 이미지별 실행 이력을 영속 DB에 저장하는 기능은 아직 구현하지 않았습니다.

```sh
python3 scripts/audit_erlang_licenses.py \
  --sbom artifacts/elixir-alpine/normalized-platform-v1.cdx.json \
  --source artifacts/elixir-alpine/otp_src_28.5.0.7.tar.gz \
  --rootfs artifacts/elixir-alpine/rootfs.tar \
  --output artifacts/elixir-alpine/normalized-erlang-audit-final.cdx.json \
  --evidence artifacts/elixir-alpine/erlang-audit-final-evidence.json \
  --notices-dir artifacts/elixir-alpine/erlang-notice-sources-final
```

출력 경로는 새 경로여야 합니다. 원본·이전 BOM은 보존했습니다. 같은 설치 파일에 연결된 upstream 선언을 재사용하는 자동화이며 임의 바이너리의 모든 저작권을 발견하는 범용 엔진은 아닙니다.

## 검증과 증적

테스트 28개 통과. SPDX 주석 추출, 식·예외 보존, 정확한 파일 매칭과 컴파일 추정 구분, 소스 테스트 항목의 미매핑, NOASSERTION 누락 방지, 버전·기존 라이선스 충돌·네이티브 조건 불일치 거부, 입력 불변 및 반복 동일성을 확인했습니다. 실제 캐시로 재실행해 BOM·보고서·원문 추출 결과를 대조했습니다.

DT 기존 프로젝트 업로드 COMPLETED. 전체 28개 이름·버전 집합 유지, 다른 구성요소의 라이선스 보존 및 Erlang 전체 식·미확정 속성 저장을 API로 확인했습니다. UI는 직접 검사하지 않았습니다. 응답은 `erlang-audit-final-upload/`에 있습니다.

확장 증적 `submission-erlang-final/`은 기존 증적, 이번 BOM·보고서, 라이선스·예외 원문, 소스 저작권 고지, SQL 규칙·스크립트, 매핑 CSV·HTML과 DT 검증 응답을 포함합니다. 공식 SPDX 데이터도 고정 커밋으로 캐시했습니다. 원본 소스/rootfs 아카이브는 별도 보존하며 SHA-256을 기록했습니다. 실제 납품 고지는 `NOTICE-PREPARATION.md`와 원문을 사용해 준비할 수 있지만, 수신자에게 고지를 배포하거나 의무 이행을 확인한 상태는 아닙니다.
