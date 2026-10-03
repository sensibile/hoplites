# 배포판 패치를 반영하는 VEX 첫 실험

2026-10-03. Temurin/Ubuntu 정규화 프로젝트의 `gnupg 2.4.4-2ubuntu17.6`에서 DT가 NVD 3건을 매칭했다. Syft의 일반 upstream CPE가 출발점이고, Trivy BOM에는 같은 패키지의 CPE가 없어 DT 결과가 달랐다. BOM 생성기의 검출 능력이나 CVE 숫자만으로 실제 취약성을 비교할 수 없다.

## 판정 범위

이미지 digest와 원본 SBOM/CPE는 유지한다. 추가 VEX는 정확히 Ubuntu 24.04 / 소스 패키지 gnupg2 / 바이너리 gnupg / 설치 버전 `2.4.4-2ubuntu17.6`을 검토한 판정이다. 런타임 공격 재현으로 확인한 결과가 아니라, dpkg 상태와 Ubuntu 공식 보안 권고를 대조한 판정이다.

| CVE | Ubuntu 공식 상태 | VEX |
|---|---|---|
| CVE-2025-30258 | Fixed `2.4.4-2ubuntu17.2` | `resolved` |
| CVE-2025-68973 | Fixed `2.4.4-2ubuntu17.4` | `resolved` |
| CVE-2025-68972 | Not affected, upstream/Ubuntu 보안 이슈 분류 판단 | `not_affected` |

두 fixed 버전은 동일 Ubuntu 패키징 브랜치에서 검토 대상 `.6`보다 앞선다. 이번 엔진은 일반 버전 비교기를 구현하지 않고 **검토한 정확한 `.6`만 허용**한다. 다른 설치 버전·배포판·소스 패키지·CVE로 자동 확장하지 않는다. 검출이 없다는 이유로 안전 판정을 만들지 않는다. 원문에 없는 VEX justification은 넣지 않는다.

## 구조와 재현

- `migrations/0004_ubuntu_vex_decisions.sql`: 검토한 CVE/배포판/소스/바이너리/정확한 버전, 상태, 수정 버전, URL, 조회 원문 SHA-256, 검토일을 누적한다.
- `scripts/build_distro_vex.py`: DT VEX export와 dpkg 인벤토리를 대조한다. PURL 배포판·패키지·버전, installed 상태, source 필드를 확인하고 일치하는 규칙만 적용한다. 공식 HTML의 SHA-256 및 noble 상태 문구를 확인한다. HTML 해시 확인은 검토된 snapshot의 일관성 확인이며 자동으로 새로운 권고를 해석하는 기능이 아니다.
- CycloneDX 1.5: 현재 DT export와 동일한 규격. 해당 컴포넌트만 `affects`에 포함하며, 다른 컴포넌트의 같은 CVE에 판정을 전파하지 않는다. 원래 NVD 정보와 severity는 유지한다.
- 일치하는 규칙이 없는 검출은 sidecar `unresolved`로 남긴다. 현재 export의 나머지 30건은 이번 실험에서 판정하지 않았다.
- 판정 원문, 기존 export, 출력 VEX, 결정 기록은 `artifacts/temurin21-noble/vex-gnupg/`에 보존한다. artifacts는 gitignore 대상이다.

```sh
python3 scripts/build_distro_vex.py \
  --export artifacts/temurin21-noble/vex-gnupg/before-vex.json \
  --status artifacts/temurin21-noble/rootfs-evidence/var/lib/dpkg/status \
  --sources artifacts/temurin21-noble/vex-gnupg \
  --output artifacts/temurin21-noble/vex-gnupg/gnupg.vex.json \
  --evidence artifacts/temurin21-noble/vex-gnupg/decisions.json
```

출력이 이미 존재하면 새 파일명을 사용한다. DT에는 `PUT /api/v1/vex`로 project UUID와 base64 VEX를 전달한다. API 키는 macOS Keychain에서 실행 중 읽고 출력·소스·인자에 기록하지 않는다.

## 현재 반영 상태

VEX 3건 생성과 테스트 36개 통과. 처음에는 API 키의 권한 부족으로 HTTP 403이 발생했으며, 사용자가 `VULNERABILITY_ANALYSIS_UPDATE` 권한을 추가한 뒤 업로드했다. 이벤트 `COMPLETED`와 실제 분석 상태를 확인했다.

- CVE-2025-30258 / CVE-2025-68973: `RESOLVED`.
- CVE-2025-68972: `NOT_AFFECTED`.
- 3건 모두 `isSuppressed=true`, Ubuntu 근거 URL·원문 SHA-256·검토한 설치 버전이 analysisDetails에 반영됐다.
- 감사 이력에 `CycloneDX VEX`가 기록됐다. 기존 CPE·패키지 버전은 그대로 유지된다.
- `gnupg` 활성 findings 0건, suppressed를 포함한 조회에서 원래 3건이 보존된다. DT의 `suppressed=true` 조회는 suppressed만 반환하지 않고 포함해서 반환하므로 컴포넌트 UUID와 분석 상태를 함께 확인했다.
- 즉시 조회한 metrics는 예전 3건이 남아 있었다. component/project metrics refresh 요청 후 `gnupg vulnerabilities=0, suppressed=3, inheritedRiskScore=0`을 확인했다. 프로젝트 전체는 활성 30건/suppressed 3건이다. 나머지 30건은 이번 판정 대상이 아니며 해결됐다고 주장하지 않는다.
- UI는 직접 확인하지 않았다. API 검증 결과는 `vex-gnupg/dt-apply-v1/`의 before/after, metrics, 재수출 VEX 파일로 보존한다.

`apply_dtrack_vex.py`는 분석 이력이 없는 기존 finding의 analysis GET 404를 미작성 상태로 처리한다. 컴포넌트·프로젝트·기존 취약점이 실제로 있는지 먼저 별도로 확인하며 다른 API의 404나 권한 오류를 숨기지 않는다. 현재 스크립트는 판정·근거·suppression 검증까지 수행하고, metrics refresh는 이번 실행에서 별도 API 호출로 수행했다.

## 재검토

이미지/패키지/배포판 버전 변경, 권고 내용 변경, 정해진 재검토 기한에는 규칙을 다시 검토한다. 미래의 자동 재검토·기한 만료·판정 철회/DT suppression 해제는 아직 구현하지 않았다. 현재 SQL에 기록한 조회일만으로 권고의 최신성을 보장하지 않는다. VEX importer가 기존 audit와 suppression을 변경할 수 있으므로 원본 export 및 API 분석 trail을 보존하고, 철회는 새 판정과 suppression 해제로 추적한다.

공식 근거: [Ubuntu CVE-2025-30258](https://ubuntu.com/security/CVE-2025-30258), [CVE-2025-68973](https://ubuntu.com/security/CVE-2025-68973), [CVE-2025-68972](https://ubuntu.com/security/CVE-2025-68972), [DT VEX import](https://dependencytrack.github.io/docs/next/reference/vex-and-vdr/), [Trivy 배포판 권고 선택](https://trivy.dev/docs/latest/guide/scanner/vulnerability/).

권한 추가 후 다음 명령으로 업로드 및 각 분석의 반영 여부를 검증할 수 있다. 실행 전 컴포넌트·프로젝트·기존 finding 식별자가 일치하는지 확인하며, 새로운 출력 폴더에 변경 전후 기록을 남긴다.

```sh
python3 scripts/apply_dtrack_vex.py \
  --vex artifacts/temurin21-noble/vex-gnupg/gnupg.vex.json \
  --project c255977f-69be-47da-af19-04daad1ec269 \
  --output-dir artifacts/temurin21-noble/vex-gnupg/dt-apply-v1
```

## 전체 범위 확장

후속 실행에서 [이미지 전체 VEX 처리](project-vex.md)로 확대했다. 기존 3건을 포함한 전체 33건을 평가했고, OpenSSL의 추가 30건은 Ubuntu 패치 근거로 resolved 반영했다. 최종 DT active=0/suppressed=33이다. 기존 exact-version SQL 판정은 명시적 웹 근거를 보존하는 예외 규칙으로 유지하며, 일반 패키지 버전 범위는 고정 Ubuntu OSV snapshot과 Debian 비교기로 평가한다.
