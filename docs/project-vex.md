# 이미지 전체 검출의 배포판 VEX 처리

미해결 advisory·identity·배포판 판정은 sidecar뿐 아니라 `in_triage` VEX로도 내보낸다. 재실행에서 근거가 없어졌을 때 이전 DT suppression이 남지 않도록 적용기가 suppression을 명시적으로 해제하고 분석 API로 확인한다. 미해결 내역은 계속 보고서에 유지한다.

2026-10-03. `gnupg` 3건 실험을 Temurin 이미지의 DT 전체 검출로 확장했다. `codex/project-skeleton` 워크트리에서 수행했으며 기존 SBOM 구성요소/CPE는 유지했다.

## 결과

| 항목 | 결과 |
|---|---:|
| SBOM 구성요소 | 139 |
| DT 검출 구성요소 | 2 (gnupg, openssl) |
| 검토한 component–CVE 관계 | 33 |
| resolved | 32 (gnupg 2 + openssl 30) |
| not_affected | 1 (gnupg) |
| 이번 실행의 미해결 / 충돌 | 0 / 0 |
| 최종 DT 활성 검출 / suppressed | 0 / 33 |

OpenSSL 설치 버전 `3.0.13-0ubuntu3.16`을 Ubuntu 공식 OSV의 noble 소스 패키지 범위와 비교했다. 30건의 수정 경계는 `.4`, `.7`, `.9`, `.11`, `.15`였으며 `.16`은 해당 범위 밖이다. 일반 upstream CPE는 배포판 백포트를 반영하지 못할 수 있다. 이름·버전·PURL·CPE 139개가 변경되지 않은 것도 API로 대조했다.

**현재 DT에서 검출된 전체 33건에 대한 배포판 판정 완료다. 이미지의 모든 가능한 취약점을 찾았다거나 안전 인증을 완료했다는 뜻은 아니다.** DT 검출이 없는 나머지 137개는 별도 coverage 기록에서 `no DT finding; not a safety decision`으로 남긴다. VEX는 새로운 components/findings를 생성하지 않으므로 스캐너 탐지 범위의 확대와는 별도다.

## 실행 구조

1. DT에서 suppressed 항목을 포함하는 VEX export를 읽는다.
2. `collect_project_advisories.py`가 모든 CVE의 Ubuntu 공식 OSV JSON을 고정 upstream commit에서 수집한다. `migrations/0005_vex_advisory_cache.sql`로 생성한 로컬 SQLite에 원문·URL·SHA-256·커밋·조회 시점을 보존한다. DB는 재생성 가능한 실행 캐시이며 gitignore된 artifacts 아래에 둔다. 근거 snapshot JSON/index는 제출 증적에 보존한다. 같은 커밋 재실행에서는 33건 모두 캐시를 사용했고 CVE 원문 다운로드가 없었다.
3. `build_project_vex.py`가 rootfs·정규화 증적·BOM 출력 hash와 DT 프로젝트의 이미지 digest를 확인한다. finding의 컴포넌트도 검증된 SBOM 안에 있어야 한다.
4. rootfs dpkg 상태에서 binary/source/version/architecture를 얻는다. Source에 별도 버전이 있으면 소스 버전을 사용하며, 없으면 설치 버전을 사용한다. OS release, PURL의 배포판·이름·버전·아키텍처와 대조한다.
5. Ubuntu OSV의 해당 LTS ecosystem/소스 패키지 ECOSYSTEM 범위를 Debian 버전 규칙으로 평가한다. `introduced`와 배타적인 `fixed`, 여러 재도입 구간을 지원한다. 다른 범위 형식·last_affected/limit·모호한 자료는 미해결로 기록한다. 자료가 없다는 이유로 영향 없음 판정을 만들지 않는다.
6. 정확히 검토한 웹 원문 판정과 machine-readable 결과가 충돌하면 `in_triage`로 전달한다. 미해결은 sidecar에 남기고 안전 판정 VEX에 넣지 않는다. `exploitable`은 vendor range의 affected 상태를 뜻하며 실제 공격 재현을 했다는 뜻이 아니다.
7. `apply_dtrack_vex.py`가 프로젝트/컴포넌트/기존 finding을 확인한 뒤 VEX를 업로드한다. suppressed 포함 조회와 pagination으로 기존 판정도 재검증한다. 판정 상태·상세 근거·suppression을 실제 API에서 확인한다. active/triage 재판정에는 VEX만으로 이전 suppression이 해제되지 않을 수 있어 분석 API로 해제하고 감사 comment를 남긴다. `--refresh-metrics`는 집계 갱신과 snapshot 기록을 요청한다. 집계는 비동기이므로 완료 판단에는 finding 상태 및 새 집계 값 확인도 필요하다.

Ubuntu LTS OSV 어댑터가 현재 구현 범위다. Alpine/RPM/비패키지 런타임은 향후 별도 근거 어댑터를 추가한다. 지원하지 않는 식별·배포판은 미해결이며 자동 제외하지 않는다. 현재 rootfs reader는 이번 Ubuntu 이미지의 dpkg/os-release 경로를 사용한다. 동일 binary name이 여러 architecture에 있으면 PURL의 arch로 선택한다. arch 없이 후보가 여러 개면 미해결로 남긴다.

## 철회된 CVE 기록 처리

CVE-2025-68972는 원문 JSON의 과거 `introduced=0`만 보면 affected처럼 보이지만 `withdrawn`이 있다. 이 필드를 먼저 확인해야 한다. 이번에는 이미 검토한 Ubuntu 웹의 Not affected 판정이 있어서 그 판정을 유지하고 OSV 철회 시점·원문 해시를 추가했다. **withdrawn만으로 무조건 not_affected를 만들지는 않는다.** 별도 명시적 근거가 없으면 미해결이다.

## 재사용 명령

```sh
python3 scripts/run_project_vex.py \
  --project c255977f-69be-47da-af19-04daad1ec269 \
  --sbom artifacts/temurin21-noble/normalized-v2.cdx.json \
  --normalization-evidence artifacts/temurin21-noble/normalization-v2-evidence.json \
  --rootfs artifacts/temurin21-noble/rootfs.tar \
  --reviewed-sources artifacts/temurin21-noble/vex-gnupg \
  --cache artifacts/temurin21-noble/vex-all/advisory-cache.sqlite \
  --output-dir artifacts/temurin21-noble/vex-next \
  --apply
```

`--apply`를 생략하면 수집·판정·증적까지만 생성한다. `--commit <전체 SHA>`를 지정하면 동일 snapshot으로 재현한다. 생략하면 현재 upstream commit을 확인해 새 snapshot을 만든다. 출력 디렉터리는 덮어쓰지 않는다. API 키는 macOS Keychain에서 프로세스 안으로 읽고 저장·출력하지 않으며 외부 공개 자료 요청에 전달하지 않는다.

프로젝트별 export에서 확인된 검출이 전부 재평가 대상이다. 새 패키지 버전/이미지로 기존 판정을 복사하지 않는다. 기존 판정 수동 편집의 우선순위, 장기 유효기한, 근거 불가 시 기존 suppression을 어떻게 철회할지는 후속 정책이며 현재 완전 자동화된 장기 운영 시스템으로 간주하지 않는다.

## 검증·증적

- 테스트 47개 통과: source와 binary 버전 차이, 고정 버전 경계, 재도입 구간, epoch/~ / 숫자 정렬, 잘못된 자료, 다른 architecture, 원문 변조, 철회·충돌·원본 보존.
- 실제 이미지의 dpkg와 196개 버전 조합 대조: 모두 일치.
- 전체 orchestration을 고정 commit으로 재실행: cache hit 33/33, resolved 32/not_affected 1, 미해결 0.
- DT 이벤트 COMPLETED, 33개 판정 상태·상세 근거·suppression 일치. 활성 조회 0개, suppressed 포함 조회 33개를 보존했다. 전체 metrics도 active=0/suppressed=33 확인.
- UI는 직접 확인하지 않았다. 실제 결과는 API로 검증했다.

`artifacts/temurin21-noble/vex-all/`에 원래 검출 export, pinned advisory JSON/index, 결정 기록, 출력 VEX, 변경 전후 analysis/audit/metrics 및 구성요소 대조를 보존한다. 제출용 `submission/`에는 SQLite 바이너리 대신 JSON 원문·SQL schema·규칙·스크립트와 파일 hash manifest를 넣는다. rootfs는 번들 밖에 hash로 연결한다. 원문 다운로드가 실패하거나 해시가 어긋나면 안전 판정으로 처리하지 않는다.

공식 자료: [Canonical Ubuntu OSV 저장소](https://github.com/canonical/ubuntu-security-notices), [DT VEX import](https://dependencytrack.github.io/docs/next/reference/vex-and-vdr/).
