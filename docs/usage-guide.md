# 이미지 SBOM 정규화 사용 가이드

이미지 이름 하나로 Syft 원본 BOM, 정규화 BOM, 변경·제외 증적을 생성한다. 옵션으로 로컬 Dependency-Track(DT) 업로드와 Ubuntu VEX 판정까지 실행한다. 모든 명령은 저장소 루트에서 실행한다.

## 1. 준비

- Python 3.10 이상. 스크립트는 표준 라이브러리를 사용하므로 별도 pip 설치가 필요 없다.
- 실행 중인 Docker와 `docker buildx`. macOS에서는 OrbStack을 사용할 수 있다.
- 공개 이미지 registry와 버전이 고정된 라이선스·취약점 근거 자료를 내려받을 네트워크.
- 이미지 아카이브, rootfs, 스캐너 캐시를 보관할 디스크 공간. 사용량은 이미지에 따라 달라진다.

```sh
python3 --version
docker info
docker buildx version
python3 scripts/image_pipeline.py --help
```

Syft와 Trivy는 Docker 이미지로 실행한다. 호스트에 따로 설치하지 않는다. 현재 공개 Linux 이미지로 검증했고, private registry 인증 전달은 추가 구현이 필요하다.

### DT 업로드 준비

`--upload`를 쓸 때만 필요하다. [DT 실행 안내](../deploy/dependency-track/README.md)를 따라 서비스를 시작한다. API는 `http://localhost:18080`, UI는 `http://localhost:18081`이다. 현재 CLI의 API 주소는 이 로컬 주소로 고정되어 있다.

DT에서 초기 비밀번호를 변경한 뒤 API 키를 가진 팀에 프로젝트·컴포넌트 조회, BOM 업로드, 프로젝트 자동 생성 권한을 부여한다. `--vex`로 분석 상태를 반영하려면 `VULNERABILITY_ANALYSIS_UPDATE` 권한도 필요하다.

현재 업로드 구현은 macOS Keychain을 사용한다. 키체인 접근 앱에서 일반 암호 항목을 만들고 다음 값으로 저장한다.

| 항목 | 값 |
| --- | --- |
| 항목 이름/service | `hoplites-dependency-track` |
| 계정/account | `hoplites` |
| 암호 | DT에서 발급한 API 키 |

키의 존재만 확인할 때는 다음 명령을 사용한다. `-w`를 붙이지 않아 키 값을 출력하지 않는다.

```sh
security find-generic-password -a hoplites -s hoplites-dependency-track >/dev/null
```

API 키는 소스, `.env`, 명령 인자에 넣지 않는다. Linux 등에서는 BOM·증적 생성은 사용할 수 있지만 현재 Keychain 업로드 경로를 대체해야 한다.

## 2. 이미지 하나 처리하기

먼저 업로드 없이 결과를 확인한다.

```sh
python3 scripts/image_pipeline.py eclipse-temurin:21-jre-noble
```

기본 플랫폼은 `linux/arm64`이며 출력은 `artifacts/image-…-<시각>/`에 생성된다. 출력 경로와 플랫폼을 지정할 수도 있다.

```sh
python3 scripts/image_pipeline.py ubuntu:24.04 \
  --platform linux/amd64 \
  --output-dir artifacts/ubuntu-amd64-run-001
```

태그를 입력해도 실제 처리 대상은 플랫폼별 manifest digest로 고정된다. 재현하려면 결과의 `image.json`에 기록된 `image_ref`를 다음 실행의 입력으로 사용한다. 지원하는 플랫폼을 찾지 못하면 실패한다.

기존 출력 디렉터리는 덮어쓰지 않는다. 재실행할 때는 새 경로를 지정하거나 `--output-dir`를 생략한다.

### DT 업로드와 VEX

```sh
python3 scripts/image_pipeline.py eclipse-temurin:21-jre-noble \
  --upload --vex \
  --dt-project hoplites-temurin-arm64
```

`--upload`는 정규화 BOM을 업로드하고 이벤트 완료 뒤 컴포넌트 개수와 식별·라이선스 필드를 API로 확인한다. `--dt-project`는 프로젝트 이름이다. 생략하면 이미지 repository와 architecture에서 이름을 만든다. 프로젝트 버전은 manifest digest이므로 새 이미지 digest는 별도 프로젝트 버전으로 관리된다.

`--vex`는 `--upload`와 함께 사용한다. 현재 Ubuntu advisory 경로를 지원하며 검증된 판정은 DT 분석 상태에 반영된다. 다른 배포판, 근거 부족, 판정 충돌은 미해결로 남긴다. VEX를 생략하면 BOM 업로드까지만 진행한다.

### 새 이미지 실험의 필수 Trivy 비교

```sh
python3 scripts/image_pipeline.py alpine:3.24 --trivy --upload
```

`--trivy`는 취약점·라이선스 검사를 켠 CycloneDX 비교본을 추가한다. 새 이미지·버전 실험에서는 필수로 실행하고 [작업 지침](image-processing-workflow.md)에 따라 결과를 항목 단위로 대조한다. DT에 올라가는 기본 BOM은 정규화한 Syft 결과이다. Trivy의 발견 항목을 DT에 자동 병합하는 기능은 아직 없다.

## 3. 결과 확인과 제출

| 파일/디렉터리 | 확인할 내용 |
| --- | --- |
| `summary.json` | `status`, 원본·정규화 개수, `unresolved`, DT UUID, VEX 처리 요약 |
| `image.json` | 입력 태그, 고정한 digest, 플랫폼 |
| `scanners.json` | 스캐너의 고정 index/플랫폼 manifest digest와 실제 image ID |
| `original.cdx.json` | 변경하지 않은 Syft 원본 |
| `normalized.cdx.json` | 보강·정규화된 DT용 CycloneDX BOM |
| `normalization-evidence.json` | 원본·결과·rootfs 해시, 적용 단계와 미해결 사항 |
| `stages/*-evidence.json` | 단계별 변경·제외 근거 |
| `sources/` | 보강에 사용한 라이선스·copyright·advisory 원문 |
| `dt/verification.json` | DT 이벤트와 업로드 필드 검증 결과; 업로드 시 생성 |
| `vex/` | 취약점 판정과 반영 증적; 지원 경로 실행 시 생성 |
| `submission/` | BOM·근거·규칙·스크립트·제외 CSV·해시 manifest를 모은 제출 번들 |
| `commands.json`, `logs/` | 실행 단계, 종료 코드, 표준 출력·오류 |

```sh
python3 -m json.tool artifacts/ubuntu-amd64-run-001/summary.json
```

`status: execution-completed`는 실행 완료만 뜻한다. 요청한 정보 보강 완료 여부는 `enrichment_status`와 `enrichment_complete`, [보강 완료 검증](enrichment-validation.md)의 검토 보고서로 별도 판단한다. `unresolved`가 남아 있으면 해당 항목의 추가 확인이 필요하다. API 검증과 UI 표시 확인은 별도이며, 특히 SPDX 복합 표현은 DT 화면에 개별 라이선스 링크로 보이지 않을 수 있다.

제출할 때는 `submission/`을 중심으로 사용하고 `excluded-components.csv`와 단계별 근거를 함께 제공한다. 대용량 `rootfs.tar`와 `image-save.tar`는 번들 밖에 보관하며 manifest의 해시로 연결된다. 라이선스 정보 보강과 실제 고지·소스 제공 등 의무 이행은 별도로 관리한다.

## 4. 새 이미지를 추가하며 갱신하기

1. 최신 구현 checkout에서 새 이미지에 같은 CLI를 `--trivy`와 함께 실행한다. 먼저 로컬 결과를 검토하고, Syft/Trivy 항목별 차이와 미해결을 기록한다. 상세 순서와 완료 기준은 [이미지 처리 작업 지침](image-processing-workflow.md)을 따른다.
2. `summary.json`의 `unresolved`와 단계별 근거를 확인한다.
3. 버전·라이선스 원문을 확인하고 URL, commit, SHA-256, 적용 조건을 기록한다.
4. 데이터 규칙은 새 `migrations/NNNN_*.sql`에 추가한다. 기존 마이그레이션은 수정하지 않는다. 패키지 DB나 설치 형태가 다르면 어댑터와 회귀 검증을 추가한다.
5. 새 출력 디렉터리에서 재실행하고 표준 BOM 필드와 제외 증적을 비교한다.
6. 확인한 결과를 `--upload`로 DT에 반영하고 API 검증 결과를 확인한다.

규칙별 누적 위치와 검증 기준은 [파이프라인 설계·확장 안내](image-pipeline.md#새-이미지버전을-추가하는-방법)에 정리했다. 검토된 원문은 `.cache/hoplites/`에 재사용하지만 해시가 바뀐 자료를 자동 승인하지 않는다. 알 수 없는 소유 관계나 미검토 런타임 정보는 결과에 남긴다.

## 5. 실패 시 확인

| 증상 | 다음 확인 |
| --- | --- |
| Docker 연결 실패 | OrbStack/Docker 기동 여부와 `docker info` |
| 출력 디렉터리가 이미 있음 | 새 경로 사용 또는 `--output-dir` 생략 |
| 플랫폼 없음/모호함 | 이미지 지원 플랫폼과 `--platform` 값 |
| 원문 해시 불일치 | 원문 변경·캐시 손상 여부 조사 후 규칙 검토 |
| Keychain 조회 실패 | service/account, 항목 존재 여부와 접근 허용 |
| DT HTTP 403 | 실패 단계에 필요한 팀 권한; VEX는 분석 수정 권한 |
| DT 이벤트 대기 시간 초과 | 서버 상태·이벤트 확인 후 새 실행; 실패만으로 미접수를 단정하지 않음 |
| DT 필드 검증 실패 | `dt/verification.json`의 `mismatches` 및 서버 변환 확인 |

실패한 실행은 `summary.json`의 `error`와 `commands.json`, 해당 `logs/<단계>.stderr`를 먼저 확인한다. 실패 기록을 보존하고 새 출력 경로에서 다시 실행한다.

개발 검증은 저장소 루트에서 실행한다.

```sh
python3 -m unittest discover -s tests -v
```
