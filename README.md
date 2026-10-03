# Hoplites

아티팩트와 SBOM, 보안 검사 결과, 라이선스 의무 이행 증거를 연결하는 배포 관리 시스템을 목표로 합니다. 현재는 아티팩트-SBOM 연결과 생성 도구 비교를 검증합니다.

Remote: https://github.com/sensibile/hoplites

현재 첫 목표는 아티팩트와 SBOM을 정확히 연결하는 것입니다. 로컬 Dependency-Track과 이미지 정규화 파이프라인을 준비했습니다. 이미지 입력에서 Syft/rootfs 수집, BOM 보강·제출 증적, 옵션 DT 업로드·Ubuntu VEX까지 연결합니다. 미해결 항목은 결과에 유지합니다.

```sh
python3 scripts/image_pipeline.py eclipse-temurin:21-jre-noble --upload --vex
```

[처음 실행하는 사용 가이드](docs/usage-guide.md)와 [이미지 CLI 설계·규칙 확장](docs/image-pipeline.md)를 참고하세요.

## 점검 범위

| 영역 | 후보 도구 | 수집할 증거 |
| --- | --- | --- |
| SAST | Semgrep / CodeQL | 코드 위치, 규칙, 진단 |
| SBOM | Syft | 구성요소, 버전, 식별자 |
| CVE / SCA | Grype / Trivy | 취약점, 영향 버전, 수정 정보 |
| 의존성 지속 관리 | Dependency-Track | 프로젝트별 SBOM, 취약점 추적, 라이선스 정책 |
| 라이선스 | Grant / ORT | 발견한 라이선스와 정책 위반 |
| Secret | Gitleaks | 위치와 규칙; 비밀 값은 저장하지 않음 |
| IaC | Checkov / KICS | 설정 위치와 규칙 위반 |
| Dockerfile | Hadolint | 파일 위치와 진단 |
| Kubernetes | Kubescape / Kube-bench | 구성 및 환경 점검 결과 |
| 서명 / Provenance | Cosign | 검증 대상, 신뢰 조건, 검증 결과 |

후보 도구 모두를 동시에 도입하지 않습니다. 버전, 라이선스, 실행 권한, 지원 형식은 각 어댑터 구현 전에 공식 문서로 확인합니다.

## 문서

- [개발 작업 설정과 검사 절차](docs/development-workflow.md)
- [사용 가이드: 준비부터 결과 확인·새 이미지 추가까지](docs/usage-guide.md)
- [새 이미지 처리의 필수 순서와 완료 기준](docs/image-processing-workflow.md)
- [이미지 파이프라인](docs/image-pipeline.md)
- [전체 범위 VEX](docs/project-vex.md)
- [ADR 결정 기록](docs/adr/README.md)
- [정규화 제출 증적](docs/evidence-bundle.md)

- [Dependency-Track 로컬 실행](deploy/dependency-track/README.md)
- [OrbStack Kubernetes 배포 구성](deploy/dependency-track/k8s/README.md)
- [프로젝트 방향과 언어 기준](docs/project-direction.md)
- [SBOM 도구 비교 기준과 첫 실험](docs/sbom-comparison.md)
- [Alpine SBOM 보강 실험](docs/sbom-enrichment.md)
- [DT용 BOM 정규화](docs/sbom-normalization.md)
- [설계](docs/design.md)
- [첫 구현 범위와 완료 기준](docs/first-slice.md)
- [결과 계약](contracts/README.md)
- [Dependency-Track 검토](docs/dependency-track.md)

## 저장소 구조

- `adapters/`: 도구 실행 및 결과 변환
- `contracts/`: 실행 기록, 발견 항목, 산출물 계약
- `policies/`: 결정론적 판정 정책
- `fixtures/`: 합성 입력과 도구 출력 샘플
- `tests/`: 계약 및 실행 검증

웹앱·서버는 Elixir, 복잡한 CLI는 Rust, 스크립트로 충분한 작업은 Python을 사용합니다. 패키징과 CI 실행 환경은 아직 결정하지 않았습니다.
