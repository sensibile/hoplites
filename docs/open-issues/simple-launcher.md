# 열린 이슈: Simple Launcher의 관리·표시 단위

- 상태: Open — 처리 방침 미결정
- 기록일: 2026-10-03
- 담당: 미지정
- 범위: pip에 포함된 Windows 런처 바이너리의 BOM 모델과 Dependency-Track 표시

## 문제

DT 구성요소 목록에서 이름 `Simple Launcher`, 버전 `1.1.0.14`, 라이선스 `BSD-2-Clause`가 같은 행 6개가 보인다. BOSS가 제공한 화면에서는 파일명·대상 플랫폼·포함 관계가 드러나지 않아 중복 등록처럼 보이고, 무엇인지 또는 어떤 조치가 필요한지 판단하기 어렵다. 파일별 식별 정보를 보존하는 것만으로 사용자에게 의미가 전달되지는 않는다.

Hoplites의 목적은 배포 아티팩트의 소프트웨어 구성, 보안 위험과 라이선스 의무를 판단할 근거를 제공하는 것이다. 이 사례는 식별 정보가 있어도 관리 단위와 표시 방식이 목적에 맞지 않을 수 있음을 보여준다.

## 확인된 사실과 근거 범위

저장된 Python slim 보강 BOM에서 다음 6개 파일을 확인했다. 모두 `/usr/local/lib/python3.13/site-packages/pip/_vendor/distlib/`에 포함되어 있다.

| 대상 플랫폼 | 콘솔용 | GUI용 |
| --- | --- | --- |
| Windows x86 | t32.exe | w32.exe |
| Windows x64 | t64.exe | w64.exe |
| Windows ARM64 | t64-arm.exe | w64-arm.exe |

- distlib의 Windows 스크립트 실행용 바이너리 리소스다. [공식 API 설명](https://distlib.readthedocs.io/en/stable/reference.html)과 [런처 선택 코드](https://github.com/pypa/distlib/blob/0.4.2/distlib/scripts.py)를 참고한다.
- Syft가 PE 바이너리 각각을 같은 이름·버전의 구성요소로 식별했다. 보강 과정에서 파일명·SHA-256 qualifier를 가진 서로 다른 generic PURL을 부여하여 DT에 별도로 등록했다.
- 서로 다른 소프트웨어 제품 6개가 설치된 것은 아니다. 같은 런처의 대상 플랫폼·실행 방식별 바이너리다. Linux의 일반적인 pip 실행 경로에서는 Windows 런처를 사용하지 않는다. 이미지에는 실제 포함되어 있으므로 포함 사실과 라이선스 근거는 보존해야 한다.
- BOM의 BSD-2-Clause는 고정 distlib 소스 공지에 근거한 추정이다. 각 PE 바이너리와 해당 소스의 재빌드 byte 동등성은 미확인이다. DT 목록의 라이선스 표시는 이 확인 상태를 드러내지 않는다.
- BOSS가 제시한 [DT 구성요소](https://frontend.hoplites-dtrack.orb.local/components/4cf232be-8f30-4492-8162-bcf764bf6770)와 화면을 논의했다. 링크의 상세 화면은 직접 확인하지 못했으며, 현재 DT 상태를 새로 조회한 기록은 아니다.

로컬 근거: worktree `/Users/tonton/Documents/workspace/hoplites/worktrees/python-slim-completion`, branch `codex/python-slim-completion`, HEAD `c03f2545bf860c719ecc5a757eb2a3c1458c0e1e` 및 미커밋 보강 코드. 산출물은 `artifacts/python-slim-followup-final-001/normalized.cdx.json`, `stages/python-shipped-evidence.json`, `dt/verification.json`, `submission-reviewed/manifest.json`이다. 다른 worktree의 gitignored 산출물이며 이 문서와 함께 자동 전달되지 않는다.

대상은 linux/arm64, Python 3.13.16, pip 26.2.1, distlib 0.4.2이며 고정 manifest는 `sha256:110e8d1de526341568b8fcdb1773b0d47ad63309df21980c6028803226a2dab0`이다. PE 표시 버전 `1.1.0.14`와 distlib 패키지 버전 `0.4.2`를 같은 버전으로 취급하지 않는다.

## 열린 질문

1. 런처를 독립 소프트웨어 구성요소로 관리할지, distlib의 포함 바이너리로 연결할지? 제품·패키지·바이너리 변형·파일 occurrence의 경계를 어떻게 정할지?
2. 하나의 런처 아래 6개 변형을 묶을 근거와 표현 방식이 있는지? DT가 파일별 위치·hash·플랫폼·관계와 취약점/라이선스 근거를 보존할 수 있는지?
3. 원본 이름을 유지하면서 정체와 행 간 차이를 목록에서 어떻게 보여줄지? description·포함 관계 보강만으로 충분한지, 표시 이름이나 별도 화면이 필요한지?
4. 포함 사실과 실행 환경에서의 사용 여부를 어떻게 구분할지? Windows 전용이라는 사실을 취약점 적용성·라이선스 검토에 어떻게 연결할지? 미사용만으로 일괄 안전 또는 의무 면제로 판단해서는 안 된다.
5. 유사한 다른 포함 바이너리에도 적용할 수 있는 기준은 무엇인지? 이 사례 하나를 위해 전체 모델을 성급하게 정하지 않는다.

## 검토할 선택지 — 결정 아님

| 선택지 | 이점 | 검토할 비용·조건 |
| --- | --- | --- |
| 6개 구성요소 유지, 목록에서 변형 구분 | 바이너리별 식별 유지 | 반복 행과 사용자 부담이 남으며 DT 목록 표시 지원 확인 필요 |
| 하나의 런처에 6개 변형 연결 | 동일 런처라는 의미 전달 | 그룹화 근거와 변형별 metadata·분석 정보 손실 여부 검증 필요 |
| distlib 아래 포함 바이너리 증거로 연결 | 포함 관계와 패키지 중심 관리 | 런처 고유 버전·라이선스·CVE 식별을 잃지 않는지 검증 필요 |

이미지에서 제거하는 것은 별도 이미지 경량화 결정이다. BOM 표시 문제를 해결하기 위해 실제 포함 코드를 임의로 삭제하지 않는다.

## 현재 처리와 해결 기준

현재는 이름 변경·병합·컴포넌트 제외·이미지 변경을 결정하지 않는다. 기존 원본과 파일별 근거를 보존하고 열린 이슈로 유지한다. 이 문서 저장은 BOM이나 DT 데이터를 변경하지 않는다.

후속 검토에서는 DT의 실제 목록·상세 표시와 BOM 지원 방식을 확인하고 유사 사례를 함께 비교한다. 관리 단위와 표시 정책을 정한 뒤 다음을 검증해야 이슈를 닫을 수 있다.

- 사용자가 목록에서 런처의 정체, pip/distlib 포함 관계와 플랫폼 변형을 이해할 수 있다.
- 파일별 위치·hash·원본 식별자·라이선스 출처·확인 상태와 분석 연결을 추적할 수 있다.
- 불필요한 독립 관리 대상을 줄이면서 실제 포함 소프트웨어를 누락하지 않는다.
- 정책이 재사용 가능한 규칙과 해당 변경의 검증으로 누적된다. 적용했다면 DT 반영 상태와 실제 표시를 재확인한다.

관련 방향: [프로젝트 방향](../project-direction.md), [이미지 처리 지침](../image-processing-workflow.md), [정규화 기준](../sbom-normalization.md).
