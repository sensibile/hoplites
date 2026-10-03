# Python slim 1차 반영 범위

Python 3.13.16 slim-bookworm, linux/arm64의 정보 보강과 검증 규칙을 재사용 가능한 코드로 반영한다. 전체 라이선스·CVE 적용성·실제 의무 이행 완료는 아니다.

## 반영 내용

- 실제 Python release marker와 pip metadata, hash로 고정한 배포 라이선스 문서를 표준 필드에 반영한다. pip vendor 목록에서 포함 패키지 버전·PURL과 관계를 생성한다.
- Debian copyright의 exact hash/label 매핑을 새 migration으로 누적한다. usrmerge 부모 symlink와 leaf symlink 소유권을 구분하고 제외 대상의 실제 bytes를 확인한다.
- 이미지 source hash, CPython source/notice, 설치 파일과 build metadata를 연결하여 내부 코드의 알려진 라이선스 조건을 반영한다. compiled module의 source 연결은 추정이며 byte 동등성은 미확인이다.
- pip RECORD는 scanner/rootfs hash 및 실제 pip 설치 인벤토리 관계를 확인한 뒤 정규화 BOM에서 제외한다. 원본·sidecar에 파일과 소유 관계를 보존한다. 자기 checksum은 생성하지 않는다.
- 동일 digest Syft/Trivy 비교, 정확한 Debian source version의 CVE 조사와 hash-pinned Debian VEX 경로를 제공한다. 확인된 point release만 허용한다. open/zero/unknown 판정을 suppression하지 않는다.
- DT 업로드 후 전체 pagination의 식별·버전·라이선스·SHA-256 및 개수를 검증한다.

## 관리 대상과 증거

RECORD는 pip 설치 증거로 관리하고 독립 소프트웨어 목록에서 분리한다. Simple Launcher 6개의 관리·표시 단위는 [열린 이슈](open-issues/simple-launcher.md)로 유지한다. 현재 바이너리별 식별자를 보존하며 이름 변경·병합·이미지 삭제는 하지 않는다.

## 검증과 남은 범위

76개 unittest와 포맷·정적 분석·Python 3.10 문법·SQL·문서 링크 검사 및 문서 gate 통합 테스트를 수행했다. 실제 고정 manifest의 재실행과 DT 검증 결과는 실행 산출물에 기록한다. 고정 manifest는 `sha256:110e8d1de526341568b8fcdb1773b0d47ad63309df21980c6028803226a2dab0`이다.

현재까지 canonical 조사 미해결은 Debian 120건과 CPython 4건이다. source 집계와 binary 적용 범위, 완전한 CPython 내부 코드 목록, vendored CVE 실행 조건, 실제 고지·소스 제공 이행은 남아 있다. DT findings 0건은 안전 판정이 아니다. UI 검증은 별도다.

[첫 보완 기록](python-slim-completion.md)과 [후속 조사 기록](python-slim-followup.md)은 이전 코드/산출물의 역사적 기록이다. 각 기록의 125개는 RECORD 제외 전 결과이며 이번 정규화는 124개를 예상한다. 이전 실행과 실패 증적은 원래 worktree에 보존한다. 최신 코드 반영이 그 과거 결과를 다시 생성했다고 해석하지 않는다.
