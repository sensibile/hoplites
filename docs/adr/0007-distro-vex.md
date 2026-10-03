# ADR-0007: OS 패키지의 배포판 패치 판정을 별도 VEX로 전달

상태: 채택. 2026-10-03.

## 배경

Temurin/Ubuntu의 동일 gnupg 패키지에서 Syft BOM의 일반 CPE로 DT NVD 3건이 매칭됐다. Ubuntu 보안 정보에서는 두 건이 이미 수정됐고 한 건은 영향 없음이다. raw CVE 수만으로 실제 미수정 취약점 수를 판단할 수 없다.

## 결정

구성요소·원본 CPE·전체 설치 버전·원래 검출은 유지한다. 배포판/소스 패키지/바이너리/버전/CVE별 근거로 검토한 판정을 CycloneDX VEX로 전달한다. 엔진은 Python, 규칙은 누적 SQL 마이그레이션, 근거 snapshot과 SHA-256 및 변경 전후 기록은 증적 번들로 보존한다.

초기 규칙은 검토한 정확한 버전만 허용한다. 다른 버전·배포판·미확인 CVE에는 판정을 자동 확장하지 않는다. 원문에 없는 justification이나 실행 경로의 안전성은 만들어 넣지 않는다. 불일치·미해결은 관리 대상으로 계속 남긴다.

## 결과와 제한

DT import 완료와 분석 상태·상세 근거·suppression 실제 반영을 각각 검증한다. CPE 제거 또는 CVE 일괄 숨김으로 대체하지 않는다. 판정 재검토 기한, advisory 갱신, 철회 및 suppression 해제 자동화는 후속 구현이다. 현재 규칙은 배포판 권고를 대조한 평가이며 런타임 공격 테스트가 아니다.

실험 상세 및 현재 업로드 상태는 `../distro-vex.md`에 기록한다.

## 2026-10-03 확장

DT export의 전체 component–CVE 관계를 순회하고 고정 Canonical OSV snapshot을 캐시하여 평가한다. binary/source 버전을 구분하고 Debian 버전 순서를 사용한다. 철회된 원문은 활성 범위로 평가하지 않으며 명시적 별도 판정 근거가 필요하다. 범위가 충돌하면 triage로 재개하고 이전 suppression을 해제한다. 현재 어댑터는 Ubuntu LTS이며 다른 ecosystem은 미해결로 남긴다. 상세는 `../project-vex.md`에 기록한다.
