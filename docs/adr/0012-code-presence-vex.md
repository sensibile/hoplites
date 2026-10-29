# ADR 0012: 비배포판 CVE를 납품물의 취약 코드 포함 여부로 판정

- 상태: 채택
- 날짜: 2026-10-30

## 배경

[배포판 VEX](0007-distro-vex.md)는 Ubuntu·Debian 패키지의 vendor 범위만 판정한다. npm·pip 번들과 직접 설치 런타임의 CVE는 판정 수단이 없어 DT에서 미분석으로 남았다. 지금까지 처리한 이미지(node, python-slim, temurin, elixir, ubuntu)는 런타임 베이스 이미지이며 앱 진입점이 없다. 이 이미지에 도달 불가(`code_not_reachable`)를 판정하면 근거 없는 안전 판정이 된다. 반면 "upstream 수정이 바꾼 코드가 납품물에 들어 있는가"는 파일, 바이트, 심볼로 결정적으로 확인할 수 있다. [라이선스 적용 범위](../license-scope-correction.md) 작업도 ELF 심볼과 빌드 설정을 같은 방식으로 사용했다.

## 결정

1. 판정 질문은 코드 포함 여부 하나로 제한한다. 도달성·악용 가능성은 판정하지 않으며, 베이스 이미지에는 `code_not_reachable`을 쓰지 않는다.
2. 규칙(`code_presence_rule`, 누적 SQL migration)은 CVE·advisory·패키지·검토한 취약 범위를 기록한다. 또 upstream 수정이 바꾼 모듈이 납품물의 어느 경로·심볼에 있는지 기록한다. 근거는 GitHub advisory, 수정 커밋, 릴리스 태그의 파일, 태그와 커밋의 순서를 고정한 API snapshot이다. 각 SHA-256이 일치하고 advisory가 그 범위와 커밋을 실제로 담고 있을 때만 규칙을 적용한다.
3. 근거 등급과 VEX 매핑은 다음과 같이 고정한다(`code-presence-v1`).

| 근거 | 등급 | VEX |
| --- | --- | --- |
| 납품 파일이 설치 버전 태그의 upstream 파일과 바이트 동일하고, 수정 커밋이 그 태그보다 뒤에 있음 | confirmed-present | `in_triage` |
| 납품 파일에 취약 함수 표지가 있고 수정 표지가 없음(컴파일된 산출물) | confirmed-present | `in_triage` |
| 동적 심볼 표에 취약 함수가 정의됨 | confirmed-present | `in_triage` |
| 모듈은 있지만 릴리스 파일과 다르거나 표지 대조가 맞지 않음(백포트·로컬 변경 가능) | inferred-present | `in_triage` |
| 대상 파일이 없고, 검토한 취약 표지가 패키지의 모든 파일에 없으며, 납품 파일 목록이 검토한 릴리스 목록과 같고 미해석 링크가 없음 | confirmed-absent | `not_affected` + `code_not_present` |
| 대상 파일만 없음(표지 미검토), 표지는 없지만 릴리스 목록 대조가 없거나 다름(minify·이름 변경 가능), 또는 심볼이 없음(인라인·strip 가능) | inferred-absent | `in_triage` |
| 빌드 설정만의 근거 | inferred(현재 미구현) | `in_triage` |
| 규칙 없음, 같은 CVE의 다른 규칙이 snapshot 검증 실패, 대상이 symlink, 패키지 위치·identity·생태계 불일치, 범위 밖 버전, ELF 해석 실패 | unresolved | `in_triage` |

4. rootfs의 hard link는 원 데이터로 읽고 symlink는 따라가지 않는다. 같은 구성요소의 사본이 여러 개면 하나라도 present이면 present다. absent는 모든 사본이 confirmed-absent일 때만 인정한다. CVE 하나에 대상이 여러 개일 때도 같은 규칙을 적용한다.
5. 배포판 패키지(`pkg:deb`·`apk`·`rpm`)는 이 판정에서 제외하고 배포판 어댑터가 맡는다. `run_project_vex.py --code-presence-sources`는 두 결과를 `(CVE, 구성요소)` 단위로 병합한다. 비배포판 판정이 배포판 어댑터의 "지원하지 않는 배포판" `in_triage`를 대체한다. 따라서 재실행해도 `code_not_present`가 다시 열리지 않는다.
6. 반영은 기존 `apply_dtrack_vex.py`를 사용한다. justification을 가진 판정은 DT의 `analysisJustification`까지 확인한다.

## 대안

- 버전 범위만으로 판정: DT·Trivy가 이미 수행한 매칭과 같아서 새 정보를 주지 않는다. 백포트도 구분하지 못한다.
- 수정 커밋 diff의 줄 단위 대조: 실제 데이터에서 추가 줄이 파일 다른 위치의 기존 코드와 우연히 일치했다. v6.x 브랜치 tip은 6.27.0에서 이미 바뀌어 있어 오판정이 났다. 그래서 설치 버전 태그와의 바이트 대조로 대체했다.
- 심볼 부재를 `code_not_present`로 사용: static·인라인 함수는 심볼을 남기지 않으므로 부재를 증명하지 못한다. 채택하지 않았다.
- LLM 판단으로 포함 여부 결정: 결정적 근거가 있는 질문이므로 사용하지 않는다. 엔진+LLM 트리아지는 별도 단계(C)다.

## 영향과 한계

- DT에 finding이 없는 CVE는 평가하지 않는다. VEX는 finding을 만들지 않는다. Trivy에만 있는 항목과 런타임 CVE 탐지 공백은 별도 미해결로 관리한다. DT·Trivy 0건은 안전 판정이 아니다.
- 규칙은 사람이 검토한 대상 경로·표지에 의존한다. 수정이 여러 파일에 걸칠 때 규칙에 빠진 파일이 있으면 그 파일의 포함 여부는 판정되지 않는다.
- 결과 `in_triage`는 "취약 코드가 납품물에 있음(confirmed)"을 뜻할 수 있다. 등급은 detail과 sidecar에서 확인한다. DT 상태만으로 confirmed와 unresolved를 구분할 수 없다.
- 빌드 설정(config.gypi 등) 근거와 Python·OTP·JDK 어댑터는 구현하지 않았다.

## 검증

회귀 테스트는 `tests/test_code_presence.py`(범위·snapshot 변조·등급·사본 결합·ELF·배포판 제외·병합)에 있다. 실제 반영은 Node 이미지 13건으로 했으며 결과는 [코드 포함 판정 VEX](../code-presence-vex.md)에 기록했다.
