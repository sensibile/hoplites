# ADR-0008: 이미지 입력을 공통 단계와 버전별 보강 규칙으로 연결

상태: 채택. 2026-10-03.

## 배경

Elixir/Alpine과 Temurin/Ubuntu는 여러 실험 스크립트와 image별 근거를 연결해 처리했다. 새 이미지마다 수동 실행 연결을 반복하지 않고 같은 CLI로 적용 가능한 범위까지 처리하며 새 규칙을 누적해야 한다.

## 결정

Python orchestration script에 registry digest 고정, rootfs/BOM 수집, inventory 기반 정규화, version별 런타임 보강, 증적 출력과 옵션 DT/VEX를 연결한다. 버전별 사실과 매핑은 SQL migration으로 누적하며 공개 증거 blob은 검토한 SHA로 캐시한다. image별 실행 rootfs SHA를 release 규칙 자체로 고정하지 않고 매 실행 provenance와 marker 검증을 연결한다.

원본·단계별 결과·미해결은 보존하고 출력은 덮어쓰지 않는다. generic 패키지 정규화는 런타임이 없어도 진행한다. 어댑터/근거가 없는 항목은 원래 구성요소 및 값을 유지하고 다음 확인 방법을 기록한다. 새로운 배포판이나 runtime의 정보는 기존 image의 값으로 대체하지 않는다.

## 영향·한계

복잡한 CLI의 Rust 전환 기준은 기존 언어 ADR을 따른다. 이번에는 기존 Python 함수/스크립트 실행을 묶는 범위다. 현재 어댑터는 APK, dpkg와 검토한 런타임이며 다른 inventory/advisory는 추가가 필요하다. private registry 인증, resume, 자동 규칙 학습·검토/장기 갱신은 이번 범위에 포함하지 않는다. 상세 사용·확장·검증은 `../image-pipeline.md`를 따른다.
