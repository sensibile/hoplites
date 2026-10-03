# Elixir Alpine 첫 연결 실험

2026-10-03 수행. 공식 Elixir 1.18.4-alpine의 linux/arm64 플랫폼을 선택했습니다. 대상 컨테이너를 실행하지 않고 Syft 1.54.0으로 레지스트리 내용을 분석했습니다.

- 이미지: `docker.io/library/elixir@sha256:b82a9d4474e7d6bc26db0e0fbf5eadc281d4fa4c905805b7d9e2dac7017c0683`
- SBOM: CycloneDX 1.7, 구성요소 300개
- SBOM SHA-256: `48b7666dbd07b3ba8ca3b1e1bfbf1ca67eecfca6042df1ea06b0f402ca16efbf`
- Dependency-Track 프로젝트: `hoplites-test-elixir-alpine-arm64`
- 프로젝트 UUID: `e1b5e4ae-5b28-43b0-80ce-d3a835df7bfb`
- 프로젝트 version: 플랫폼 이미지 digest
- 처리 상태: COMPLETED
- 서버 metrics: 구성요소 300개, 현재 취약점 0개
- 페이지별 조회: 구성요소 300개 전체 및 UUID 고유성 확인

취약점 0개는 현재 서버 분석 결과이며 안전성 판정이 아닙니다. 취약점 데이터 소스의 초기 동기화와 검출 정확도는 검증하지 않았습니다. 재전송과 다른 이미지 버전 분리는 아직 검증하지 않았습니다.

원본 SBOM, 이미지 index, 연결 기록 및 서버 응답은 Git에서 제외된 `artifacts/elixir-alpine/`에 보관합니다. 핵심 연결 기록은 `link.json`입니다. Keychain 키는 파일과 로그에 저장하지 않았습니다.

이미지 목록 기준: https://raw.githubusercontent.com/docker-library/official-images/master/library/elixir
