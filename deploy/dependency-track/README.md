# Local Dependency-Track

공식 quickstart를 기준으로 API/frontend 5.1.1 및 PostgreSQL 18을 구성합니다. API는 localhost:18080, UI는 localhost:18081에만 공개하고 DB 포트는 공개하지 않습니다. 영속 볼륨은 hoplites-dtrack 프로젝트에 분리합니다.

## 실행

이 디렉터리에서 `.env.example`을 `.env`로 복사하고 DB 비밀번호를 로컬에서 생성하여 넣습니다. `.env`는 Git에서 제외되며 API 키나 사용자 비밀번호를 저장소에 넣지 않습니다. 현재 작업 공간에는 권한 0600의 로컬 DB 설정이 준비되어 있습니다.

```sh
docker compose config --quiet
docker compose up -d
docker compose ps
```

UI: http://localhost:18081
API: http://localhost:18080

최초 로그인 및 초기 비밀번호 변경은 사용자가 UI에서 직접 수행합니다. 선택 버전의 공식 초기 계정 안내를 확인합니다. 서버 기동만으로 취약점 데이터 수집이나 SBOM 분석 완료를 의미하지 않습니다.

## 중단 및 재시작

```sh
docker compose stop
docker compose up -d
```

`docker compose down`은 컨테이너와 네트워크를 제거하고 볼륨은 보존합니다. `down -v`는 데이터를 삭제하므로 일반 중단에 사용하지 않습니다.

## 첫 실험

합성 또는 공개 아티팩트 하나의 digest와 SBOM sha256을 기록합니다. UI에서 프로젝트를 만들고 CycloneDX SBOM을 업로드한 뒤 구성요소와 분석 결과를 확인합니다. 업로드 접수와 분석 완료를 구분합니다. 아티팩트 원본과 SBOM 원본의 연결 기록은 Hoplites가 별도로 유지하며, Dependency-Track 프로젝트만으로 원본 아티팩트 연결이 완성되었다고 간주하지 않습니다.

현재는 로컬 평가용입니다. 외부 서비스 연동과 비공개 SBOM 업로드 전에 데이터 전송 범위를 확인합니다. 정규화 BOM 업로드 자동화는 [이미지 CLI 사용 가이드](../../docs/usage-guide.md)에 연결되어 있습니다. 아티팩트 저장소 업로드, 릴리스 승인, 배포 기능은 아직 포함하지 않습니다.

## 기준 문서

- https://dependencytrack.org/docker-compose.yml
- https://raw.githubusercontent.com/DependencyTrack/docs/refs/heads/main/docs/tutorials/docker-compose.quickstart.yml

2026-10-03 확인. v4.14 문서의 ALPINE 설정 대신 공식 v5 quickstart의 DT_DATASOURCE 설정을 사용합니다.

## 기동 검증 기록

2026-10-03 초기 기동: Compose 설정 검증 통과. OrbStack에서 API/frontend/PostgreSQL 기동. API 컨테이너 및 PostgreSQL healthy, UI HTTP 200 확인.

후속 실험에서는 초기 비밀번호 변경 후 Elixir·Temurin·Ubuntu·Alpine의 정규화 BOM 업로드와 필드·개수 API 검증, Temurin VEX 반영까지 확인했습니다. 상세 범위는 [이미지 파이프라인 검증 기록](../../docs/image-pipeline.md#실제-연결-검증)을 참고하세요. DB 재시작 후 유지와 취약점 DB 갱신의 완전성은 별도 검증이 필요합니다.
