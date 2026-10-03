# OrbStack Kubernetes 구성

로컬 평가용으로 Compose와 같은 이미지 버전을 사용합니다. `orbstack` context와 확인한 `local-path` StorageClass를 사용하며 DB/API PVC, 각 1개 replica, ClusterIP Service, startup/readiness probe를 구성합니다. 기존 Compose 데이터와 별개이며 자동 이전하지 않습니다.

## 배포 준비 및 실행

저장소 루트에서 실행합니다. 실제 배포는 아직 수행하지 않았습니다.

```sh
kubectl --context orbstack apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: hoplites-dtrack
EOF
kubectl --context orbstack -n hoplites-dtrack create secret generic dtrack-db --from-env-file=deploy/dependency-track/.env
kubectl --context orbstack apply -k deploy/dependency-track/k8s
kubectl --context orbstack -n hoplites-dtrack rollout status deployment/apiserver --timeout=10m
kubectl --context orbstack -n hoplites-dtrack rollout status deployment/frontend --timeout=5m
```

Secret 준비는 앞서 구성한 로컬 `.env`를 사용합니다. Secret이 이미 있다면 비밀번호와 DB의 일치 여부를 확인하고 기존 Secret을 유지합니다. 비밀번호를 바꾸는 것만으로 기존 DB 비밀번호가 변경되지는 않습니다. 새 환경에서는 Compose 실행 안내에 따라 먼저 `.env`를 준비합니다.

## 접속

두 터미널에서 각각 실행합니다. Compose 포트와 충돌하지 않도록 별도 포트를 씁니다.

```sh
kubectl --context orbstack -n hoplites-dtrack port-forward --address 127.0.0.1 service/apiserver 28080:8080
kubectl --context orbstack -n hoplites-dtrack port-forward --address 127.0.0.1 service/frontend 28081:8080
```

UI: http://localhost:28081
API: http://localhost:28080

프런트엔드의 API 주소는 브라우저가 접속하는 localhost:28080입니다. 포트를 바꾸면 해당 환경 설정도 바꿉니다. 외부 Ingress나 LoadBalancer는 포함하지 않습니다.

## 보존과 제한

중단 시 Deployment를 0 replica로 줄이면 PVC를 유지할 수 있습니다. Namespace/PVC 삭제는 데이터 삭제로 이어질 수 있습니다. 현재 StorageClass의 reclaim policy는 Delete이므로 삭제를 중단 수단으로 쓰지 않습니다.

단일 노드 로컬 구성이며 HA, 백업/복구, TLS/SSO, 외부 노출, 운영 환경 검증은 포함하지 않습니다. API probe는 현재 이미지의 Docker healthcheck와 동일한 9000/health를 사용합니다. 실제 Pod 기동과 PVC 바인딩은 배포 시 검증해야 합니다.

Probe 참고: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
