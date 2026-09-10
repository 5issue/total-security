#!/usr/bin/env bash
# control 노드(VM1) 추가 프로비저닝 — D-10(NetworkPolicy) 로컬 검증 전용 kind 클러스터
# (spec 6.6절). VM3 DBMS 설계는 그대로 두고, D-10만 이 경량 K8s 환경에서 검증한다.
set -euo pipefail

KIND_VERSION="v0.24.0"
KUBECTL_VERSION="v1.31.0"

echo "[kind] installing Docker"
if ! command -v docker >/dev/null 2>&1; then
  dnf install -y docker >/dev/null
  systemctl enable --now docker
fi

echo "[kind] installing kubectl ${KUBECTL_VERSION}"
if ! command -v kubectl >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  chmod +x /usr/local/bin/kubectl
fi

echo "[kind] installing kind ${KIND_VERSION}"
if ! command -v kind >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
  chmod +x /usr/local/bin/kind
fi

echo "[kind] creating cluster 'infracheck' (no-op if already exists)"
if ! kind get clusters 2>/dev/null | grep -q '^infracheck$'; then
  kind create cluster --name infracheck
fi

# kind는 기본적으로 실행한 사용자(root, 이 provisioner)의 kubeconfig에 클러스터 정보를 남김.
# ansible-playbook은 vagrant 계정으로 실행할 것이므로 kubeconfig를 그쪽에도 넘겨준다.
echo "[kind] copying kubeconfig to vagrant user"
mkdir -p /home/vagrant/.kube
kind get kubeconfig --name infracheck > /home/vagrant/.kube/config
chown -R vagrant:vagrant /home/vagrant/.kube

echo "[kind] applying D-10 test manifests"
export KUBECONFIG=/home/vagrant/.kube/config
kubectl apply -f /infra-check/test/k8s/namespace.yaml
kubectl apply -f /infra-check/test/k8s/pods.yaml
kubectl apply -f /infra-check/test/k8s/networkpolicies.yaml
kubectl -n infracheck-test wait --for=condition=Ready pod --all --timeout=120s

echo "[kind] done — cluster 'infracheck' ready: namespace infracheck-test has mock-db-pass(PASS 케이스)/mock-db-fail(FAIL 케이스) 파드"
