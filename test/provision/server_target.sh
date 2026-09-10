#!/usr/bin/env bash
# server 노드(VM2) 프로비저닝 — 서버 role(U-XX) 점검 대상
# 의도적 FAIL 구성 (spec 6.3.2절): U-01(root 원격접속 허용), U-07(블랙리스트 계정 로그인 가능)
set -euo pipefail

echo "[server] disabling firewalld for local private-network SSH (test VM only)"
systemctl disable --now firewalld >/dev/null 2>&1 || true

echo "[server] intentional FAIL: U-01 PermitRootLogin yes"
sed -i '/^#\?PermitRootLogin/d' /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
systemctl restart sshd

echo "[server] intentional FAIL: U-07 blacklist account 'games' with login shell"
if ! id games >/dev/null 2>&1; then
  useradd -m -s /bin/bash games
else
  usermod -s /bin/bash games
fi
echo "games:games1234!" | chpasswd

echo "[server] done — U-01/U-07 should now report FAIL"
