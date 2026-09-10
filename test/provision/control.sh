#!/usr/bin/env bash
# control 노드(VM1) 프로비저닝 — Ansible + boto3/awscli 설치, VM2/VM3 SSH 트러스트 설정
set -euo pipefail

echo "[control] installing python3/pip, ansible, git"
dnf install -y python3 python3-pip git >/dev/null

# AL2023 RPM pip(21.3.1)는 자체 RECORD 메타데이터가 없어 일반 업그레이드시
# "Cannot uninstall pip" 에러가 남 -- --ignore-installed로 우회
python3 -m pip install --quiet --upgrade --ignore-installed pip
python3 -m pip install --quiet ansible boto3 openpyxl kubernetes PyMySQL psycopg2-binary

echo "[control] installing ansible-galaxy collections (requirements.yml)"
if [ -f /infra-check/ansible/requirements.yml ]; then
  ansible-galaxy collection install -r /infra-check/ansible/requirements.yml
fi

echo "[control] configuring SSH client for server/dbms targets"
chmod 600 /home/vagrant/.ssh/id_ed25519_infracheck
chown vagrant:vagrant /home/vagrant/.ssh/id_ed25519_infracheck

cat > /home/vagrant/.ssh/config <<'EOF'
Host 192.168.56.*
  User vagrant
  IdentityFile ~/.ssh/id_ed25519_infracheck
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
EOF
chown vagrant:vagrant /home/vagrant/.ssh/config
chmod 600 /home/vagrant/.ssh/config

cat > /home/vagrant/.ansible.cfg <<'EOF'
[defaults]
host_key_checking = False
interpreter_python = /usr/bin/python3
EOF
chown vagrant:vagrant /home/vagrant/.ansible.cfg

echo "[control] done. run tests with:"
echo "  vagrant ssh control"
echo "  cd /infra-check/ansible && ansible-playbook -i /infra-check/test/inventory/hosts.ini site_check.yml -e check_round=테스트 -e @group_vars/test_values.yml"
