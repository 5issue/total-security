#!/usr/bin/env bash
# dbms 노드(VM3) 프로비저닝 — DBMS role(D-XX) 점검 대상. MySQL + PostgreSQL 같은 VM(포트만 다름).
# 의도적 FAIL 구성 (spec 6.3.2절): D-01(MySQL root@localhost 잠금 해제 상태 유지 — 기본값 그대로),
#                                  D-18(PostgreSQL PUBLIC 권한 부여)
#
# 테스트 전용 계정/비밀번호 — 실제 값 아님, ansible/group_vars/test_values.yml 의
# mysql_login_*/pg_login_* 와 반드시 짝이 맞아야 함.
set -euo pipefail

TEST_DB_PASS='InfraCheckTest!2026'

echo "[dbms] disabling firewalld for local private-network access (test VM only)"
systemctl disable --now firewalld >/dev/null 2>&1 || true

# -----------------------------------------------------------------------------
# MySQL 8.0 (Amazon Linux 2023 기본 리포지토리엔 MariaDB만 있어 MySQL 공식 리포 사용)
# -----------------------------------------------------------------------------
echo "[dbms] installing MySQL 8.0 community server"
if ! rpm -q mysql80-community-release >/dev/null 2>&1; then
  dnf install -y https://dev.mysql.com/get/mysql80-community-release-el9-1.noarch.rpm >/dev/null
fi
# MySQL 리포의 공개키가 el9-1 릴리스 패키지에 번들된 키와 어긋나 있어(업스트림 키 로테이션)
# GPG 검증이 실패함 -- 로컬 일회성 테스트 VM이라 --nogpgcheck 로 우회
dnf install -y --nogpgcheck mysql-community-server >/dev/null

grep -q '^bind-address=0.0.0.0' /etc/my.cnf || sed -i '/^\[mysqld\]/a bind-address=0.0.0.0' /etc/my.cnf
systemctl enable --now mysqld

# 재프로비저닝(vagrant provision 재실행) 대비 — 이미 테스트 비밀번호로 설정돼 있으면 temp password 단계 스킵
if ! mysql -uroot -p"${TEST_DB_PASS}" -e "SELECT 1" >/dev/null 2>&1; then
  TEMP_PASS="$(awk '/A temporary password/{print $NF}' /var/log/mysqld.log | tail -1)"
  mysql --connect-expired-password -uroot -p"${TEMP_PASS}" -e \
    "ALTER USER 'root'@'localhost' IDENTIFIED BY '${TEST_DB_PASS}';" 2>/dev/null
fi
mysql -uroot -p"${TEST_DB_PASS}" -e \
  "CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${TEST_DB_PASS}'; \
   GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION; \
   CREATE DATABASE IF NOT EXISTS testdb; \
   FLUSH PRIVILEGES;"

# 의도적 FAIL: root@localhost 기본 계정을 잠그지 않음(account_locked 기본값 'N', 별도 조치 없음)
echo "[dbms] intentional FAIL: D-01 MySQL root@localhost left unlocked (default)"

# -----------------------------------------------------------------------------
# PostgreSQL 15
# -----------------------------------------------------------------------------
echo "[dbms] installing PostgreSQL 15 server"
dnf install -y postgresql15-server postgresql15 >/dev/null
[ -f /var/lib/pgsql/data/PG_VERSION ] || /usr/bin/postgresql-setup --initdb

PGDATA="/var/lib/pgsql/data"

sed -i "s/^#listen_addresses.*/listen_addresses = '*'/" "${PGDATA}/postgresql.conf"
grep -q "192.168.56.0/24" "${PGDATA}/pg_hba.conf" || \
  echo "host    all             all             192.168.56.0/24         md5" >> "${PGDATA}/pg_hba.conf"

systemctl enable --now postgresql

sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '${TEST_DB_PASS}';"
sudo -u postgres psql -c "CREATE DATABASE testdb;" 2>/dev/null || true
sudo -u postgres psql -d testdb -c "CREATE TABLE IF NOT EXISTS accounts (id serial PRIMARY KEY, name text);"

# 의도적 FAIL: 애플리케이션 테이블에 PUBLIC 권한 부여
echo "[dbms] intentional FAIL: D-18 GRANT SELECT ON accounts TO PUBLIC"
sudo -u postgres psql -d testdb -c "GRANT SELECT ON accounts TO PUBLIC;"

systemctl restart postgresql
systemctl restart mysqld

echo "[dbms] done — MySQL:3306(root/${TEST_DB_PASS}), PostgreSQL:5432(postgres/${TEST_DB_PASS})"
