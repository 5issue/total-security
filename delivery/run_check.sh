#!/usr/bin/env bash
# run_check.sh — 인프라 점검 파이프라인 전체 실행
#   사용법: ./run_check.sh <회차> [날짜(YYYYMMDD)]
#   예시:   ./run_check.sh 1차 20260914
set -euo pipefail

ROUND="${1:?사용법: ./run_check.sh <회차> [날짜(YYYYMMDD)]}"
DATE="${2:-$(date +%Y%m%d)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== [1/4] Ansible 서버·DBMS 점검 (회차: ${ROUND}) ==="
cd "${SCRIPT_DIR}/ansible"
ansible-playbook -i inventory/hosts.ini site_check.yml -e check_round="${ROUND}"

echo "=== [2/4] 서버·DBMS 결과 -> xlsx ==="
python3 scripts/build_server_dbms_xlsx.py --round "${ROUND}" --date "${DATE}"

echo "=== [3/4] 클라우드(boto3) 점검 -> xlsx ==="
cd "${SCRIPT_DIR}/cloud"
python3 cloud_check.py --round "${ROUND}" --date "${DATE}"

echo "=== [4/4] 결과 병합 + SHA-256 해시 생성 ==="
cd "${SCRIPT_DIR}"
python3 merge_report.py --round "${ROUND}" --date "${DATE}"

OUTPUT_DIR="${SCRIPT_DIR}/results/${DATE}"
OUTPUT_FILE="infra_check_${DATE}_${ROUND}.xlsx"
cd "${OUTPUT_DIR}"
sha256sum "${OUTPUT_FILE}" > "${OUTPUT_FILE}.sha256"

echo "=== 완료: ${OUTPUT_DIR}/${OUTPUT_FILE} + ${OUTPUT_FILE}.sha256 ==="
