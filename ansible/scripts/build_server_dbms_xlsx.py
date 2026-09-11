#!/usr/bin/env python3
"""Ansible 점검 결과(JSON, ./results/*.json)를 server_dbms_result.xlsx로 변환한다.

실행 예시:
    python3 build_server_dbms_xlsx.py --round "1차"

입력: site_check.yml 이 ./results/ 에 저장한
    - {inventory_hostname}_{날짜}.json  (서버, 'host' 키 존재)
    - dbms_{날짜}.json                   (DBMS, 'host' 키 없음)
출력: server_dbms_result.xlsx (시트: 서버, DBMS) — claude_code_handoff_spec.md 4.2/4.3절 컬럼 포맷
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook

COLUMNS = ["항목ID", "항목명", "판정", "상세", "대상", "점검일시", "회차"]

# 판정유형 "제외" 확정 항목 — 코드로 조회하지 않고 N/A 고정 행으로 삽입한다.
# (claude_code_handoff_spec.md 2.2/2.3절, 인프라점검_항목분류표_v0_3.xlsx 판정유형 컬럼 근거)
EXCLUDED_SERVER_ITEMS = [
    ("U-62", "로그인 시 경고 메시지 설정"),
]
EXCLUDED_DBMS_ITEMS = [
    ("D-12", "안전한 리스너 비밀번호 설정"),
    ("D-13", "불필요한 ODBC/OLE-DB 제거"),
    ("D-15", "리스너 로그/trace 파일 변경 제한"),
    ("D-16", "Windows 인증 모드 사용"),
    ("D-19", "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"),
    ("D-22", "데이터베이스의 자원 제한 기능을 TRUE로 설정"),
    ("D-23", "xp_cmdshell 사용 제한"),
    ("D-24", "Registry Procedure 권한 제한"),
]
EXCLUDED_DETAIL = "정책/해당없음 확정 항목 — 자동화 스코프 제외(가이드 별도 전달)"


def parse_args():
    script_dir = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results-dir", default=str(script_dir.parent / "results"),
                    help="site_check.yml이 저장한 JSON 결과 디렉터리 (기본: ansible/results)")
    p.add_argument("--date", default=datetime.now().strftime("%Y%m%d"),
                    help="결과를 저장할 날짜 폴더명(YYYYMMDD, 기본: 오늘) — script/results/{date}/ 아래 저장")
    p.add_argument("--output", default=None,
                    help="출력 xlsx 경로 (기본: script/results/{date}/server_dbms_result.xlsx)")
    p.add_argument("--round", dest="round_", default=None,
                    help="회차(예: 1차/2차/정기점검). 지정 시 이 회차의 JSON만 포함하고, "
                         "제외 확정 항목의 회차 표시에도 사용한다. 미지정 시 발견된 모든 JSON을 포함.")
    args = p.parse_args()
    if args.output is None:
        args.output = str(script_dir.parent.parent / "results" / args.date / "server_dbms_result.xlsx")
    return args


def load_result_files(results_dir: Path):
    if not results_dir.is_dir():
        print(f"[경고] 결과 디렉터리가 없습니다: {results_dir}", file=sys.stderr)
        return [], []
    server_files, dbms_files = [], []
    for f in sorted(results_dir.glob("*.json")):
        with f.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if "host" in data:
            server_files.append((f, data))
        else:
            dbms_files.append((f, data))
    return server_files, dbms_files


def build_server_rows(server_files, round_filter):
    rows = []
    for path, data in server_files:
        if round_filter and data.get("round") != round_filter:
            continue
        for r in data.get("results", []):
            rows.append([
                r["id"], r["item"], r["status"], r.get("detail", ""),
                data.get("host", "?"), data.get("checked_at", ""), data.get("round", ""),
            ])
    return rows


def build_dbms_rows(dbms_files, round_filter):
    rows = []
    for path, data in dbms_files:
        if round_filter and data.get("round") != round_filter:
            continue
        for r in data.get("results", []):
            rows.append([
                r["id"], r["item"], r["status"], r.get("detail", ""),
                r.get("target", "해당없음"), data.get("checked_at", ""), data.get("round", ""),
            ])
    return rows


def append_excluded_rows(rows, items, round_label, checked_at):
    for item_id, item_name in items:
        rows.append([item_id, item_name, "N/A", EXCLUDED_DETAIL, "전체(정책항목, 코드 미실행)", checked_at, round_label])


def write_sheet(wb, title, rows):
    ws = wb.create_sheet(title=title)
    ws.append(COLUMNS)
    for row in rows:
        ws.append(row)
    for col_idx, width in enumerate([10, 46, 10, 70, 22, 26, 12], start=1):
        ws.column_dimensions[chr(64 + col_idx)].width = width


def main():
    args = parse_args()
    results_dir = Path(args.results_dir)
    server_files, dbms_files = load_result_files(results_dir)

    now_iso = datetime.now().astimezone().isoformat(timespec="seconds")
    round_label = args.round_ or "정기점검"

    server_rows = build_server_rows(server_files, args.round_)
    dbms_rows = build_dbms_rows(dbms_files, args.round_)
    append_excluded_rows(server_rows, EXCLUDED_SERVER_ITEMS, round_label, now_iso)
    append_excluded_rows(dbms_rows, EXCLUDED_DBMS_ITEMS, round_label, now_iso)

    wb = Workbook()
    wb.remove(wb.active)
    write_sheet(wb, "서버", server_rows)
    write_sheet(wb, "DBMS", dbms_rows)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out_path)
    print(f"[완료] {out_path} 생성 — 서버 {len(server_rows)}행, DBMS {len(dbms_rows)}행")


if __name__ == "__main__":
    main()
