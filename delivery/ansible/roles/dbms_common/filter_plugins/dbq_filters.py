"""DB 파드 내부 클라이언트(k8s_exec) 출력을 행 dict 리스트로 변환하는 필터.

db_exec_query.yml에서 사용 — 기존 community.mysql/postgresql 모듈의 query_result와
같은 행 형태를 만들어 판정 태스크를 그대로 재사용하기 위함.
"""
import json
import re

_INT = re.compile(r"^-?\d+$")


def _cast(value):
    # mysql -B는 NULL을 문자열 "NULL"로, 숫자도 문자열로 출력하므로 원래 타입으로 되돌린다
    if value == "NULL":
        return None
    if _INT.match(value):
        return int(value)
    return value


def dbq_mysql_rows(stdout):
    """`mysql -B` 출력(첫 줄 컬럼명, 탭 구분)을 행 dict 리스트로 변환."""
    lines = [line for line in (stdout or "").splitlines() if line != ""]
    if not lines:
        return []
    header = lines[0].split("\t")
    return [dict(zip(header, map(_cast, line.split("\t")))) for line in lines[1:]]


def dbq_psql_rows(stdout):
    """json_agg로 감싼 `psql -At` 출력(JSON 배열 한 줄)을 행 dict 리스트로 변환.
    JSON 배열이 아니면 문자열 "__parse_error__" — Ansible vars 템플릿은 None을 빈 문자열로
    바꿔버리므로 None 대신 문자열로 실패를 표시하고, 호출부는 `is string`으로 판별한다."""
    text = (stdout or "").strip()
    try:
        rows = json.loads(text)
    except ValueError:
        return "__parse_error__"
    return rows if isinstance(rows, list) else "__parse_error__"


class FilterModule:
    def filters(self):
        return {"dbq_mysql_rows": dbq_mysql_rows, "dbq_psql_rows": dbq_psql_rows}
