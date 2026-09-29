"""DBMS 공통 : DB 파드 내부 쿼리 출력 파서."""
import json
import re

_INT = re.compile(r"^-?\d+$")


def _cast(value):
    if value == "NULL":
        return None
    if _INT.match(value):
        return int(value)
    return value


def dbq_mysql_rows(stdout):
    lines = [line for line in (stdout or "").splitlines() if line != ""]
    if not lines:
        return []
    header = lines[0].split("\t")
    return [dict(zip(header, map(_cast, line.split("\t")))) for line in lines[1:]]


def dbq_psql_rows(stdout):
    text = (stdout or "").strip()
    try:
        rows = json.loads(text)
    except ValueError:
        return "__parse_error__"
    return rows if isinstance(rows, list) else "__parse_error__"


class FilterModule:
    def filters(self):
        return {"dbq_mysql_rows": dbq_mysql_rows, "dbq_psql_rows": dbq_psql_rows}
