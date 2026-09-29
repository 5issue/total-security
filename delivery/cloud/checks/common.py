"""클라우드 점검 공통 유틸리티."""


def make_result(item_id: str, item: str, status: str, detail: str) -> dict:
    return {"id": item_id, "item": item, "status": status, "detail": detail, "target": "계정 전체"}


def safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)
