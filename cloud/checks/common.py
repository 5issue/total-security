"""클라우드 점검 공통 유틸리티."""
from datetime import datetime, timezone


def make_result(item_id: str, item: str, status: str, detail: str) -> dict:
    """스펙 4.3절 컬럼 스키마 중 판정 로직에서 채우는 필드만 dict로 반환한다.
    대상(target)은 클라우드 항목 전체가 '계정 전체'로 고정(스펙 4.3 예시 근거)."""
    return {"id": item_id, "item": item, "status": status, "detail": detail, "target": "계정 전체"}


def age_in_days(dt) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def safe_call(fn, *args, **kwargs):
    """boto3/K8s 호출 실패 시 예외를 문자열로 반환(호출부에서 None 체크)."""
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001 - 점검 스크립트는 개별 API 실패로 전체가 죽으면 안 됨
        return None, str(exc)
