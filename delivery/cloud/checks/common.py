"""클라우드 점검 공통 유틸리티."""


def make_result(item_id: str, item: str, status: str, detail: str) -> dict:
    """판정 결과 dict 생성. target(대상)은 클라우드 항목 전체가 '계정 전체'로 고정."""
    return {"id": item_id, "item": item, "status": status, "detail": detail, "target": "계정 전체"}


def safe_call(fn, *args, **kwargs):
    """boto3/K8s 호출 실패 시 예외를 문자열로 반환(호출부에서 None 체크)."""
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001 - 점검 스크립트는 개별 API 실패로 전체가 죽으면 안 됨
        return None, str(exc)
