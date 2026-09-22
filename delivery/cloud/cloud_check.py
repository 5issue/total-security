#!/usr/bin/env python3
"""AWS 클라우드 인프라 점검 (boto3) — cloud_result.xlsx 생성.

실행 예시:
    python3 cloud_check.py --round "1차"
    python3 cloud_check.py --round "1차" --eks-clusters my-cluster-1,my-cluster-2

인증: boto3 기본 자격증명 체인 사용(환경변수/공유 credentials/인스턴스 프로파일 등).
      mgmt 서버에 이미 구성된 AWS CLI 프로파일을 그대로 사용하면 된다.
출력: cloud_result.xlsx (시트: 클라우드) — claude_code_handoff_spec.md 4.2/4.3절 컬럼 포맷
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

import boto3
from openpyxl import Workbook

import config
from checks import auth_checks, eks_checks, elb_checks, iam_checks, logging_checks, network_checks, storage_checks
from checks.common import make_result

COLUMNS = ["항목ID", "항목명", "판정", "상세", "대상", "점검일시", "회차"]

# 판정유형 "제외" 확정 항목 — 코드로 조회하지 않고 N/A 고정 행으로 삽입한다.
EXCLUDED_ITEMS = [
    ("4.13", "백업 사용 여부"),
]
EXCLUDED_DETAIL = "정책/해당없음 확정 항목 — 자동화 스코프 제외(가이드 별도 전달)"


def parse_args():
    script_dir = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--round", dest="round_", default="정기점검", help="회차(예: 1차/2차/정기점검)")
    p.add_argument("--date", default=datetime.now().strftime("%Y%m%d"),
                   help="결과를 저장할 날짜 폴더명(YYYYMMDD, 기본: 오늘) — script/results/{date}/ 아래 저장")
    p.add_argument("--output", default=None,
                   help="출력 xlsx 경로 (기본: script/results/{date}/cloud_result.xlsx)")
    p.add_argument("--region", default=None, help="boto3 리전 지정(미지정 시 기본 프로파일 리전 사용)")
    p.add_argument("--eks-clusters", default=None,
                   help="점검할 EKS 클러스터 이름(콤마구분). 미지정 시 config.EKS_CLUSTER_NAMES, "
                        "그마저 없으면 eks.list_clusters()로 자동 탐색")
    p.add_argument("--test-config", action="store_true",
                   help="⚠ 테스트 전용 — config_test.py의 임의값으로 config.py의 TODO(None) 값을 "
                        "덮어쓰고 실행한다. 로컬 검증 시에만 사용, 운영 실행에는 절대 붙이지 말 것.")
    args = p.parse_args()
    if args.output is None:
        args.output = str(script_dir.parent / "results" / args.date / "cloud_result.xlsx")
    return args


def apply_test_config():
    import config_test
    for key, value in vars(config_test).items():
        if not key.startswith("_"):
            setattr(config, key, value)
    print("[알림] --test-config 적용됨 — config_test.py의 임의값으로 TODO 항목을 판정합니다.", file=sys.stderr)


def discover_eks_clusters(eks, override):
    """반환: (cluster_names, discovery_error). discovery_error는 API 호출 자체가
    실패했을 때만 채워진다 — "정상 조회됐는데 0개"와 구분해야 최종 리포트에서
    SKIP 사유(조회 실패 vs 진짜 없음)를 정확히 표시할 수 있다."""
    if override:
        return [c.strip() for c in override.split(",") if c.strip()], None
    if config.EKS_CLUSTER_NAMES:
        return config.EKS_CLUSTER_NAMES, None
    try:
        return eks.list_clusters()["clusters"], None
    except Exception as exc:  # noqa: BLE001
        print(f"[경고] EKS 클러스터 자동탐색 실패: {exc}", file=sys.stderr)
        return [], str(exc)


def main():
    args = parse_args()
    if args.test_config:
        apply_test_config()
    session = boto3.Session(region_name=args.region)

    sts = session.client("sts")
    try:
        account_id = sts.get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001
        print(f"[경고] AWS 자격증명 확인 실패: {exc}", file=sys.stderr)
        account_id = None

    iam = session.client("iam")
    ec2 = session.client("ec2")
    s3 = session.client("s3")
    s3control = session.client("s3control")
    rds = session.client("rds")
    elbv2 = session.client("elbv2")
    logs = session.client("logs")
    cloudtrail = session.client("cloudtrail")
    eks = session.client("eks")
    awsconfig = session.client("config")  # 1.8 Access Key 사용주기 Config Rule 조회용
    ssm = session.client("ssm")  # SVC-08 세션 로깅 설정 조회용

    results = []
    results += iam_checks.run_all(iam, ec2, awsconfig)
    results += network_checks.run_all(ec2)
    results += storage_checks.run_all(ec2, s3, s3control, rds, account_id)
    results += logging_checks.run_all(elbv2, logs, ec2, cloudtrail)
    results += elb_checks.run_all(elbv2, ec2)

    cluster_names, discovery_error = discover_eks_clusters(eks, args.eks_clusters)
    results += eks_checks.run_all(eks, iam, ec2, cluster_names, discovery_error)

    for item_id, item_name in EXCLUDED_ITEMS:
        results.append(make_result(item_id, item_name, "N/A", EXCLUDED_DETAIL))

    # 인증_인가(SVC-02/AUTHN-14/SVC-08) — 항목ID가 "1.1" 같은 점(.) 구분 숫자가 아니라
    # 별도 시트("인증_인가")에 따로 쓴다(아래 숫자 정렬 키가 못 씀).
    auth_results = auth_checks.run_all(eks, ec2, ssm, elbv2, cluster_names)

    now_iso = datetime.now().astimezone().isoformat(timespec="seconds")
    rows = [[r["id"], r["item"], r["status"], r["detail"], r["target"], now_iso, args.round_] for r in results]
    rows.sort(key=lambda r: tuple(int(p) for p in r[0].split(".")))
    auth_rows = [[r["id"], r["item"], r["status"], r["detail"], r["target"], now_iso, args.round_] for r in auth_results]
    auth_rows.sort(key=lambda r: r[0])

    wb = Workbook()
    ws = wb.active
    ws.title = "클라우드"
    ws.append(COLUMNS)
    for row in rows:
        ws.append(row)
    for col_idx, width in enumerate([10, 42, 10, 80, 14, 26, 12], start=1):
        ws.column_dimensions[chr(64 + col_idx)].width = width

    ws_auth = wb.create_sheet("인증_인가")
    ws_auth.append(COLUMNS)
    for row in auth_rows:
        ws_auth.append(row)
    for col_idx, width in enumerate([10, 42, 10, 80, 14, 26, 12], start=1):
        ws_auth.column_dimensions[chr(64 + col_idx)].width = width

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out_path)
    print(f"[완료] {out_path} 생성 — 클라우드 {len(rows)}개 항목, 인증_인가 {len(auth_rows)}개 항목")


if __name__ == "__main__":
    main()
