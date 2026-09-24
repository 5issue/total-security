"""4.4~4.8, 4.11~4.12 — 통신구간 암호화 및 로깅 설정 점검."""
import config
from .common import make_result, safe_call


def check_4_4_transit_encryption(elbv2):
    lbs, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return [make_result("4.4", "통신구간 암호화 설정", "SKIP", f"ALB 조회 실패: {err}")]
    plaintext = []
    for lb in lbs["LoadBalancers"]:
        listeners, lerr = safe_call(elbv2.describe_listeners, LoadBalancerArn=lb["LoadBalancerArn"])
        if lerr:
            continue
        for l in listeners["Listeners"]:
            # 2026-09-24 — HTTPS 리다이렉트 전용 HTTP 리스너는 평문 서비스가 아니므로 제외
            # (3.10이 80→443 리다이렉트를 필수로 요구하므로, 제외하지 않으면 두 항목이 동시에 PASS 불가)
            actions = l.get("DefaultActions", [])
            https_redirect_only = l["Protocol"] == "HTTP" and bool(actions) and all(
                a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                for a in actions)
            if l["Protocol"] in ("HTTP", "TCP") and not https_redirect_only:
                plaintext.append(f"{lb['LoadBalancerName']}:{l['Port']}({l['Protocol']})")
    status = "PASS" if not plaintext else "FAIL"
    detail = "평문 리스너: " + (", ".join(plaintext) if plaintext else "없음(전체 HTTPS/TLS)")
    return [make_result("4.4", "통신구간 암호화 설정", status, detail)]


def check_4_5_cloudtrail_encryption(trails):
    unencrypted = [t["Name"] for t in trails if not t.get("KmsKeyId")]
    status = "PASS" if (trails and not unencrypted) else "FAIL"
    detail = ("KMS 암호화 미설정 Trail: " + (", ".join(unencrypted) if unencrypted else "없음")) \
        if trails else "CloudTrail 미구성"
    return [make_result("4.5", "CloudTrail 암호화 설정", status, detail)]


def check_4_6_cloudwatch_encryption(logs):
    groups, err = safe_call(logs.describe_log_groups)
    if err:
        return [make_result("4.6", "CloudWatch 암호화 설정", "SKIP", f"로그그룹 조회 실패: {err}")]
    unencrypted = [g["logGroupName"] for g in groups["logGroups"] if not g.get("kmsKeyId")]
    status = "PASS" if not unencrypted else "FAIL"
    detail = "KMS 미설정 로그그룹: " + (", ".join(unencrypted[:10]) if unencrypted else "없음") + \
             (f" 외 {len(unencrypted) - 10}건" if len(unencrypted) > 10 else "")
    return [make_result("4.6", "CloudWatch 암호화 설정", status, detail)]


def check_4_7_account_logging(trails):
    active = [t for t in trails if t.get("_is_logging")]
    status = "PASS" if active else "FAIL"
    detail = "활성 CloudTrail: " + (", ".join(t["Name"] for t in active) if active else "없음")
    return [make_result("4.7", "AWS 사용자 계정 로깅 설정", status, detail)]


def check_4_8_instance_logging(logs):
    groups, err = safe_call(logs.describe_log_groups)
    if err:
        return [make_result("4.8", "인스턴스 로깅 설정", "SKIP", f"로그그룹 조회 실패: {err}")]
    status = "PASS" if groups["logGroups"] else "FAIL"
    detail = f"CloudWatch 로그그룹 {len(groups['logGroups'])}개 존재" if groups["logGroups"] \
        else "CloudWatch 로그그룹 없음 — 인스턴스 로그스트림 보관 미설정 추정(에이전트/네이밍 규칙에 따라 오탐 가능, 수동 확인 권장)"
    return [make_result("4.8", "인스턴스 로깅 설정", status, detail)]


def check_4_11_vpc_flow_logs(ec2):
    vpcs, verr = safe_call(ec2.describe_vpcs)
    flow_logs, ferr = safe_call(ec2.describe_flow_logs)
    if verr or ferr:
        return [make_result("4.11", "VPC 플로우 로깅 설정", "SKIP", f"조회 실패: {verr or ferr}")]
    logged_resources = {fl["ResourceId"] for fl in flow_logs["FlowLogs"]}
    missing = [v["VpcId"] for v in vpcs["Vpcs"] if v["VpcId"] not in logged_resources]
    status = "PASS" if not missing else "FAIL"
    detail = "플로우 로그 미설정 VPC: " + (", ".join(missing) if missing else "없음")
    return [make_result("4.11", "VPC 플로우 로깅 설정", status, detail)]


def check_4_12_log_retention(logs):
    groups, err = safe_call(logs.describe_log_groups)
    if err:
        return [make_result("4.12", "로그 보관 기간 설정", "SKIP", f"로그그룹 조회 실패: {err}")]
    short_retention = [
        g["logGroupName"] for g in groups["logGroups"]
        if g.get("retentionInDays") and g["retentionInDays"] < config.LOG_RETENTION_MIN_DAYS
    ]
    status = "PASS" if not short_retention else "FAIL"
    detail = f"기준({config.LOG_RETENTION_MIN_DAYS}일) 미만 보관 로그그룹: " + \
             (", ".join(short_retention[:10]) if short_retention else "없음")
    return [make_result("4.12", "로그 보관 기간 설정", status, detail)]


def run_all(elbv2, logs, ec2, cloudtrail):
    trail_list, terr = safe_call(cloudtrail.describe_trails)
    trails = trail_list["trailList"] if not terr else []
    for t in trails:
        status, serr = safe_call(cloudtrail.get_trail_status, Name=t["Name"])
        t["_is_logging"] = (not serr) and status.get("IsLogging", False)

    results = []
    results += check_4_4_transit_encryption(elbv2)
    results += check_4_5_cloudtrail_encryption(trails)
    results += check_4_6_cloudwatch_encryption(logs)
    results += check_4_7_account_logging(trails)
    results += check_4_8_instance_logging(logs)
    results += check_4_11_vpc_flow_logs(ec2)
    results += check_4_12_log_retention(logs)
    return results
