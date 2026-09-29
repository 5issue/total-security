"""4.4~4.8, 4.11 — 통신구간 암호화 및 로깅 설정 점검(4.12는 로그 버킷 탐지를 공유하려고 storage_checks로 이동)."""
from .common import make_result, safe_call


def check_4_4_transit_encryption(elbv2):
    lbs, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return [make_result("4.4", "통신구간 암호화 설정", "SKIP", f"ALB 조회 실패: {err}")]
    plaintext = []
    for lb in lbs["LoadBalancers"]:
        listeners, lerr = safe_call(elbv2.describe_listeners, LoadBalancerArn=lb["LoadBalancerArn"])
        if lerr:
            # [2026-09-28] 기존엔 조회 실패 시 건너뛰어 PASS가 될 수 있었음 → 확인 불가로 FAIL 처리
            plaintext.append(f"{lb['LoadBalancerName']}(리스너 조회 실패: {lerr})")
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


def check_4_8_instance_logging(logs, ec2):
    # [2026-09-29 원문(p140) 재대조 — 오판 수정] 원문 양호: (인스턴스 로그를) CloudWatch 로그 스트림으로
    # 보관하고 있는 경우. 기존엔 로그그룹이 하나라도 있으면 PASS라 EKS 제어 플레인·VPC 플로우 로그그룹만
    # 있어도 통과했음. → 실행 중인 인스턴스마다 인스턴스 ID 또는 호스트명(ip-10-0-…)으로 시작하는
    # 로그 스트림이 있는지 확인(CloudWatch 에이전트 기본 스트림명 = 인스턴스 ID, Fluent Bit 호스트 로그 = 호스트명).
    reservations, err = safe_call(ec2.describe_instances,
                                  Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
    if err:
        return [make_result("4.8", "인스턴스 로깅 설정", "SKIP", f"EC2 인스턴스 조회 실패: {err}")]
    instances = {i["InstanceId"]: (i.get("PrivateDnsName") or "").split(".")[0]
                 for r in reservations["Reservations"] for i in r["Instances"]}
    paginator = logs.get_paginator("describe_log_groups")
    groups, gerr = safe_call(lambda: [g["logGroupName"] for page in paginator.paginate() for g in page["logGroups"]])
    if gerr:
        return [make_result("4.8", "인스턴스 로깅 설정", "SKIP", f"로그그룹 조회 실패: {gerr}")]
    logged, errors = {}, set()
    for iid, host in instances.items():
        for group in groups:
            for prefix in filter(None, (iid, host)):
                res, lerr = safe_call(logs.describe_log_streams, logGroupName=group, logStreamNamePrefix=prefix, limit=1)
                if lerr:
                    errors.add(f"{group}({lerr})")
                elif res["logStreams"]:
                    logged[iid] = f"{group}/{res['logStreams'][0]['logStreamName']}"
                    break
            if iid in logged:
                break
    missing = [f"{iid}({instances[iid] or '-'})" for iid in instances if iid not in logged]
    status = "PASS" if instances and not missing else ("REVIEW" if errors or not instances else "FAIL")
    detail = (f"실행 중 인스턴스 {len(instances)}대 중 CloudWatch 로그 스트림 없는 인스턴스: "
              + (", ".join(missing) if missing else "없음")
              + (f" / 보관 중: {', '.join(f'{k}→{v}' for k, v in logged.items())}" if logged else "")
              + (f" / 로그 스트림 조회 실패: {', '.join(sorted(errors))}" if errors else ""))
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
    results += check_4_8_instance_logging(logs, ec2)
    results += check_4_11_vpc_flow_logs(ec2)
    return results
