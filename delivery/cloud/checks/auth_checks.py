"""SVC-02, AUTHN-14, SVC-08 — 인증_인가 시트 중 AWS CLI/boto3로 조회 가능한 항목.

AUTHZ-08/AUTHZ-09/SVC-01은 ansible/roles/auth_authz에 별도 구현되어 있다.
"""
import json
import re

import config
from .common import make_result, safe_call


def _parse_addon_version(version_str):
    """'v1.16.0-eksbuild.1' 같은 EKS addon 버전 문자열에서 (major, minor) 추출."""
    m = re.search(r"(\d+)\.(\d+)", version_str or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def check_svc_02_vpc_cni(eks, cluster_names):
    """vpc-cni >= 1.14, enableNetworkPolicy = true."""
    item = "VPC CNI 1.14+ · enableNetworkPolicy 네이티브 적용"
    if not cluster_names:
        return [make_result("SVC-02", item, "SKIP", "EKS 클러스터 조회 결과 없음 — 클러스터 확인 필요")]

    results = []
    for cluster_name in cluster_names:
        addon_res, err = safe_call(eks.describe_addon, clusterName=cluster_name, addonName="vpc-cni")
        if err:
            results.append(make_result("SVC-02", item, "SKIP", f"[{cluster_name}] vpc-cni addon 조회 실패: {err}"))
            continue

        info = addon_res["addon"]
        version_str = info.get("addonVersion", "")
        version = _parse_addon_version(version_str)
        version_ok = version is not None and version >= (1, 14)

        config_values = {}
        raw_cfg = info.get("configurationValues")
        if raw_cfg:
            try:
                config_values = json.loads(raw_cfg)
            except (TypeError, ValueError):
                config_values = {}
        enable_np = config_values.get("enableNetworkPolicy")
        np_ok = str(enable_np).lower() == "true"

        status = "PASS" if (version_ok and np_ok) else "FAIL"
        detail = (f"[{cluster_name}] addonVersion={version_str}(기준 >= 1.14), "
                  f"enableNetworkPolicy={enable_np}(기준 true)")
        results.append(make_result("SVC-02", item, status, detail))
    return results


def check_authn_14_tls_enforced(elbv2):
    """ALB에 평문(HTTP) 트래픽을 실제로 처리하는 리스너가 없어야 함
    (80번이 없거나 443 리다이렉트 전용이면 PASS)."""
    item = "전 구간 TLS/HTTPS 강제(엣지 종료)"
    lbs, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return [make_result("AUTHN-14", item, "SKIP", f"ALB 조회 실패: {err}")]

    plaintext = []
    for lb in lbs["LoadBalancers"]:
        listeners_res, lerr = safe_call(elbv2.describe_listeners, LoadBalancerArn=lb["LoadBalancerArn"])
        if lerr:
            continue
        for listener in listeners_res["Listeners"]:
            if listener["Protocol"] != "HTTP":
                continue
            redirects_to_https = any(
                a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                for a in listener.get("DefaultActions", [])
            )
            if not redirects_to_https:
                plaintext.append(f"{lb['LoadBalancerName']}:{listener['Port']}(HTTP, 443 리다이렉트 미설정)")

    status = "PASS" if not plaintext else "FAIL"
    detail = "평문 트래픽 처리 리스너: " + (
        ", ".join(plaintext) if plaintext else "없음(HTTP 리스너 없거나 전부 443 리다이렉트 전용)"
    )
    return [make_result("AUTHN-14", item, status, detail)]


def check_svc_08_ssm_bastion(ec2, ssm):
    """SG 22번 인바운드 차단·SSM 세션로그 연동 자동확인. MFA는 1.9와 중복되어
    config.SVC08_MFA_CROSS_CHECK_DONE 확정 전까지 REVIEW로 판정."""
    item = "운영관리자 SSM 접근·Bastion/SSH 미노출·MFA·세션로그"

    sgs, err = safe_call(ec2.describe_security_groups)
    if err:
        return [make_result("SVC-08", item, "SKIP", f"보안그룹 조회 실패: {err}")]

    ssh_offenders = []
    for sg in sgs["SecurityGroups"]:
        for perm in sg["IpPermissions"]:
            from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
            if from_port is None or to_port is None or not (from_port <= 22 <= to_port):
                continue
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if open_v4 or open_v6:
                ssh_offenders.append(f"{sg['GroupId']}(22번 인바운드 공개)")

    doc_res, derr = safe_call(ssm.get_document, Name="SSM-SessionManagerRunShell")
    session_log_configured = False
    session_log_note = f"조회 실패: {derr}" if derr else "미설정(기본 문서 그대로 — 로그 미연동)"
    if not derr:
        try:
            content = json.loads(doc_res["Content"])
            inputs = content.get("inputs", {})
            session_log_configured = bool(inputs.get("cloudWatchLogGroupName") or inputs.get("s3BucketName"))
            if session_log_configured:
                session_log_note = "설정됨"
        except (TypeError, ValueError, KeyError):
            session_log_configured = False

    if ssh_offenders or (not session_log_configured):
        status = "FAIL"
    elif config.SVC08_MFA_CROSS_CHECK_DONE:
        status = "PASS"
    else:
        status = "REVIEW"

    detail = (
        f"22번 포트 공개 SG: {', '.join(ssh_offenders) if ssh_offenders else '없음'} / "
        f"SSM 세션로그 CloudWatch·S3 연동: {session_log_note} / "
        f"MFA 강제 여부는 클라우드 1.9(MFA 설정) 판정과 중복되어 별도 확인 후 반영 예정"
        f"(config.SVC08_MFA_CROSS_CHECK_DONE={config.SVC08_MFA_CROSS_CHECK_DONE})"
    )
    return [make_result("SVC-08", item, status, detail)]


def run_all(eks, ec2, ssm, elbv2, cluster_names):
    results = []
    results += check_svc_02_vpc_cni(eks, cluster_names)
    results += check_authn_14_tls_enforced(elbv2)
    results += check_svc_08_ssm_bastion(ec2, ssm)
    return results
