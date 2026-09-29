"""1.x, 2.x — IAM 사용자·그룹·정책 관리 점검."""
import csv
import io
import re
import time

import config
from .common import make_result, safe_call

IDENTITY_TAG_KEYS = {"name", "email", "dept", "department", "부서", "이름", "이메일"}
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _has_admin_policy(list_fn, **name_kw):
    """AdministratorAccess 연결 여부. 반환: True/False, 조회 실패 시 None."""
    res, err = safe_call(list_fn, **name_kw)
    return None if err else any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in res["AttachedPolicies"])


def check_1_1_user_account_management(iam):
    users, err = safe_call(iam.list_users)
    if err:
        return [make_result("1.1", "사용자 계정 관리", "SKIP", f"IAM 사용자 목록 조회 실패: {err}")]
    errors = []
    groups, gerr = safe_call(iam.list_groups)
    if gerr:
        errors.append(f"그룹 목록({gerr})")
    admin_groups = set()
    for g in ([] if gerr else groups["Groups"]):
        has = _has_admin_policy(iam.list_attached_group_policies, GroupName=g["GroupName"])
        if has is None:
            errors.append(f"그룹 {g['GroupName']} 정책")
        elif has:
            admin_groups.add(g["GroupName"])

    admin_users = {}   # 사용자 → 권한 경로(직접 / 그룹명)
    for u in users["Users"]:
        name = u["UserName"]
        has = _has_admin_policy(iam.list_attached_user_policies, UserName=name)
        if has is None:
            errors.append(f"사용자 {name} 정책")
        via = ["직접"] if has else []
        ugroups, ugerr = safe_call(iam.list_groups_for_user, UserName=name)
        if ugerr:
            errors.append(f"사용자 {name} 그룹")
        via += [f"그룹 {g['GroupName']}" for g in ([] if ugerr else ugroups["Groups"]) if g["GroupName"] in admin_groups]
        if via:
            admin_users[name] = via

    paginator = iam.get_paginator("list_roles")
    roles, rerr = safe_call(lambda: [r for page in paginator.paginate() for r in page["Roles"]])
    if rerr:
        errors.append(f"Role 목록({rerr})")
    admin_roles = []
    for r in ([] if rerr else roles):
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue   # AWS가 생성·관리하는 서비스 연결 역할
        has = _has_admin_policy(iam.list_attached_role_policies, RoleName=r["RoleName"])
        if has is None:
            errors.append(f"Role {r['RoleName']} 정책")
        elif has:
            admin_roles.append(r["RoleName"])

    all_names = [u["UserName"] for u in users["Users"]]
    blacklisted = [n for n in all_names if any(re.match(p, n) for p in config.TEST_ACCOUNT_NAME_PATTERNS)]
    admins_desc = ("관리자 권한(AdministratorAccess) 보유 — 사용자: "
                   + (", ".join(f"{n}({'/'.join(v)})" for n, v in admin_users.items()) or "없음")
                   + " / Role: " + (", ".join(admin_roles) or "없음"))

    if config.IAM_ADMIN_WHITELIST is None:
        status = "FAIL" if blacklisted else "SKIP"
        detail = ((f"테스트/불필요 계정 존재: {', '.join(blacklisted)} / " if blacklisted else "")
                  + "인가된 관리자 목록(config.IAM_ADMIN_WHITELIST) 미확정 — " + admins_desc)
    else:
        bad_users = [n for n in admin_users if n not in config.IAM_ADMIN_WHITELIST]
        bad_roles = [r for r in admin_roles if r not in config.IAM_ADMIN_ROLE_WHITELIST]
        status = "FAIL" if (blacklisted or bad_users or bad_roles) else ("REVIEW" if errors else "PASS")
        detail = ("테스트/불필요 계정: " + (", ".join(blacklisted) or "없음")
                  + " / 인가 목록 외 관리자 사용자: " + (", ".join(bad_users) or "없음")
                  + " / 인가 목록 외 관리자 Role: " + (", ".join(bad_roles) or "없음")
                  + " | " + admins_desc)
    if errors:
        detail += " / 조회 실패: " + ", ".join(errors[:5]) + (f" 외 {len(errors) - 5}건" if len(errors) > 5 else "")
    return [make_result("1.1", "사용자 계정 관리", status, detail)]


def check_1_2_iam_single_account(iam):
    if config.IAM_ACCOUNT_OWNER_MAP is None:
        users, err = safe_call(iam.list_users)
        names = [u["UserName"] for u in users["Users"]] if not err else []
        return [make_result("1.2", "IAM 사용자 계정 단일화 관리", "SKIP",
                             "계정-담당자 매핑표(config.IAM_ACCOUNT_OWNER_MAP) 미확정 — "
                             f"전체 IAM 사용자(참고용): {', '.join(names) if names else '없음'}")]
    exceptions = set(config.IAM_SHARED_ACCOUNT_EXCEPTIONS or [])
    owner_counts = {}
    for user_name, owner in config.IAM_ACCOUNT_OWNER_MAP.items():
        if user_name in exceptions:
            continue
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
    dup_owners = {owner: cnt for owner, cnt in owner_counts.items() if cnt > 1}

    users, err = safe_call(iam.list_users)
    unmapped = []
    if not err:
        unmapped = [u["UserName"] for u in users["Users"] if u["UserName"] not in config.IAM_ACCOUNT_OWNER_MAP]

    status = "PASS" if not dup_owners and not unmapped else "FAIL"
    detail = ("1인 다중 계정 보유자: " + (str(dup_owners) if dup_owners else "없음")
              + " / 매핑표 외 신규·미상 계정: " + (", ".join(unmapped) if unmapped else "없음"))
    return [make_result("1.2", "IAM 사용자 계정 단일화 관리", status, detail)]


def check_1_3_user_identity_tags(iam):
    users, err = safe_call(iam.list_users)
    if err:
        return [make_result("1.3", "IAM 사용자 계정 식별 관리", "SKIP", f"IAM 사용자 목록 조회 실패: {err}")]
    missing = []
    for u in users["Users"]:
        tags, terr = safe_call(iam.list_user_tags, UserName=u["UserName"])
        keys = {t["Key"].lower() for t in tags["Tags"]} if not terr else set()
        if not (keys & IDENTITY_TAG_KEYS):
            missing.append(u["UserName"])
    status = "PASS" if not missing else "FAIL"
    detail = "식별 태그(Name/Email/Dept 등) 없는 사용자: " + (", ".join(missing) if missing else "없음")
    return [make_result("1.3", "IAM 사용자 계정 식별 관리", status, detail)]


def check_1_4_group_membership(iam):
    groups, err = safe_call(iam.list_groups)
    if err:
        return [make_result("1.4", "IAM 그룹 사용자 계정 관리", "SKIP", f"IAM 그룹 목록 조회 실패: {err}")]
    membership = {}
    for g in groups["Groups"]:
        users, uerr = safe_call(iam.get_group, GroupName=g["GroupName"])
        membership[g["GroupName"]] = [u["UserName"] for u in users["Users"]] if not uerr else []
    if config.IAM_GROUP_WHITELIST is None:
        detail = "그룹별 구성원(화이트리스트 TODO, 참고용): " + str(membership)
        return [make_result("1.4", "IAM 그룹 사용자 계정 관리", "SKIP", detail)]
    unauthorized = {
        g: [u for u in users if u not in config.IAM_GROUP_WHITELIST.get(g, [])]
        for g, users in membership.items()
    }
    unauthorized = {g: u for g, u in unauthorized.items() if u}
    status = "PASS" if not unauthorized else "FAIL"
    return [make_result("1.4", "IAM 그룹 사용자 계정 관리", status, f"화이트리스트 외 구성원: {unauthorized}")]


def _ssh_inbound_open(perm):
    proto = perm.get("IpProtocol")
    return proto == "-1" or (proto in ("tcp", "6") and perm.get("FromPort", 0) <= 22 <= perm.get("ToPort", -1))


def check_1_5_keypair_access(ec2):
    reservations, err = safe_call(ec2.describe_instances)
    if err:
        return [make_result("1.5", "Key Pair 접근 관리", "SKIP", f"EC2 인스턴스 조회 실패: {err}")]
    sgs, serr = safe_call(ec2.describe_security_groups)
    if serr:
        return [make_result("1.5", "Key Pair 접근 관리", "SKIP", f"보안그룹 조회 실패: {serr}")]
    ssh_open_sgs = {sg["GroupId"] for sg in sgs["SecurityGroups"]
                    if any(_ssh_inbound_open(p) for p in sg["IpPermissions"])}
    with_keypair, ssm_only, ssh_exposed = [], [], []
    for res in reservations["Reservations"]:
        for inst in res["Instances"]:
            if inst.get("KeyName"):
                with_keypair.append(inst["InstanceId"])
                continue
            open_sgs = sorted({g["GroupId"] for g in inst.get("SecurityGroups", [])} & ssh_open_sgs)
            if open_sgs:
                ssh_exposed.append(f"{inst['InstanceId']}({', '.join(open_sgs)})")
            else:
                ssm_only.append(inst["InstanceId"])
    status = "FAIL" if ssh_exposed else "PASS"
    detail = ("Key Pair 없이 SSH(22) 인바운드가 열린 인스턴스(패스워드 접근 가능성): "
              + (", ".join(ssh_exposed) if ssh_exposed else "없음")
              + f" / Key Pair 미사용·SSH 인바운드 차단(SSM 전용 접속, 패스워드 접근 경로 없음): {len(ssm_only)}대"
              + " / Key Pair 사용 인스턴스: " + (", ".join(with_keypair) if with_keypair else "없음"))
    return [make_result("1.5", "Key Pair 접근 관리", status, detail)]


def check_1_6_keypair_storage(ec2):
    reservations, err = safe_call(ec2.describe_instances)
    if err:
        return [make_result("1.6", "Key Pair 보관 관리", "SKIP", f"EC2 인스턴스 조회 실패: {err}")]
    with_keypair = []
    for res in reservations["Reservations"]:
        for inst in res["Instances"]:
            if inst.get("KeyName"):
                with_keypair.append(f"{inst['InstanceId']}({inst['KeyName']})")
    status = "FAIL" if with_keypair else "N/A"
    detail = ("Key Pair 사용 인스턴스 발견(예외 상황, 보관위치 수동 확인 필요): " + ", ".join(with_keypair)
              if with_keypair else "EC2 Key Pair 미사용 확정(SSM 접속) — 점검 대상 자체 없음")
    return [make_result("1.6", "Key Pair 보관 관리", status, detail)]


def _root_credential_row(iam):
    for _ in range(5):
        gen, gerr = safe_call(iam.generate_credential_report)
        if not gerr and gen.get("State") == "COMPLETE":
            break
        time.sleep(1)
    report, rerr = safe_call(iam.get_credential_report)
    if rerr:
        return None, f"Credential Report 조회 실패: {rerr}"
    reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
    root_row = next((row for row in reader if row["user"] == "<root_account>"), None)
    return root_row, (None if root_row else "Credential Report에 root 계정 행 없음")


def _root_key_active(root_row):
    return root_row.get("access_key_1_active") == "true" or root_row.get("access_key_2_active") == "true"


def check_1_7_admin_console_policy(iam):
    root_row, rerr = _root_credential_row(iam)
    if rerr:
        return [make_result("1.7", "Admin Console 관리자 정책 관리", "SKIP", rerr)]
    key_active = _root_key_active(root_row)
    status = "FAIL" if key_active else "PASS"
    detail = f"root Access Key 존재={key_active}, password_last_used={root_row.get('password_last_used')}"
    return [make_result("1.7", "Admin Console 관리자 정책 관리", status, detail)]


def check_1_8_access_key_lifecycle(iam, configservice):
    root_row, rerr = _root_credential_row(iam)
    root_note = ("root 계정 Access Key 확인 실패: " + rerr) if rerr else \
        ("root 계정 Access Key 존재" if _root_key_active(root_row) else "root 계정 Access Key 없음")
    root_bad = bool(root_row) and _root_key_active(root_row)
    result, err = safe_call(
        configservice.describe_compliance_by_config_rule,
        ConfigRuleNames=[config.ACCESS_KEY_ROTATION_CONFIG_RULE],
    )
    rules = [] if err else result.get("ComplianceByConfigRules", [])
    if err or not rules:
        key_note = (f"AWS Config Rule({config.ACCESS_KEY_ROTATION_CONFIG_RULE}) 조회 실패: {err}" if err
                    else f"Config Rule({config.ACCESS_KEY_ROTATION_CONFIG_RULE}) 미존재 — 배포 여부 확인 필요")
        return [make_result("1.8", "Admin Console 계정 Access Key 활성화 및 사용주기 관리",
                             "FAIL" if root_bad else "SKIP", f"{root_note} / IAM 사용자 키: {key_note}")]
    compliance_type = rules[0]["Compliance"]["ComplianceType"]
    if root_bad or compliance_type != "COMPLIANT":
        status = "FAIL"
    elif rerr:
        status = "REVIEW"
    else:
        status = "PASS"
    detail = f"{root_note} / IAM 사용자 키 60일 주기 Config Rule({config.ACCESS_KEY_ROTATION_CONFIG_RULE}): {compliance_type}"
    return [make_result("1.8", "Admin Console 계정 Access Key 활성화 및 사용주기 관리", status, detail)]


def check_1_9_mfa(iam):
    users, err = safe_call(iam.list_users)
    if err:
        return [make_result("1.9", "MFA(Multi-Factor Authentication) 설정", "SKIP", f"IAM 사용자 목록 조회 실패: {err}")]
    no_mfa = []
    for u in users["Users"]:
        _, lp_err = safe_call(iam.get_login_profile, UserName=u["UserName"])
        if lp_err:
            continue
        devices, derr = safe_call(iam.list_mfa_devices, UserName=u["UserName"])
        if not derr and not devices["MFADevices"]:
            no_mfa.append(u["UserName"])
    summary, serr = safe_call(iam.get_account_summary)
    root_mfa_off = (not serr) and summary["SummaryMap"].get("AccountMFAEnabled", 0) == 0
    status = "PASS" if not no_mfa and not root_mfa_off else "FAIL"
    detail = "MFA 미설정 콘솔 사용자: " + (", ".join(no_mfa) if no_mfa else "없음") + \
             (" / root 계정 MFA 미설정" if root_mfa_off else "")
    return [make_result("1.9", "MFA(Multi-Factor Authentication) 설정", status, detail)]


def check_1_10_password_policy(iam):
    policy, err = safe_call(iam.get_account_password_policy)
    if err:
        return [make_result("1.10", "AWS 계정 패스워드 정책 관리", "FAIL", "패스워드 정책 미설정")]
    p = policy["PasswordPolicy"]
    ok = (
        p.get("MinimumPasswordLength", 0) >= 8
        and p.get("RequireSymbols") and p.get("RequireNumbers")
        and p.get("RequireUppercaseCharacters") and p.get("RequireLowercaseCharacters")
        and p.get("MaxPasswordAge") and p.get("PasswordReusePrevention")
    )
    status = "PASS" if ok else "FAIL"
    return [make_result("1.10", "AWS 계정 패스워드 정책 관리", status, str(p))]



def run_all(iam, ec2, configservice):
    results = []
    results += check_1_1_user_account_management(iam)
    results += check_1_2_iam_single_account(iam)
    results += check_1_3_user_identity_tags(iam)
    results += check_1_4_group_membership(iam)
    results += check_1_5_keypair_access(ec2)
    results += check_1_6_keypair_storage(ec2)
    results += check_1_7_admin_console_policy(iam)
    results += check_1_8_access_key_lifecycle(iam, configservice)
    results += check_1_9_mfa(iam)
    results += check_1_10_password_policy(iam)
    return results
