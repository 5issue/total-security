"""1.x, 2.x — IAM 사용자·그룹·정책 관리 점검."""
import config
from .common import age_in_days, make_result, safe_call

IDENTITY_TAG_KEYS = {"name", "email", "dept", "department", "부서", "이름", "이메일"}


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


def check_1_5_keypair_access(ec2):
    reservations, err = safe_call(ec2.describe_instances)
    if err:
        return [make_result("1.5", "Key Pair 접근 관리", "SKIP", f"EC2 인스턴스 조회 실패: {err}")]
    no_keypair = []
    for res in reservations["Reservations"]:
        for inst in res["Instances"]:
            if not inst.get("KeyName"):
                no_keypair.append(inst["InstanceId"])
    status = "PASS" if not no_keypair else "FAIL"
    detail = "Key Pair 미설정 인스턴스: " + (", ".join(no_keypair) if no_keypair else "없음")
    return [make_result("1.5", "Key Pair 접근 관리", status, detail)]


def check_1_6_keypair_storage():
    return [make_result("1.6", "Key Pair 보관 관리", "SKIP", config.KEY_PAIR_STORAGE_CHECK_NOTE)]


def check_1_8_access_key_lifecycle(iam):
    users, err = safe_call(iam.list_users)
    if err:
        return [make_result("1.8", "Admin Console 계정 Access Key 활성화 및 사용주기 관리", "SKIP",
                             f"IAM 사용자 목록 조회 실패: {err}")]
    violations = []
    for u in users["Users"]:
        keys, kerr = safe_call(iam.list_access_keys, UserName=u["UserName"])
        if kerr:
            continue
        for k in keys["AccessKeyMetadata"]:
            if k["Status"] == "Active" and age_in_days(k["CreateDate"]) > config.ACCESS_KEY_MAX_AGE_DAYS:
                violations.append(f"{u['UserName']}({age_in_days(k['CreateDate'])}일)")
    status = "PASS" if not violations else "FAIL"
    detail = (f"기준({config.ACCESS_KEY_MAX_AGE_DAYS}일) 초과 Access Key: " +
              (", ".join(violations) if violations else "없음"))
    return [make_result("1.8", "Admin Console 계정 Access Key 활성화 및 사용주기 관리", status, detail)]


def check_1_9_mfa(iam):
    users, err = safe_call(iam.list_users)
    if err:
        return [make_result("1.9", "MFA(Multi-Factor Authentication) 설정", "SKIP", f"IAM 사용자 목록 조회 실패: {err}")]
    no_mfa = []
    for u in users["Users"]:
        # 콘솔 로그인 프로필 없는 사용자(Access Key 전용)는 MFA 대상에서 제외
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


def check_1_11_eks_user_management():
    return [make_result("1.11", "EKS 사용자 관리", "SKIP",
                         "인가된 EKS 접근 사용자 화이트리스트(config.EKS_ACCESS_WHITELIST) 미확정")]


def check_2_x_service_policies():
    if config.SERVICE_IAM_POLICY_MAP is not None:
        status, detail = "REVIEW", "서비스별 IAM 정책 매핑 존재 — 실제 IAM 정책과 대조 필요"
    else:
        status = "SKIP"
        detail = "서비스 역할별 필요권한 정의서(config.SERVICE_IAM_POLICY_MAP) 미확정 — API 명세서 기반 매핑 진행 중"
    return [
        make_result("2.1", "인스턴스 서비스 정책 관리", status, detail),
        make_result("2.2", "네트워크 서비스 정책 관리", status, detail),
        make_result("2.3", "기타 서비스 정책 관리", status, detail),
    ]


def run_all(iam, ec2):
    results = []
    results += check_1_3_user_identity_tags(iam)
    results += check_1_4_group_membership(iam)
    results += check_1_5_keypair_access(ec2)
    results += check_1_6_keypair_storage()
    results += check_1_8_access_key_lifecycle(iam)
    results += check_1_9_mfa(iam)
    results += check_1_10_password_policy(iam)
    results += check_1_11_eks_user_management()
    results += check_2_x_service_policies()
    return results
