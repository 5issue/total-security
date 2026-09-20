"""3.10 — ELB(ALB) 연결 관리(제어 정책) 점검.

인프라팀 협의 완료(2026-09-13, 8/8 전체 확정)로 판정유형 "제외"→"자동판정가능"으로
전환: ①리스너 443+80리다이렉트 ②SSL Policy TLS1.2 미만 미사용 ③액세스로그 활성화
(SSE-S3) ④Deletion Protection 활성화 ⑤Idle Timeout >= 60초(config.ELB_IDLE_TIMEOUT_
SECONDS) ⑥헬스체크(경로 /, 200-399, 기본값 15초/5초/2/2) ⑦ALB 보안그룹 443/80만
허용 ⑧Cross-Zone Load Balancing 자동활성화.

이 항목ID(3.10)는 분류표상 한 행이라, ALB/기준별 위반사항을 모아 하나의 PASS/FAIL로
집계한다(개별 ALB 위반 내역은 상세 컬럼에 나열).
"""
import config
from .common import make_result, safe_call

# ② SSL Policy — TLS1.2 미만을 포함하는 AWS 관리형 정책명 패턴(휴리스틱).
#   실제 계정에 커스텀 정책이 있다면 이름만으로 판단이 어려우니 수동 대조 권장.
WEAK_SSL_POLICY_MARKERS = ("TLS-1-0", "TLS-1-1", "2016-08")


def _attr(attrs, key, default=None):
    return next((a["Value"] for a in attrs if a["Key"] == key), default)


def _http_code_covers_2xx_3xx(matcher_code: str) -> bool:
    if not matcher_code:
        return False
    for part in matcher_code.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            if not (lo.strip().startswith(("2", "3")) and hi.strip().startswith(("2", "3"))):
                return False
        elif not part.startswith(("2", "3")):
            return False
    return True


def _check_alb(elbv2, ec2, lb):
    name = lb["LoadBalancerName"]
    arn = lb["LoadBalancerArn"]
    violations = []

    attrs_res, aerr = safe_call(elbv2.describe_load_balancer_attributes, LoadBalancerArn=arn)
    attrs = attrs_res["Attributes"] if not aerr else []

    listeners_res, lerr = safe_call(elbv2.describe_listeners, LoadBalancerArn=arn)
    listeners = listeners_res["Listeners"] if not lerr else []
    ports = {l["Port"]: l for l in listeners}

    # ① 리스너 443(HTTPS) + 80 → 443 리다이렉트
    l443, l80 = ports.get(443), ports.get(80)
    if not l443 or l443.get("Protocol") != "HTTPS":
        violations.append("443/HTTPS 리스너 없음")
    if not l80:
        violations.append("80 리스너 없음")
    else:
        redirects = [a for a in l80.get("DefaultActions", [])
                     if a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"]
        if not redirects:
            violations.append("80→443 리다이렉트 미설정")

    # ② SSL Policy TLS1.2 미만 미사용
    if l443:
        policy = l443.get("SslPolicy", "") or ""
        if any(marker in policy for marker in WEAK_SSL_POLICY_MARKERS):
            violations.append(f"약한 SSL Policy: {policy}")

    # ③ 액세스 로그 활성화(SSE-S3)
    if _attr(attrs, "access_logs.s3.enabled") != "true":
        violations.append("액세스 로그(S3) 비활성화")

    # ④ Deletion Protection 활성화
    if _attr(attrs, "deletion_protection.enabled") != "true":
        violations.append("Deletion Protection 비활성화")

    # ⑤ Idle Timeout — [확정 2026-09-13] 절대기준 ">= 60초"(정확히 60초도 PASS, `<`로만 FAIL)
    idle_timeout = _attr(attrs, "idle_timeout.timeout_seconds")
    idle_note = f"Idle Timeout={idle_timeout}s"
    if config.ELB_IDLE_TIMEOUT_SECONDS is not None and idle_timeout is not None:
        if int(idle_timeout) < int(config.ELB_IDLE_TIMEOUT_SECONDS):
            violations.append(f"Idle Timeout {idle_timeout}s (기준 {config.ELB_IDLE_TIMEOUT_SECONDS}s 이상)")
        idle_note += f" (기준 {config.ELB_IDLE_TIMEOUT_SECONDS}s 이상)"
    else:
        idle_note += " (기준값 미확정 — 판정 제외)"

    # ⑥ 헬스체크 경로 '/'(또는 config.ELB_HEALTHCHECK_PATH_EXCEPTIONS 예외), 200-399,
    #   기본값(간격15초/타임아웃5초/정상2/비정상2)
    tgs_res, terr = safe_call(elbv2.describe_target_groups, LoadBalancerArn=arn)
    healthcheck_allowed_paths = {"/"} | set(config.ELB_HEALTHCHECK_PATH_EXCEPTIONS or [])
    for tg in (tgs_res["TargetGroups"] if not terr else []):
        tg_name = tg["TargetGroupName"]
        if tg.get("HealthCheckPath") not in healthcheck_allowed_paths:
            violations.append(f"헬스체크({tg_name}) 경로={tg.get('HealthCheckPath')}(기준 '/' 또는 예외목록 {sorted(healthcheck_allowed_paths)})")
        matcher_code = tg.get("Matcher", {}).get("HttpCode", "")
        if not _http_code_covers_2xx_3xx(matcher_code):
            violations.append(f"헬스체크({tg_name}) HttpCode={matcher_code}(기준 200-399)")
        if (tg.get("HealthCheckIntervalSeconds") != 15 or tg.get("HealthCheckTimeoutSeconds") != 5
                or tg.get("HealthyThresholdCount") != 2 or tg.get("UnhealthyThresholdCount") != 2):
            violations.append(f"헬스체크({tg_name}) 간격/타임아웃/임계값 기본값(15/5/2/2) 아님")

    # ⑦ ALB 보안그룹 443/80만 허용
    sg_ids = lb.get("SecurityGroups", [])
    if not sg_ids:
        violations.append("ALB에 연결된 보안그룹 없음")
    else:
        sgs_res, serr = safe_call(ec2.describe_security_groups, GroupIds=sg_ids)
        for sg in (sgs_res["SecurityGroups"] if not serr else []):
            for perm in sg["IpPermissions"]:
                from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
                if (from_port, to_port) not in ((443, 443), (80, 80)):
                    violations.append(f"보안그룹({sg['GroupId']}) 인바운드 {from_port}-{to_port}(443/80 외)")

    # ⑧ Cross-Zone Load Balancing 자동활성화
    if _attr(attrs, "load_balancing.cross_zone.enabled") == "false":
        violations.append("Cross-Zone Load Balancing 비활성화")

    return violations, idle_note


def check_3_10_elb_control_policy(elbv2, ec2):
    lbs_res, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", "SKIP", f"ELB 목록 조회 실패: {err}")]
    albs = [lb for lb in lbs_res["LoadBalancers"] if lb.get("Type") == "application"]
    if not albs:
        # ⚠ RDS(3.8/4.2/4.9, 영구 미사용 확정)와 달리 ALB는 이 아키텍처에 실제로 존재하는
        # 핵심 리소스라 "없음"이 정책상 해당없음(N/A)일 수 없다 — 로컬 테스트 계정처럼
        # ALB 자체가 없는 환경이거나, 운영에서라면 조회 재확인이 필요해 SKIP이 맞다.
        return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", "SKIP",
                             "ALB 없음 — 로컬 테스트 계정처럼 ALB 미사용 환경이거나 운영에서는 조회 결과 재확인 필요")]

    all_violations = []
    idle_notes = []
    for lb in albs:
        violations, idle_note = _check_alb(elbv2, ec2, lb)
        idle_notes.append(f"{lb['LoadBalancerName']}: {idle_note}")
        if violations:
            all_violations.append(f"{lb['LoadBalancerName']}: " + "; ".join(violations))

    status = "PASS" if not all_violations else "FAIL"
    detail = ("확정 7개 항목 위반 없음" if not all_violations else " / ".join(all_violations))
    detail += " | " + ", ".join(idle_notes)
    return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", status, detail)]


def run_all(elbv2, ec2):
    return check_3_10_elb_control_policy(elbv2, ec2)
