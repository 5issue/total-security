"""3.10 — ELB(Elastic Load Balancing) 연결 관리 점검.

[2026-09-28 원문(2024 클라우드 보안가이드 p107~116) 기준 재작성] 원문 판단기준은 "ELB 제어
정책(AWS Security Hub ELB.1~16)을 준수하고 있는 경우 양호". 기존 9개 기준 중 원문 정책에 없는
SSL Policy·Idle Timeout·헬스체크·ALB 보안그룹·Cross-Zone(ELB.9는 Classic LB 전용)은 초기
분류표 착오라 판정에서 제외하고, 원문에 있는데 빠져 있던 ELB.4·ELB.12·ELB.13을 추가했다.
  ALB 대상: ELB.1(HTTP→HTTPS 리다이렉트) ELB.4(잘못된 헤더 삭제) ELB.5(로깅) ELB.6(삭제 방지)
            ELB.12(비동기화 완화 모드 defensive/strictest) ELB.16(WAF 웹 ACL 연결)
  ELBv2 전체(ALB/NLB/GWLB): ELB.13(2개 이상 가용 영역)
  Classic LB 전용 정책(ELB.2/3/7/8/9/10/14)은 CLB가 있을 때만 해당 — 이 스크립트는 CLB를
  점검하지 않으므로 CLB가 발견되면 REVIEW(수동 확인)로 표시한다.
ALB 보안그룹은 3.1/3.2, TLS 리스너는 4.4에서 판정한다.

[2026-09-23] ELB.16(WAF) — 인증인가 설계서상 "단계적 활성화"로 아직 미활성화 상태라 현재는
FAIL로 잡히는 게 정상(활성화 완료 시 자동 PASS 전환).

이 항목ID(3.10)는 분류표상 한 행이라, LB·정책별 위반사항을 모아 하나의 판정으로 집계한다.
"""
from .common import make_result, safe_call

ELB_MIN_AVAILABILITY_ZONES = 2   # ELB.13 — Security Hub 기본값
DESYNC_OK_MODES = ("defensive", "strictest")   # ELB.12


def _attr(attrs, key, default=None):
    return next((a["Value"] for a in attrs if a["Key"] == key), default)


def _check_alb(elbv2, wafv2, lb):
    arn = lb["LoadBalancerArn"]
    violations = []

    # ELB.1 — 모든 HTTP 리스너가 HTTPS로 리다이렉트
    listeners_res, lerr = safe_call(elbv2.describe_listeners, LoadBalancerArn=arn)
    if lerr:
        violations.append(f"ELB.1 리스너 조회 실패: {lerr}")
    else:
        for l in listeners_res["Listeners"]:
            if l.get("Protocol") != "HTTP":
                continue
            redirects = [a for a in l.get("DefaultActions", [])
                         if a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"]
            if not redirects:
                violations.append(f"ELB.1 HTTP:{l.get('Port')} 리스너 HTTPS 리다이렉트 미설정")

    # ELB.4/5/6/12 — 로드밸런서 속성
    attrs_res, aerr = safe_call(elbv2.describe_load_balancer_attributes, LoadBalancerArn=arn)
    if aerr:
        violations.append(f"ELB.4/5/6/12 속성 조회 실패: {aerr}")
    else:
        attrs = attrs_res["Attributes"]
        if _attr(attrs, "routing.http.drop_invalid_header_fields.enabled") != "true":
            violations.append("ELB.4 잘못된 HTTP 헤더 삭제 비활성화")
        if _attr(attrs, "access_logs.s3.enabled") != "true":
            violations.append("ELB.5 액세스 로그 비활성화")
        if _attr(attrs, "deletion_protection.enabled") != "true":
            violations.append("ELB.6 삭제 방지 비활성화")
        desync = _attr(attrs, "routing.http.desync_mitigation_mode")
        if desync not in DESYNC_OK_MODES:
            violations.append(f"ELB.12 비동기화 완화 모드={desync}(기준 defensive/strictest)")

    # ELB.16 — WAF 웹 ACL 연결
    webacl_res, werr = safe_call(wafv2.get_web_acl_for_resource, ResourceArn=arn)
    if werr:
        violations.append(f"ELB.16 WAF 연결 조회 실패: {werr}")
    elif not (webacl_res or {}).get("WebACL"):
        violations.append("ELB.16 WAF 웹 ACL 미연결")

    return violations


def check_3_10_elb_control_policy(elbv2, elb, wafv2):
    lbs_res, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", "SKIP", f"ELB 목록 조회 실패: {err}")]
    lbs = lbs_res["LoadBalancers"]
    clbs_res, cerr = safe_call(elb.describe_load_balancers)
    clb_names = [c["LoadBalancerName"] for c in clbs_res["LoadBalancerDescriptions"]] if not cerr else []

    if not lbs and not clb_names:
        # ⚠ RDS(3.8/4.2/4.9, 영구 미사용 확정)와 달리 ALB는 이 아키텍처에 실제로 존재하는
        # 핵심 리소스라 "없음"이 정책상 해당없음(N/A)일 수 없다 — 로컬 테스트 계정처럼
        # ALB 자체가 없는 환경이거나, 운영에서라면 조회 재확인이 필요해 SKIP이 맞다.
        return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", "SKIP",
                             "로드밸런서 없음 — 로컬 테스트 계정처럼 ALB 미사용 환경이거나 운영에서는 조회 결과 재확인 필요")]

    all_violations = []
    for lb in lbs:
        violations = _check_alb(elbv2, wafv2, lb) if lb.get("Type") == "application" else []
        azs = lb.get("AvailabilityZones", [])
        if len(azs) < ELB_MIN_AVAILABILITY_ZONES:
            violations.append(f"ELB.13 가용 영역 {len(azs)}개(기준 {ELB_MIN_AVAILABILITY_ZONES}개 이상)")
        if violations:
            all_violations.append(f"{lb['LoadBalancerName']}: " + "; ".join(violations))

    notes = []
    if cerr:
        notes.append(f"Classic LB 조회 실패(ELB.2/3/7/8/9/10/14 확인 불가): {cerr}")
    elif clb_names:
        notes.append(f"Classic LB 존재 — ELB.2/3/7/8/9/10/14 수동 확인 필요: {', '.join(clb_names)}")

    if all_violations:
        status = "FAIL"
    elif notes:
        status = "REVIEW"
    else:
        status = "PASS"
    detail = (" / ".join(all_violations) if all_violations
              else "ELB 제어 정책(ELB.1/4/5/6/12/13/16) 위반 없음")
    if notes:
        detail += " | " + " / ".join(notes)
    return [make_result("3.10", "ELB(Elastic Load Balancing) 연결 관리", status, detail)]


def run_all(elbv2, elb, wafv2):
    return check_3_10_elb_control_policy(elbv2, elb, wafv2)
