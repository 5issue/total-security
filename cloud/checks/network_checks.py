"""3.x — VPC/보안그룹/NACL/라우팅 네트워크 점검."""
import config
from .common import make_result, safe_call


def check_3_1_sg_any(ec2):
    sgs, err = safe_call(ec2.describe_security_groups)
    if err:
        return [make_result("3.1", "보안 그룹 인/아웃바운드 ANY 설정 관리", "SKIP", f"보안그룹 조회 실패: {err}")]
    offenders = []
    for sg in sgs["SecurityGroups"]:
        for direction, perms in (("in", sg["IpPermissions"]), ("out", sg["IpPermissionsEgress"])):
            for perm in perms:
                # 2026-09-24 — 원문 기준은 "포트가 Any로 허용"이므로 모든 트래픽(-1)뿐 아니라
                # TCP/UDP 전체 포트 범위(0~65535, 1~65535)도 Any로 판정(프로토콜만 바꿔 우회하는 경우 방지)
                is_any_proto = perm.get("IpProtocol") == "-1"
                is_all_ports = (perm.get("IpProtocol") in ("tcp", "udp", "6", "17")
                                and perm.get("FromPort", 65535) <= 1 and perm.get("ToPort", 0) >= 65535)
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if (is_any_proto or is_all_ports) and (open_v4 or open_v6):
                    offenders.append(f"{sg['GroupId']}({direction})")
    status = "PASS" if not offenders else "FAIL"
    detail = "전체(ANY) 허용 규칙 보유 SG: " + (", ".join(offenders) if offenders else "없음")
    return [make_result("3.1", "보안 그룹 인/아웃바운드 ANY 설정 관리", status, detail)]


def _internet_facing_alb_sg_ids(elbv2):
    lbs, err = safe_call(elbv2.describe_load_balancers)
    if err:
        return None, err
    return {sg for lb in lbs["LoadBalancers"]
            if lb.get("Scheme") == "internet-facing" for sg in lb.get("SecurityGroups", [])}, None


def check_3_2_sg_unnecessary_rules(ec2, elbv2):
    # [확정 — 2026-09-13 인프라팀 노션 회신] 인바운드는 VPC 내부 대역(SG_ALLOWED_INBOUND_CIDR)
    # 만 전체 허용, 외부 인터넷(0.0.0.0/0) 인바운드는 전면 차단. 아웃바운드의 0.0.0.0/0은
    # 정상이므로 방향(인바운드/아웃바운드) 구분이 필수 — 인바운드만 판정 대상.
    # [2026-09-28 인프라팀 회신] internet-facing ALB에 붙은 SG는 ALB_PUBLIC_INBOUND_PORTS의
    # 외부 인바운드를 허용(ALB 동작에 필수). SG ID는 재생성 때 바뀌므로 ALB 연결로 자동 탐지.
    # ALB 조회가 실패하면 예외 없이 판정(FAIL로 남고 상세에 사유 표시).
    sgs, err = safe_call(ec2.describe_security_groups)
    if err:
        return [make_result("3.2", "보안 그룹 인/아웃바운드 불필요 정책 관리", "SKIP", f"보안그룹 조회 실패: {err}")]
    alb_sg_ids, alb_err = _internet_facing_alb_sg_ids(elbv2)
    alb_sg_ids = alb_sg_ids or set()
    allowed_ports = set(config.ALB_PUBLIC_INBOUND_PORTS)
    offenders = []
    for sg in sgs["SecurityGroups"]:
        for perm in sg["IpPermissions"]:
            is_alb_port = (sg["GroupId"] in alb_sg_ids and perm.get("IpProtocol") in ("tcp", "6")
                           and perm.get("FromPort") == perm.get("ToPort") in allowed_ports)
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp")
                if cidr and cidr != config.SG_ALLOWED_INBOUND_CIDR and not (is_alb_port and cidr == "0.0.0.0/0"):
                    offenders.append(f"{sg['GroupId']}(inbound {cidr})")
            for r in perm.get("Ipv6Ranges", []):
                if r.get("CidrIpv6") and not (is_alb_port and r["CidrIpv6"] == "::/0"):
                    offenders.append(f"{sg['GroupId']}(inbound {r['CidrIpv6']})")
    status = "PASS" if not offenders else "FAIL"
    detail = (f"허용 대역({config.SG_ALLOWED_INBOUND_CIDR}) 외 인바운드 규칙: "
              + (", ".join(offenders) if offenders else "없음")
              + (f" / internet-facing ALB SG({', '.join(sorted(alb_sg_ids))})는 TCP {sorted(allowed_ports)} 외부 허용"
                 if alb_sg_ids else "")
              + (f" / ALB 조회 실패로 ALB 예외 미적용: {alb_err}" if alb_err else ""))
    return [make_result("3.2", "보안 그룹 인/아웃바운드 불필요 정책 관리", status, detail)]


def check_3_3_nacl(ec2):
    nacls, err = safe_call(ec2.describe_network_acls)
    if err:
        return [make_result("3.3", "네트워크 ACL 인/아웃바운드 트래픽 정책 관리", "SKIP", f"NACL 조회 실패: {err}")]
    offenders = []
    for nacl in nacls["NetworkAcls"]:
        for entry in nacl["Entries"]:
            if (entry.get("Protocol") == "-1" and entry.get("RuleAction") == "allow"
                    and entry.get("CidrBlock") == "0.0.0.0/0"):
                direction = "egress" if entry.get("Egress") else "ingress"
                offenders.append(f"{nacl['NetworkAclId']}({direction})")
    status = "PASS" if not offenders else "FAIL"
    detail = "전체 허용(Any-Any) 규칙 보유 NACL: " + (", ".join(offenders) if offenders else "없음")
    return [make_result("3.3", "네트워크 ACL 인/아웃바운드 트래픽 정책 관리", status, detail)]


def check_3_4_route_table(ec2):
    rts, err = safe_call(ec2.describe_route_tables)
    if err:
        return [make_result("3.4", "라우팅 테이블 정책 관리", "SKIP", f"라우팅테이블 조회 실패: {err}")]
    offenders = []
    for rt in rts["RouteTables"]:
        any_routes = [r for r in rt["Routes"] if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
        blackholes = [r for r in any_routes if r.get("State") == "blackhole"]
        if len(any_routes) > 1 or blackholes:
            offenders.append(rt["RouteTableId"])
    status = "PASS" if not offenders else "FAIL"
    detail = "중복/불량(blackhole) ANY 라우트 보유 라우팅테이블: " + (", ".join(offenders) if offenders else "없음")
    return [make_result("3.4", "라우팅 테이블 정책 관리", status, detail)]


def _subnet_route_table_map(ec2):
    """서브넷ID -> 연결된 라우팅테이블ID (명시적 연결 없으면 VPC의 Main 라우팅테이블)."""
    rts, err = safe_call(ec2.describe_route_tables)
    if err:
        return {}, {}
    subnet_to_rt, main_rt_by_vpc = {}, {}
    for rt in rts["RouteTables"]:
        for assoc in rt["Associations"]:
            if assoc.get("SubnetId"):
                subnet_to_rt[assoc["SubnetId"]] = rt
            if assoc.get("Main"):
                main_rt_by_vpc[rt["VpcId"]] = rt
    return subnet_to_rt, main_rt_by_vpc


def check_3_5_igw_nat_gateway(ec2):
    # [2026-09-28 원문(2024 클라우드 가이드 3.5) 재대조] 원문 양호: 인터넷 게이트웨이에 불필요하게 연결된
    # NAT 게이트웨이가 존재하지 않는 경우. 기존엔 "프라이빗 서브넷의 IGW 직접 경로"를 봤는데 원문 기준이
    # 아니었음 → 사용 가능한 NAT 게이트웨이 중 어떤 라우팅 테이블도 경유하지 않는(불필요한) 것을 FAIL.
    # NAT 게이트웨이를 쓰지 않으면(NAT 인스턴스 사용) 불필요한 연결이 없으므로 양호.
    nat_gws, err = safe_call(ec2.describe_nat_gateways, Filter=[{"Name": "state", "Values": ["available"]}])
    if err:
        return [make_result("3.5", "인터넷 게이트웨이 연결 관리", "SKIP", f"NAT 게이트웨이 조회 실패: {err}")]
    rts, rerr = safe_call(ec2.describe_route_tables)
    if rerr:
        return [make_result("3.5", "인터넷 게이트웨이 연결 관리", "SKIP", f"라우팅테이블 조회 실패: {rerr}")]
    routed = {r.get("NatGatewayId") for rt in rts["RouteTables"] for r in rt["Routes"] if r.get("NatGatewayId")}
    all_ids = [g["NatGatewayId"] for g in nat_gws["NatGateways"]]
    unused = [g for g in all_ids if g not in routed]
    status = "PASS" if not unused else "FAIL"
    detail = (f"NAT 게이트웨이 {len(all_ids)}개 중 어떤 라우팅 테이블도 경유하지 않는(불필요한) NAT 게이트웨이: "
              + (", ".join(unused) if unused else "없음")
              + ("" if all_ids else " (NAT 게이트웨이 미사용)"))
    return [make_result("3.5", "인터넷 게이트웨이 연결 관리", status, detail)]


def check_3_6_nat_management(ec2):
    # [확정 — 2026-09-13 인프라팀 노션 회신] NAT 경유지(인스턴스명)·퍼블릭 서브넷·NAT를
    # 사용하는 프라이빗 서브넷 대역까지 전부 확정(config.NAT_PURPOSE_CONFIRMED_RESOURCES).
    reservations, err = safe_call(ec2.describe_instances)
    if err:
        return [make_result("3.6", "NAT 게이트웨이 연결 관리", "SKIP", f"EC2 인스턴스 조회 실패: {err}")]
    nat_instances = []
    for res in reservations["Reservations"]:
        for inst in res["Instances"]:
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            if "nat" in name.lower():
                nat_instances.append(inst)

    offenders = []
    for inst in nat_instances:
        attr, aerr = safe_call(ec2.describe_instance_attribute, InstanceId=inst["InstanceId"],
                                Attribute="sourceDestCheck")
        if not aerr and attr["SourceDestCheck"]["Value"] is True:
            offenders.append(f"{inst['InstanceId']}(source/dest check 활성화)")

    confirmed = config.NAT_PURPOSE_CONFIRMED_RESOURCES
    if confirmed is not None:
        expected_names = set(confirmed.get("nat_instance_names", []))
        found_names = {
            next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            for inst in nat_instances
        }
        unexpected_names = found_names - expected_names
        missing_names = expected_names - found_names
        if unexpected_names:
            offenders.append(f"목적 미확인 NAT 인스턴스(Name 미매칭): {', '.join(unexpected_names)}")
        if missing_names:
            offenders.append(f"확정된 NAT 경유지 중 미발견: {', '.join(missing_names)}")

        # [2026-09-28 원문 재대조] 원문 취약: 목적이 확인되지 않은 리소스가 NAT에 연결된 경우 — NAT(인스턴스·
        # 게이트웨이)로 기본 경로(0.0.0.0/0)를 보내는 서브넷이 확정된 프라이빗 서브넷 대역인지 확인.
        # 기존엔 allowed_private_subnet_cidrs 값을 두고도 판정에 쓰지 않았음.
        allowed_cidrs = set(confirmed.get("allowed_private_subnet_cidrs", []))
        nat_ids = {inst["InstanceId"] for inst in nat_instances}
        nat_enis = {eni["NetworkInterfaceId"] for inst in nat_instances for eni in inst.get("NetworkInterfaces", [])}
        subnets, serr = safe_call(ec2.describe_subnets)
        subnet_to_rt, main_rt_by_vpc = _subnet_route_table_map(ec2)
        if serr:
            offenders.append(f"NAT 연결 서브넷 확인 실패: {serr}")
        else:
            for subnet in subnets["Subnets"]:
                rt = subnet_to_rt.get(subnet["SubnetId"]) or main_rt_by_vpc.get(subnet["VpcId"])
                uses_nat = rt and any(
                    r.get("DestinationCidrBlock") == "0.0.0.0/0"
                    and (r.get("InstanceId") in nat_ids or r.get("NetworkInterfaceId") in nat_enis or r.get("NatGatewayId"))
                    for r in rt["Routes"])
                if uses_nat and subnet["CidrBlock"] not in allowed_cidrs:
                    offenders.append(f"목적 미확인 서브넷의 NAT 경유: {subnet['SubnetId']}({subnet['CidrBlock']})")

    status = "PASS" if nat_instances and not offenders else ("FAIL" if offenders else "REVIEW")
    detail = (
        f"NAT 인스턴스(Name 태그 'nat' 포함) {len(nat_instances)}대"
        + (f" — 위반: {', '.join(offenders)}" if offenders else " — 위반 없음")
        + (f" (확정 경유지: {', '.join(confirmed.get('nat_instance_names', []))})" if confirmed is not None
           else " — '목적 확인된 리소스 목록' 대조는 별도 확인 필요(config.NAT_PURPOSE_CONFIRMED_RESOURCES TODO)")
    )
    return [make_result("3.6", "NAT 게이트웨이 연결 관리", status, detail)]


def run_all(ec2, elbv2):
    results = []
    results += check_3_1_sg_any(ec2)
    results += check_3_2_sg_unnecessary_rules(ec2, elbv2)
    results += check_3_3_nacl(ec2)
    results += check_3_4_route_table(ec2)
    results += check_3_5_igw_nat_gateway(ec2)
    results += check_3_6_nat_management(ec2)
    return results
