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


def check_3_2_sg_unnecessary_rules(ec2):
    # [확정 — 2026-09-13 인프라팀 노션 회신] 인바운드는 VPC 내부 대역(SG_ALLOWED_INBOUND_CIDR)
    # 만 전체 허용, 외부 인터넷(0.0.0.0/0) 인바운드는 전면 차단. 아웃바운드의 0.0.0.0/0은
    # 정상이므로 방향(인바운드/아웃바운드) 구분이 필수 — 인바운드만 판정 대상.
    sgs, err = safe_call(ec2.describe_security_groups)
    if err:
        return [make_result("3.2", "보안 그룹 인/아웃바운드 불필요 정책 관리", "SKIP", f"보안그룹 조회 실패: {err}")]
    offenders = []
    for sg in sgs["SecurityGroups"]:
        for perm in sg["IpPermissions"]:
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp")
                if cidr and cidr != config.SG_ALLOWED_INBOUND_CIDR:
                    offenders.append(f"{sg['GroupId']}(inbound {cidr})")
            for r in perm.get("Ipv6Ranges", []):
                if r.get("CidrIpv6"):
                    offenders.append(f"{sg['GroupId']}(inbound {r['CidrIpv6']})")
    status = "PASS" if not offenders else "FAIL"
    detail = (f"허용 대역({config.SG_ALLOWED_INBOUND_CIDR}) 외 인바운드 규칙: "
              + (", ".join(offenders) if offenders else "없음"))
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


def check_3_5_igw_direct_route(ec2):
    subnets, serr = safe_call(ec2.describe_subnets)
    if serr:
        return [make_result("3.5", "인터넷 게이트웨이 연결 관리", "SKIP", f"서브넷 조회 실패: {serr}")]
    subnet_to_rt, main_rt_by_vpc = _subnet_route_table_map(ec2)
    offenders = []
    for subnet in subnets["Subnets"]:
        if subnet.get("MapPublicIpOnLaunch"):
            continue  # 퍼블릭 서브넷은 IGW 직접경로가 정상
        rt = subnet_to_rt.get(subnet["SubnetId"]) or main_rt_by_vpc.get(subnet["VpcId"])
        if not rt:
            continue
        for route in rt["Routes"]:
            if route.get("DestinationCidrBlock") == "0.0.0.0/0" and str(route.get("GatewayId", "")).startswith("igw-"):
                offenders.append(f"{subnet['SubnetId']}->{rt['RouteTableId']}")
    status = "PASS" if not offenders else "FAIL"
    detail = "프라이빗 서브넷의 IGW 직접경로(절대기준 위반): " + (", ".join(offenders) if offenders else "없음")
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

    status = "PASS" if nat_instances and not offenders else ("FAIL" if offenders else "REVIEW")
    detail = (
        f"NAT 인스턴스(Name 태그 'nat' 포함) {len(nat_instances)}대"
        + (f" — 위반: {', '.join(offenders)}" if offenders else " — 위반 없음")
        + (f" (확정 경유지: {', '.join(confirmed.get('nat_instance_names', []))})" if confirmed is not None
           else " — '목적 확인된 리소스 목록' 대조는 별도 확인 필요(config.NAT_PURPOSE_CONFIRMED_RESOURCES TODO)")
    )
    return [make_result("3.6", "NAT 게이트웨이 연결 관리", status, detail)]


def run_all(ec2):
    results = []
    results += check_3_1_sg_any(ec2)
    results += check_3_2_sg_unnecessary_rules(ec2)
    results += check_3_3_nacl(ec2)
    results += check_3_4_route_table(ec2)
    results += check_3_5_igw_direct_route(ec2)
    results += check_3_6_nat_management(ec2)
    return results
