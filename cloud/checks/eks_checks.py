"""1.11~1.13, 2.1~2.2, 3.9, 4.14~4.15 — EKS 점검 (boto3 + kubernetes 파이썬 클라이언트).

K8s API 접근이 필요한 항목(1.11,1.12,1.13,2.2,3.9)은 mgmt 서버에 이미 구성된 kubeconfig
컨텍스트(클러스터 이름과 동일하다고 가정, `aws eks update-kubeconfig --name <cluster>`
로 사전 구성)를 사용한다. 컨텍스트가 없으면 해당 항목만 SKIP 처리하고 나머지는 계속 진행한다.
"""
import json
import os

import yaml

import config
from .common import make_result, safe_call

try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
except ImportError:  # kubernetes 패키지 미설치 환경 대비
    k8s_client = None
    k8s_config = None

EXCLUDED_ANONYMOUS_BINDING = "system:public-info-viewer"
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


def _resolve_context(cluster_name):
    # `aws eks update-kubeconfig --name <cluster>`는 --alias 없이 쓰면 컨텍스트 이름을
    # 클러스터 이름이 아니라 "arn:aws:eks:<region>:<account>:cluster/<cluster-name>" 전체
    # ARN으로 만든다. 정확히 일치하는 컨텍스트가 없으면 클러스터 이름을 포함하는 컨텍스트를
    # 대신 찾는다(ARN 마지막 세그먼트로 끝나는 것 우선).
    try:
        contexts, _ = k8s_config.list_kube_config_contexts()
    except Exception as exc:  # noqa: BLE001
        return None, f"kubeconfig 컨텍스트 목록 조회 실패: {exc}"
    names = [c["name"] for c in contexts]
    if cluster_name in names:
        return cluster_name, None
    matches = [n for n in names if n.endswith("/" + cluster_name)] or \
              [n for n in names if cluster_name in n]
    if len(matches) == 1:
        return matches[0], None
    if not matches:
        return None, f"'{cluster_name}' 클러스터에 해당하는 kubeconfig 컨텍스트를 찾지 못함(보유 컨텍스트: {names})"
    return None, f"'{cluster_name}'과 매칭되는 컨텍스트가 여러 개({matches}) — kubeconfig에 --alias로 명확히 구분 필요"


def _load_core_v1(cluster_name):
    if k8s_config is None:
        return None, "kubernetes 패키지 미설치"
    context, err = _resolve_context(cluster_name)
    if err:
        return None, err
    try:
        k8s_config.load_kube_config(context=context)
        return k8s_client.CoreV1Api(), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _load_rbac_v1(cluster_name):
    if k8s_config is None:
        return None, "kubernetes 패키지 미설치"
    context, err = _resolve_context(cluster_name)
    if err:
        return None, err
    try:
        k8s_config.load_kube_config(context=context)
        return k8s_client.RbacAuthorizationV1Api(), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def check_1_11_eks_user_management(cluster_name):
    # [확정 — 2026-09-13 인프라팀 노션 회신] aws-auth ConfigMap의 mapUsers/mapRoles가
    # config.EKS_ACCESS_WHITELIST(ARN 목록)와 정확히 일치해야 함 — 그 외 매핑 발견 시 FAIL.
    if config.EKS_ACCESS_WHITELIST is None:
        return [make_result("1.11", "EKS 사용자 관리", "SKIP",
                             "인가된 EKS 접근 사용자 화이트리스트(config.EKS_ACCESS_WHITELIST) 미확정")]
    core_v1, err = _load_core_v1(cluster_name)
    if err:
        return [make_result("1.11", "EKS 사용자 관리", "SKIP",
                             f"[{cluster_name}] kubeconfig 컨텍스트 로드 실패: {err}")]
    cm, kerr = safe_call(core_v1.read_namespaced_config_map, name="aws-auth", namespace="kube-system")
    if kerr:
        return [make_result("1.11", "EKS 사용자 관리", "SKIP", f"[{cluster_name}] aws-auth ConfigMap 조회 실패: {kerr}")]
    data = cm.data or {}
    mapped_arns = []
    for key in ("mapUsers", "mapRoles"):
        try:
            entries = yaml.safe_load(data.get(key, "[]")) or []
        except yaml.YAMLError:
            entries = []
        mapped_arns.extend(e.get("userarn") or e.get("rolearn") for e in entries if isinstance(e, dict))
    mapped_arns = [a for a in mapped_arns if a]
    unauthorized = [a for a in mapped_arns if a not in config.EKS_ACCESS_WHITELIST]
    status = "PASS" if not unauthorized else "FAIL"
    detail = f"[{cluster_name}] 화이트리스트 외 aws-auth 매핑: " + (", ".join(unauthorized) if unauthorized else "없음")
    return [make_result("1.11", "EKS 사용자 관리", status, detail)]


def check_1_12_automount_token(cluster_name):
    core_v1, err = _load_core_v1(cluster_name)
    if err:
        return [make_result("1.12", "EKS 서비스 어카운트 관리", "SKIP",
                             f"[{cluster_name}] kubeconfig 컨텍스트 로드 실패: {err}")]
    sas, kerr = safe_call(core_v1.list_service_account_for_all_namespaces)
    if kerr:
        return [make_result("1.12", "EKS 서비스 어카운트 관리", "SKIP", f"[{cluster_name}] 조회 실패: {kerr}")]
    violations = [
        f"{sa.metadata.namespace}/{sa.metadata.name}"
        for sa in sas.items
        if sa.automount_service_account_token is not False
    ]
    status = "PASS" if not violations else "FAIL"
    detail = f"[{cluster_name}] automountServiceAccountToken=False 미설정 ServiceAccount " \
             f"{len(violations)}건: " + (", ".join(violations[:10]) if violations else "없음")
    return [make_result("1.12", "EKS 서비스 어카운트 관리", status, detail)]


def check_1_13_anonymous_access(cluster_name):
    rbac_v1, err = _load_rbac_v1(cluster_name)
    if err:
        return [make_result("1.13", "EKS 불필요한 익명 접근 관리", "SKIP",
                             f"[{cluster_name}] kubeconfig 컨텍스트 로드 실패: {err}")]
    crbs, kerr = safe_call(rbac_v1.list_cluster_role_binding)
    if kerr:
        return [make_result("1.13", "EKS 불필요한 익명 접근 관리", "SKIP", f"[{cluster_name}] 조회 실패: {kerr}")]
    offenders = []
    for crb in crbs.items:
        if crb.metadata.name == EXCLUDED_ANONYMOUS_BINDING:
            continue
        for subj in crb.subjects or []:
            if subj.name in ("system:anonymous", "system:unauthenticated"):
                offenders.append(crb.metadata.name)
    status = "PASS" if not offenders else "FAIL"
    detail = f"[{cluster_name}] 익명 그룹 바인딩(system:public-info-viewer 제외): " + \
             (", ".join(offenders) if offenders else "없음")
    return [make_result("1.13", "EKS 불필요한 익명 접근 관리", status, detail)]


def check_3_9_pod_security(cluster_name):
    core_v1, err = _load_core_v1(cluster_name)
    if err:
        return [make_result("3.9", "EKS Pod 보안 정책 관리", "SKIP",
                             f"[{cluster_name}] kubeconfig 컨텍스트 로드 실패: {err}")]
    namespaces, kerr = safe_call(core_v1.list_namespace)
    if kerr:
        return [make_result("3.9", "EKS Pod 보안 정책 관리", "SKIP", f"[{cluster_name}] 조회 실패: {kerr}")]
    offenders = []
    for ns in namespaces.items:
        if ns.metadata.name in SYSTEM_NAMESPACES:
            continue
        labels = ns.metadata.labels or {}
        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        audit = labels.get("pod-security.kubernetes.io/audit", "")
        if enforce == "privileged" or (not enforce and audit not in ("baseline", "restricted")):
            offenders.append(ns.metadata.name)
    status = "PASS" if not offenders else "FAIL"
    detail = f"[{cluster_name}] PSA baseline/audit 미달 네임스페이스: " + \
             (", ".join(offenders) if offenders else "없음")
    return [make_result("3.9", "EKS Pod 보안 정책 관리", status, detail)]


def check_4_14_control_plane_logging(eks, cluster_name):
    desc, err = safe_call(eks.describe_cluster, name=cluster_name)
    if err:
        return [make_result("4.14", "EKS Cluster 제어 플레인 로깅 설정", "SKIP",
                             f"[{cluster_name}] describe_cluster 실패: {err}")]
    log_types_enabled = set()
    for entry in desc["cluster"].get("logging", {}).get("clusterLogging", []):
        if entry.get("enabled"):
            log_types_enabled.update(entry.get("types", []))
    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
    missing = required - log_types_enabled
    status = "PASS" if not missing else "FAIL"
    detail = f"[{cluster_name}] 미활성 로그 유형: " + (", ".join(sorted(missing)) if missing else "없음")
    return [make_result("4.14", "EKS Cluster 제어 플레인 로깅 설정", status, detail)]


def check_4_15_secrets_encryption(eks, cluster_name):
    desc, err = safe_call(eks.describe_cluster, name=cluster_name)
    if err:
        return [make_result("4.15", "EKS Cluster 암호화 설정", "SKIP", f"[{cluster_name}] describe_cluster 실패: {err}")]
    enc_configs = desc["cluster"].get("encryptionConfig", [])
    has_secrets_enc = any("secrets" in c.get("resources", []) for c in enc_configs)
    status = "PASS" if has_secrets_enc else "FAIL"
    detail = f"[{cluster_name}] encryptionConfig: {enc_configs}" if enc_configs else f"[{cluster_name}] 암호화 미설정"
    return [make_result("4.15", "EKS Cluster 암호화 설정", status, detail)]


def _fmt_set(names):
    return ", ".join(sorted(names)) if names else "없음"


def _attached_policy_names(iam, role_name):
    result, err = safe_call(iam.list_attached_role_policies, RoleName=role_name)
    if err:
        return None, err
    return {p["PolicyName"] for p in result["AttachedPolicies"]}, None


def check_2_1_instance_service_policies(eks, iam, ec2, cluster_names):
    # [확정 — 2026-09-13 인프라팀 직접 질의 회신] EKS 워커노드/NAT 인스턴스 IAM 역할에
    # 허용된 관리형 정책 집합(config.EKS_WORKER_NODE_REQUIRED_POLICIES /
    # NAT_INSTANCE_REQUIRED_POLICIES)과 정확히 일치해야 함 — 초과·누락 모두 FAIL.
    required_node = set(config.EKS_WORKER_NODE_REQUIRED_POLICIES)
    required_nat = set(config.NAT_INSTANCE_REQUIRED_POLICIES)
    violations = []
    checked = False

    for cluster_name in cluster_names:
        ngs, err = safe_call(eks.list_nodegroups, clusterName=cluster_name)
        if err:
            continue
        for ng_name in ngs.get("nodegroups", []):
            desc, derr = safe_call(eks.describe_nodegroup, clusterName=cluster_name, nodegroupName=ng_name)
            if derr:
                continue
            role_name = desc["nodegroup"]["nodeRole"].rsplit("/", 1)[-1]
            attached, aerr = _attached_policy_names(iam, role_name)
            if aerr:
                violations.append(f"[{cluster_name}/{ng_name}] role={role_name} 정책 조회 실패: {aerr}")
                continue
            checked = True
            extra, missing = attached - required_node, required_node - attached
            if extra or missing:
                violations.append(
                    f"[{cluster_name}/{ng_name}] role={role_name} 초과정책=({_fmt_set(extra)}) 누락정책=({_fmt_set(missing)})"
                )

    nat_names = set((config.NAT_PURPOSE_CONFIRMED_RESOURCES or {}).get("nat_instance_names", []))
    if nat_names:
        reservations, rerr = safe_call(
            ec2.describe_instances, Filters=[{"Name": "tag:Name", "Values": sorted(nat_names)}]
        )
        if not rerr:
            for res in reservations["Reservations"]:
                for inst in res["Instances"]:
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                    profile_arn = (inst.get("IamInstanceProfile") or {}).get("Arn")
                    if not profile_arn:
                        violations.append(f"NAT({name}) IAM 인스턴스 프로파일 없음")
                        continue
                    profile_name = profile_arn.rsplit("/", 1)[-1]
                    prof, perr = safe_call(iam.get_instance_profile, InstanceProfileName=profile_name)
                    if perr or not prof["InstanceProfile"]["Roles"]:
                        violations.append(f"NAT({name}) 인스턴스 프로파일({profile_name}) 조회 실패")
                        continue
                    role_name = prof["InstanceProfile"]["Roles"][0]["RoleName"]
                    attached, aerr = _attached_policy_names(iam, role_name)
                    if aerr:
                        violations.append(f"NAT({name}) role={role_name} 정책 조회 실패: {aerr}")
                        continue
                    checked = True
                    extra, missing = attached - required_nat, required_nat - attached
                    if extra or missing:
                        violations.append(
                            f"NAT({name}) role={role_name} 초과정책=({_fmt_set(extra)}) 누락정책=({_fmt_set(missing)})"
                        )

    if not checked:
        return [make_result("2.1", "인스턴스 서비스 정책 관리", "SKIP", "EKS 노드그룹/NAT 인스턴스를 찾지 못함")]
    status = "PASS" if not violations else "FAIL"
    detail = "확정 IAM 역할 정책 구성과 일치(위반 없음)" if not violations else " / ".join(violations)
    return [make_result("2.1", "인스턴스 서비스 정책 관리", status, detail)]


def _load_alb_official_actions():
    path = os.path.join(os.path.dirname(__file__), "..", "reference", "alb_iam_policy.json")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    actions = set()
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        acts = stmt.get("Action", [])
        actions.update([acts] if isinstance(acts, str) else acts)
    return actions


def _statement_actions(statements):
    actions = set()
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        acts = stmt.get("Action", [])
        actions.update([acts] if isinstance(acts, str) else acts)
    return actions


def _role_granted_actions(iam, role_name):
    actions = set()
    attached, aerr = safe_call(iam.list_attached_role_policies, RoleName=role_name)
    if aerr:
        return None, aerr
    for p in attached["AttachedPolicies"]:
        pol, perr = safe_call(iam.get_policy, PolicyArn=p["PolicyArn"])
        if perr:
            continue
        ver, verr = safe_call(iam.get_policy_version, PolicyArn=p["PolicyArn"],
                               VersionId=pol["Policy"]["DefaultVersionId"])
        if verr:
            continue
        actions |= _statement_actions(ver["PolicyVersion"]["Document"].get("Statement", []))
    inline, ierr = safe_call(iam.list_role_policies, RoleName=role_name)
    if not ierr:
        for policy_name in inline["PolicyNames"]:
            doc_res, derr = safe_call(iam.get_role_policy, RoleName=role_name, PolicyName=policy_name)
            if derr:
                continue
            actions |= _statement_actions(doc_res["PolicyDocument"].get("Statement", []))
    return actions, None


def check_2_2_network_service_policies(iam, cluster_names):
    # [확정 — 2026-09-13 인프라팀 직접 질의 회신]
    # ALB(aws-load-balancer-controller IRSA): 실제 권한이 공식 정책(reference/
    # alb_iam_policy.json, 2026-09-13 고정)의 부분집합인지 대조(초과 권한만 FAIL).
    # VPC CNI: 전용 IRSA 미분리 상태는 인프라팀이 이미 인지·확정한 정적 사실이라(차기
    # 스프린트에 IRSA 분리 예정) EKS 클러스터를 조회할 수 있는지와 무관하게 이 항목은
    # 최소 REVIEW — ALB 쪽만 라이브 대조가 되면 그 결과로 FAIL까지 격상될 수 있다.
    try:
        official_actions = _load_alb_official_actions()
    except OSError as exc:
        return [make_result("2.2", "네트워크 서비스 정책 관리", "SKIP", f"공식 ALB 정책 파일 로드 실패: {exc}")]

    alb_status, alb_detail = None, None
    for cluster_name in cluster_names:
        core_v1, err = _load_core_v1(cluster_name)
        if err:
            continue
        sa, serr = safe_call(
            core_v1.read_namespaced_service_account,
            name=config.ALB_IRSA_SERVICE_ACCOUNT["name"],
            namespace=config.ALB_IRSA_SERVICE_ACCOUNT["namespace"],
        )
        if serr:
            alb_detail = f"[{cluster_name}] aws-load-balancer-controller ServiceAccount 조회 실패: {serr}"
            continue
        role_arn = (sa.metadata.annotations or {}).get("eks.amazonaws.com/role-arn")
        if not role_arn:
            alb_detail = f"[{cluster_name}] ServiceAccount에 IRSA role-arn annotation 없음"
            continue
        role_name = role_arn.rsplit("/", 1)[-1]
        actual_actions, aerr = _role_granted_actions(iam, role_name)
        if aerr:
            alb_detail = f"[{cluster_name}] role={role_name} 정책 조회 실패: {aerr}"
            continue
        extra = actual_actions - official_actions
        alb_status = "PASS" if not extra else "FAIL"
        alb_detail = f"[{cluster_name}] ALB IRSA role={role_name} 공식 정책 대비 초과 액션: {_fmt_set(extra)}"
        break  # 클러스터가 여러 개여도 controller는 보통 1개 클러스터에만 배포됨 — 첫 매칭 대표 판정

    if alb_status is None:
        alb_detail = alb_detail or (
            "EKS 클러스터 없음 또는 aws-load-balancer-controller ServiceAccount를 찾지 못해 ALB IRSA 대조는 보류"
            if not cluster_names else
            "aws-load-balancer-controller ServiceAccount를 찾지 못함(K8s 접근 실패 또는 미배포) — ALB IRSA 대조는 보류"
        )

    # VPC CNI 이슈는 클러스터 조회 가능 여부와 무관한 확정 사실이라 항상 최소 REVIEW —
    # ALB가 실제로 FAIL로 확인된 경우에만 더 심각한 FAIL로 격상한다.
    status = "FAIL" if alb_status == "FAIL" else "REVIEW"
    detail = f"{alb_detail} | {config.VPC_CNI_IRSA_NOT_SEPARATED_NOTE}"
    return [make_result("2.2", "네트워크 서비스 정책 관리", status, detail)]


def run_all(eks, iam, ec2, cluster_names, discovery_error=None):
    # ⚠ EKS는 RDS(3.8/4.2/4.9, 영구 미사용 확정)와 달리 이 아키텍처의 핵심 컴퓨트
    # 플랫폼이라 "클러스터를 못 찾음"이 정책상 해당없음(N/A)일 수 없다 — 항상 존재해야
    # 하는데 이번 조회에서 안 보였다는 뜻이라 SKIP이 맞다(로컬 테스트 계정처럼 EKS
    # 자체가 없는 환경이거나, 운영에서라면 조회 실패/권한 문제로 봐야 함 — 둘 다
    # "지금은 판정 불가"이지 "적용 대상 아님"이 아니다). 2026-09-13 확정.
    if not cluster_names:
        if discovery_error:
            note = f"EKS 클러스터 조회 자체가 실패함(권한/네트워크 등 확인 필요): {discovery_error}"
        else:
            note = "EKS 클러스터 없음 — 로컬 테스트 계정처럼 EKS 미사용 환경이거나 운영에서는 조회 결과 재확인 필요"
        results = [
            make_result("1.11", "EKS 사용자 관리", "SKIP", note),
            make_result("1.12", "EKS 서비스 어카운트 관리", "SKIP", note),
            make_result("1.13", "EKS 불필요한 익명 접근 관리", "SKIP", note),
            make_result("3.9", "EKS Pod 보안 정책 관리", "SKIP", note),
            make_result("4.14", "EKS Cluster 제어 플레인 로깅 설정", "SKIP", note),
            make_result("4.15", "EKS Cluster 암호화 설정", "SKIP", note),
        ]
    else:
        results = []
        for cluster_name in cluster_names:
            results += check_1_11_eks_user_management(cluster_name)
            results += check_1_12_automount_token(cluster_name)
            results += check_1_13_anonymous_access(cluster_name)
            results += check_3_9_pod_security(cluster_name)
            results += check_4_14_control_plane_logging(eks, cluster_name)
            results += check_4_15_secrets_encryption(eks, cluster_name)
    # 2.2(VPC CNI REVIEW)는 클러스터 조회 가능 여부와 무관한 정적 확정 사실이 걸려 있어
    # cluster_names가 비어도 항상 호출한다(check_2_2_network_service_policies 내부에서
    # ALB 파트만 조건부로 SKIP 취급하고 최종 상태는 최소 REVIEW로 고정).
    results += check_2_2_network_service_policies(iam, cluster_names)
    results += check_2_1_instance_service_policies(eks, iam, ec2, cluster_names)
    return results
