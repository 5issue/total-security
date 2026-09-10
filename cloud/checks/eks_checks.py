"""1.12~1.13, 3.9, 4.14~4.15 — EKS 점검 (boto3 + kubernetes 파이썬 클라이언트).

K8s API 접근이 필요한 항목(1.12,1.13,3.9)은 mgmt 서버에 이미 구성된 kubeconfig
컨텍스트(클러스터 이름과 동일하다고 가정, `aws eks update-kubeconfig --name <cluster>`
로 사전 구성)를 사용한다. 컨텍스트가 없으면 해당 항목만 SKIP 처리하고 나머지는 계속 진행한다.
"""
from .common import make_result, safe_call

try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
except ImportError:  # kubernetes 패키지 미설치 환경 대비
    k8s_client = None
    k8s_config = None

EXCLUDED_ANONYMOUS_BINDING = "system:public-info-viewer"
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


def _load_core_v1(cluster_name):
    if k8s_config is None:
        return None, "kubernetes 패키지 미설치"
    try:
        k8s_config.load_kube_config(context=cluster_name)
        return k8s_client.CoreV1Api(), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _load_rbac_v1(cluster_name):
    if k8s_config is None:
        return None, "kubernetes 패키지 미설치"
    try:
        k8s_config.load_kube_config(context=cluster_name)
        return k8s_client.RbacAuthorizationV1Api(), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


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


def run_all(eks, cluster_names):
    if not cluster_names:
        note = "EKS 클러스터 없음(또는 조회 실패) — 해당없음"
        return [
            make_result("1.12", "EKS 서비스 어카운트 관리", "N/A", note),
            make_result("1.13", "EKS 불필요한 익명 접근 관리", "N/A", note),
            make_result("3.9", "EKS Pod 보안 정책 관리", "N/A", note),
            make_result("4.14", "EKS Cluster 제어 플레인 로깅 설정", "N/A", note),
            make_result("4.15", "EKS Cluster 암호화 설정", "N/A", note),
        ]
    results = []
    for cluster_name in cluster_names:
        results += check_1_12_automount_token(cluster_name)
        results += check_1_13_anonymous_access(cluster_name)
        results += check_3_9_pod_security(cluster_name)
        results += check_4_14_control_plane_logging(eks, cluster_name)
        results += check_4_15_secrets_encryption(eks, cluster_name)
    return results
