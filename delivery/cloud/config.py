"""클라우드(AWS CLI/boto3) 점검 기준값.

값이 없으면(None) 해당 항목은 SKIP으로 떨어진다. 값이 정해지면 이 파일만
수정하면 되고 checks/*.py 로직은 건드릴 필요가 없다.
"""

# 1.1 업무상 인가된 관리자(AdministratorAccess 직접보유) 화이트리스트
IAM_ADMIN_WHITELIST = [
    "mgmt-automation-user",
    "infra-jongwon",
    "infra-youngheon",
    "infra-mingyu",
    "infra-jaehyeok",
    "infra-jiyoon",
]

# 1.1 테스트/불필요 계정 네이밍 블랙리스트
TEST_ACCOUNT_NAME_PATTERNS = [r"^testuser$", r"^test\d+$"]

# 1.2 IAM 계정-담당자 매핑표(1인 1계정 검증용)
IAM_ACCOUNT_OWNER_MAP = {
    "infra-jongwon": "임종원",
    "infra-youngheon": "박영헌",
    "infra-mingyu": "김민규",
    "infra-jaehyeok": "이재혁",
    "infra-jiyoon": "이지윤",
    "mgmt-automation-user": "시스템 공용 배포 계정",
}
IAM_SHARED_ACCOUNT_EXCEPTIONS = ["mgmt-automation-user"]

# 1.8 Admin Console Access Key 사용주기 — AWS Config Rule(maxAccessKeyAge=60)로 구현됨
ACCESS_KEY_ROTATION_CONFIG_RULE = "access-keys-rotated"

# 1.4 IAM 그룹 사용자 화이트리스트
IAM_GROUP_WHITELIST = {
    "infra-admin": [
        "infra-jaehyeok",
        "infra-jiyoon",
        "infra-jongwon",
        "infra-mingyu",
        "infra-youngheon",
        "mgmt-automation-user",
    ],
}

# 1.6 Key Pair 보관 관리 — EC2 Key Pair 자체 미사용(SSM), 항상 N/A가 정상

# 1.11 EKS 접근 인가 사용자 화이트리스트(EKS Access Entry)
EKS_ACCESS_WHITELIST = [
    "arn:aws:iam::596601390909:user/mgmt-automation-user",
    "arn:aws:iam::596601390909:user/infra-jongwon",
    "arn:aws:iam::596601390909:user/infra-youngheon",
    "arn:aws:iam::596601390909:user/infra-mingyu",
    "arn:aws:iam::596601390909:user/infra-jaehyeok",
    "arn:aws:iam::596601390909:user/infra-jiyoon",
]

# 1.12 SA 토큰 자동 마운트 판정 범위 — 모든 네임스페이스 default SA + 앱 네임스페이스 SA
# (K8s API가 필요한 SA는 "네임스페이스/SA이름" 형식으로 예외에 추가)
EKS_APP_NAMESPACES = ["backend", "frontend", "dev"]
EKS_SA_API_ACCESS_EXCEPTIONS = ["backend/shared-pg"]   # CNPG DB 파드용 SA

# 2.1(인스턴스 서비스) — EKS 워커노드/NAT 인스턴스 IAM 역할에 허용된 관리형 정책
EKS_WORKER_NODE_REQUIRED_POLICIES = [
    "AmazonEKSWorkerNodePolicy",
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonSSMManagedInstanceCore",
    "AmazonEKS_CNI_Policy",
]
NAT_INSTANCE_REQUIRED_POLICIES = [
    "AmazonSSMManagedInstanceCore",
]

# 2.2(네트워크 서비스) — ALB(aws-load-balancer-controller IRSA) + VPC CNI
ALB_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-load-balancer-controller"}
VPC_CNI_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-node"}
VPC_CNI_IRSA_NOT_SEPARATED_NOTE = (
    "VPC CNI가 전용 IRSA 없이 워커노드 IAM 역할의 AmazonEKS_CNI_Policy를 상속받는 구조"
    " — aws-node ServiceAccount에서 IRSA annotation을 확인하지 못함, REVIEW 권장"
)

# 2.3(기타 서비스) 인스턴스/네트워크 외 서비스별 IAM 최소권한 정의서
SERVICE_IAM_POLICY_MAP = {
    "namespace": "backend",
    "service_accounts": {
        "auth-service": "auth-sa",
        "order-service": "order-sa",
        "payment-service": "payment-sa",
        "product-service": "product-sa",
        "user-service": "user-sa",
        "oms-service": "oms-sa",
        "wms-service": "wms-sa",
        "scm-service": "scm-sa",
    },
}
SERVICE_IAM_KMS_CHECK_ENABLED = True
SERVICE_IAM_KMS_ALLOWED_SERVICES = ["auth-service"]
SERVICE_IAM_KMS_ALLOWED_ACTIONS = ["kms:Sign", "kms:GetPublicKey"]

# 3.2 보안그룹 인/아웃바운드 규칙 baseline
SG_ALLOWED_INBOUND_CIDR = "10.0.0.0/16"

# 3.6 NAT 연결 "목적 확인된 리소스" 목록
NAT_PURPOSE_CONFIRMED_RESOURCES = {
    "nat_instance_names": ["eks-nat-instance-2a", "eks-nat-instance-2c"],
    "nat_public_subnet_cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
    "allowed_private_subnet_cidrs": ["10.0.16.0/20", "10.0.32.0/20"],
}

# 3.10⑤ ELB Idle Timeout 기준(초) — ">= 60초"(정확히 60초도 PASS)
ELB_IDLE_TIMEOUT_SECONDS = 60

# 3.10⑥ 헬스체크 경로 예외(ArgoCD/Prometheus 자체 표준 엔드포인트)
ELB_HEALTHCHECK_PATH_EXCEPTIONS = ["/healthz", "/api/health"]

# 4.12 로그 보관 기간 최소 기준(일)
LOG_RETENTION_MIN_DAYS = 365

# EKS 클러스터 이름 목록 (실행 시 --eks-clusters 옵션으로도 전달 가능)
EKS_CLUSTER_NAMES = None

# EKS kubeconfig 컨텍스트 중복 해소 — 클러스터 이름별 강제 지정 컨텍스트
EKS_KUBECONFIG_CONTEXT_OVERRIDE = {
    "test-eks": "arn:aws:eks:ap-northeast-2:596601390909:cluster/test-eks",
}

# 인증_인가(SVC-08) — MFA 강제 여부는 클라우드 1.9와 판정이 겹쳐 True 확정 전까지 REVIEW
SVC08_MFA_CROSS_CHECK_DONE = False
