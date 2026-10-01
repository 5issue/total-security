"""클라우드 점검 기준값."""

# 1.1 관리자 화이트리스트
IAM_ADMIN_WHITELIST = [
    "mgmt-automation-user",
    "infra-user1",
    "infra-user2",
    "infra-user3",
    "infra-user4",
    "infra-user5",
]

# 1.1 관리자 Role 화이트리스트
IAM_ADMIN_ROLE_WHITELIST = ["target-infra"]

# 1.1 테스트 계정 네이밍 블랙리스트
TEST_ACCOUNT_NAME_PATTERNS = [r"^testuser$", r"^test\d+$"]

# 1.2 IAM 계정-담당자 매핑표
IAM_ACCOUNT_OWNER_MAP = {
    "infra-user1": "인프라 담당자 1",
    "infra-user2": "인프라 담당자 2",
    "infra-user3": "인프라 담당자 3",
    "infra-user4": "인프라 담당자 4",
    "infra-user5": "인프라 담당자 5",
    "mgmt-automation-user": "시스템 공용 배포 계정",
    "be-user1": "백엔드 담당자 1",
    "be-user2": "백엔드 담당자 2",
    "be-user3": "백엔드 담당자 3",
    # 2026-10-01 인프라팀 회신 — GitHub Actions에서 MySQL(audit 플러그인) 이미지를 ECR로 push하는 CI 전용 계정
    "github-ecr": "GitHub Actions ECR push 전용 계정",
}
IAM_SHARED_ACCOUNT_EXCEPTIONS = ["mgmt-automation-user", "github-ecr"]

# 1.8 Access Key 사용주기
ACCESS_KEY_ROTATION_CONFIG_RULE = "access-keys-rotated"

# 1.4 IAM 그룹 사용자 화이트리스트
IAM_GROUP_WHITELIST = {
    "infra-admin": [
        "infra-user4",
        "infra-user5",
        "infra-user1",
        "infra-user3",
        "infra-user2",
        "mgmt-automation-user",
    ],
}

# 1.6 Key Pair 보관 관리

# 1.11 EKS 접근 인가 사용자 화이트리스트
EKS_ACCESS_WHITELIST = [
    "arn:aws:iam::123456789012:user/mgmt-automation-user",
    "arn:aws:iam::123456789012:user/infra-user1",
    "arn:aws:iam::123456789012:user/infra-user2",
    "arn:aws:iam::123456789012:user/infra-user3",
    "arn:aws:iam::123456789012:user/infra-user4",
    "arn:aws:iam::123456789012:user/infra-user5",
    "arn:aws:iam::123456789012:user/be-user1",
    "arn:aws:iam::123456789012:user/be-user2",
    "arn:aws:iam::123456789012:user/be-user3",
    "arn:aws:iam::123456789012:role/db-admin-secret-reader",
    "arn:aws:iam::123456789012:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
    "arn:aws:iam::123456789012:role/eks-cluster-access",
    "arn:aws:iam::123456789012:role/rabbitmq-redis-secret-reader",
    "arn:aws:iam::123456789012:role/target-infra",
    "arn:aws:iam::123456789012:role/total-workload-publication",
]

# 1.12 EKS 서비스 어카운트 관리
EKS_APP_NAMESPACES = ["backend", "frontend", "dev"]
EKS_SA_API_ACCESS_EXCEPTIONS = ["backend/shared-pg", "backend/moco-shared-mysql", "backend/shared-mysql-backup"]

# 2.1 인스턴스 서비스 정책 관리
EKS_WORKER_NODE_REQUIRED_POLICIES = [
    "AmazonEKSWorkerNodePolicy",
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonSSMManagedInstanceCore",
    "AmazonEKS_CNI_Policy",
    "test-eks-node-ansible-s3",
]
NAT_INSTANCE_REQUIRED_POLICIES = [
    "AmazonSSMManagedInstanceCore",
    "test-eks-node-ansible-s3",
]

# 2.2 네트워크 서비스 정책 관리
ALB_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-load-balancer-controller"}
VPC_CNI_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-node"}
VPC_CNI_IRSA_NOT_SEPARATED_NOTE = (
    "VPC CNI가 전용 IRSA 없이 워커노드 IAM 역할의 AmazonEKS_CNI_Policy를 상속받는 구조"
    " — aws-node ServiceAccount에서 IRSA annotation을 확인하지 못함, REVIEW 권장"
)

# 2.3 기타 서비스 정책 관리
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
SERVICE_IAM_KMS_ALLOWED_ACTIONS = ["kms:Sign", "kms:GetPublicKey", "kms:Verify", "kms:DescribeKey"]

# 3.2 보안그룹 인/아웃바운드 규칙 baseline
SG_ALLOWED_INBOUND_CIDR = "10.0.0.0/16"
ALB_PUBLIC_INBOUND_PORTS = [80, 443]

# 3.6 NAT 연결 "목적 확인된 리소스" 목록
NAT_PURPOSE_CONFIRMED_RESOURCES = {
    "nat_instance_names": ["eks-nat-instance-2a", "eks-nat-instance-2c"],
    "nat_public_subnet_cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
    "allowed_private_subnet_cidrs": ["10.0.16.0/20", "10.0.32.0/20"],
}

# 4.12 로그 보관 기간 최소 기준
LOG_RETENTION_MIN_DAYS = 365

# EKS 클러스터 이름 목록
EKS_CLUSTER_NAMES = None

# EKS kubeconfig 컨텍스트
EKS_KUBECONFIG_CONTEXT_OVERRIDE = {
    "test-eks": "arn:aws:eks:ap-northeast-2:123456789012:cluster/test-eks",
}

# SVC-08 MFA 판정 제외(자동화 계정)
SVC08_MFA_EXCEPTIONS = ["mgmt-automation-user"]
