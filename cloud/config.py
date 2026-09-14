"""클라우드(AWS CLI/boto3) 점검 기준값.

Ansible의 group_vars/all.yml과 동일한 원칙: 로직은 항상 작성하고, 값이 없으면(None)
해당 항목은 SKIP으로 떨어진다. 값이 정해지면 이 파일만 수정하면 되고 checks/*.py
로직은 건드릴 필요가 없다.

⚠ 이 파일은 실제 운영용이다 — 로컬 테스트용 임의값은 절대 여기 넣지 말고
`config_test.py`(테스트 전용, `cloud_check.py --test-config`로만 로드됨)에 넣을 것.

출처: 인프라점검_항목분류표_v0_3.xlsx 클라우드 시트 "확정 기준값" 컬럼
"""

# 1.1 업무상 인가된 관리자(AdministratorAccess 직접보유) 화이트리스트
# [확정 — 2026-09-13 인프라팀 노션 회신] 이 목록 외 계정이 AdministratorAccess를
# 직접 보유하면(IAM 그룹 미소속) FAIL.
IAM_ADMIN_WHITELIST = [
    "mgmt-automation-user",
    "infra-jongwon",
    "infra-youngheon",
    "infra-mingyu",
    "infra-jaehyeok",
    "infra-jiyoon",
]

# 1.1 테스트/불필요 계정 네이밍 블랙리스트 [확정] — 정적 판정, 외부 확인 불필요
TEST_ACCOUNT_NAME_PATTERNS = [r"^testuser$", r"^test\d+$"]

# 1.2 IAM 계정-담당자 매핑표(1인 1계정 검증용)
# [확정 — 2026-09-13 인프라팀 노션 회신] {user_name: owner}. 이 매핑에 없는 IAM 사용자가
# 발견되면 FAIL(신규/미상 계정). mgmt-automation-user는 자동화 전용 공용 계정이라
# 1인 1계정 원칙의 명시적 예외로 둔다(owner_counts 중복 검사에서 제외).
IAM_ACCOUNT_OWNER_MAP = {
    "infra-jongwon": "임종원",
    "infra-youngheon": "박영헌",
    "infra-mingyu": "김민규",
    "infra-jaehyeok": "이재혁",
    "infra-jiyoon": "이지윤",
    "mgmt-automation-user": "시스템 공용 배포 계정",
}
IAM_SHARED_ACCOUNT_EXCEPTIONS = ["mgmt-automation-user"]

# 1.8 Admin Console Access Key 사용주기 [확정] — AWS Config Rule로 구현(인프라팀 회신 2026-09-10)
# maxAccessKeyAge=60으로 이미 Terraform 배포됨. 자체 계산 대신 컴플라이언스 상태를 그대로 매핑.
ACCESS_KEY_ROTATION_CONFIG_RULE = "access-keys-rotated"

# 1.4 IAM 그룹 사용자 화이트리스트
# [확정 — 2026-09-13 인프라팀 노션 회신] {group_name: [allowed_user_names]}
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

# 1.6 Key Pair 보관 관리 [확정 — 2026-09-13 인프라팀 노션 회신]
# EC2 Key Pair 자체 미사용(SSM AmazonSSMManagedInstanceCore) 확정 — 항상 N/A가 정상.
# Key Pair를 사용하는 인스턴스가 발견되는 경우에만 FAIL로 전환(1.5와 동일 조회 재사용).

# 1.11 EKS 접근 인가 사용자 화이트리스트(aws-auth ConfigMap)
# [확정 — 2026-09-13 인프라팀 노션 회신] 이 목록 외 mapUsers/mapRoles 매핑 발견 시 FAIL.
EKS_ACCESS_WHITELIST = [
    "arn:aws:iam::596601390909:user/mgmt-automation-user",
    "arn:aws:iam::596601390909:user/infra-jongwon",
    "arn:aws:iam::596601390909:user/infra-youngheon",
    "arn:aws:iam::596601390909:user/infra-mingyu",
    "arn:aws:iam::596601390909:user/infra-jaehyeok",
    "arn:aws:iam::596601390909:user/infra-jiyoon",
]

# 2.1(인스턴스 서비스) — EKS 워커노드/NAT 인스턴스 IAM 역할에 허용된 관리형 정책
# [확정 — 2026-09-13 인프라팀 직접 질의 회신] 이름 외 정책이 붙어 있으면(초과) FAIL,
# 누락돼도 FAIL(권한 부족으로 오작동 가능성). ARN 전체가 아니라 정책 이름만 비교.
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
# [확정 — 2026-09-13 인프라팀 직접 질의 회신]
# ALB: 실제 역할의 권한이 reference/alb_iam_policy.json(공식 정책, 2026-09-13 고정)의
#   부분집합인지 대조(초과 권한만 FAIL). K8s ServiceAccount 이름/네임스페이스는 AWS Load
#   Balancer Controller Helm 차트 기본값을 그대로 사용한다는 전제.
ALB_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-load-balancer-controller"}
# VPC CNI: 워커노드 IAM 역할에 포함된 AmazonEKS_CNI_Policy를 그대로 상속받는 구조라
#   전용 IRSA 분리(AWS 권장 방식)가 안 되어 있음 — 인프라팀도 인지하고 있고 "차기 배포
#   스프린트에 IRSA 분리 예정"이라 FAIL이 아니라 REVIEW로 보고한다(2.2 항목에 코멘트 병기).
VPC_CNI_IRSA_NOT_SEPARATED_NOTE = (
    "VPC CNI가 전용 IRSA 없이 워커노드 IAM 역할의 AmazonEKS_CNI_Policy를 상속받는 구조"
    " — 인프라팀 인지·개선 예정(차기 배포 스프린트에 IRSA 분리 반영 예정), REVIEW 권장"
)

# 2.3(기타 서비스) 인스턴스/네트워크 외 서비스별 IAM 최소권한 정의서
# [TODO] 2.1/2.2와 달리 아직 미확정 — KMS/S3/SecretManager baseline은 spec 3.1.1절에
# 별도 확보돼 있으나(2026-09-11) IAM 역할-서비스 매핑 규칙이 없어 이 변수 자체는 계속 TODO.
SERVICE_IAM_POLICY_MAP = None

# 3.2 보안그룹 인/아웃바운드 규칙 baseline
# [확정 — 2026-09-13 인프라팀 노션 회신] 인바운드는 VPC 내부 대역만 전체 허용, 외부
# 인터넷(0.0.0.0/0) 인바운드는 전면 차단. 아웃바운드의 0.0.0.0/0은 정상(방향 구분 필수).
SG_ALLOWED_INBOUND_CIDR = "10.0.0.0/16"

# 3.6 NAT 연결 "목적 확인된 리소스" 목록 [확정 — 2026-09-13 인프라팀 노션 회신]
# source/dest check 비활성화 여부는 절대기준으로 자동판정(기존 로직 유지).
NAT_PURPOSE_CONFIRMED_RESOURCES = {
    "nat_instance_names": ["eks-nat-instance-2a", "eks-nat-instance-2c"],
    "nat_public_subnet_cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
    "allowed_private_subnet_cidrs": ["10.0.16.0/20", "10.0.32.0/20"],
}

# 3.10⑤ ELB Idle Timeout 기준(초) [확정 — 2026-09-13 인프라팀 승인]
# "현재 60초로 설정, 필요시 60초 이상 조정 가능" — 절대기준은 ">= 60초"(정확히 60초도
# PASS). 나머지 7개 항목(리스너/SSL Policy/액세스로그/Deletion Protection/헬스체크/
# 보안그룹/Cross-Zone)은 이미 확정, 항상 판정.
ELB_IDLE_TIMEOUT_SECONDS = 60

# 4.12 로그 보관 기간 최소 기준(일) [확정]
LOG_RETENTION_MIN_DAYS = 365

# EKS 클러스터 이름 목록 [TODO — 실행 시 --eks-clusters 옵션으로도 전달 가능]
EKS_CLUSTER_NAMES = None
