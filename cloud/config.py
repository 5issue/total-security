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
# 1.1 관리자 Role(AdministratorAccess 연결) 인가 목록 [2026-09-29 — 원문 재대조로 Role도 판정 대상에 포함]
#   target-infra: 2026-09-29 인프라팀 회신 — mgmt 서버가 Assume해 점검·클러스터 관리에 쓰는 자동화용 Role
#   (AdministratorAccess 부여 확인). 목록 밖 관리자 Role이 발견되면 FAIL.
IAM_ADMIN_ROLE_WHITELIST = ["target-infra"]

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
    # 2026-09-29 인프라팀 회신 — 백엔드 개발팀 발급 계정
    "be-user1": "손하영",
    "be-user2": "김재우",
    "be-user3": "신지훈",
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

# 1.11 EKS 접근 인가 사용자 화이트리스트(EKS Access Entry)
# [확정 — 2026-09-13 인프라팀 노션 회신] 이 목록 외 STANDARD 타입 Access Entry 발견 시 FAIL.
# [2026-09-18 갱신] 인프라팀 확인 — 이 프로젝트는 aws-auth ConfigMap이 아니라 EKS Access
# Entry로 접근을 관리(트래킹표 2/2-1/2-2번). 인프라팀이 DB Secret 접근·workload
# publication용 목적별 IAM Role(AssumeRole 대상)을 새로 만들면 그 Role ARN도 여기에
# 추가해야 함 — 안 그러면 1.11이 FAIL로 잡는다.
EKS_ACCESS_WHITELIST = [
    "arn:aws:iam::596601390909:user/mgmt-automation-user",
    "arn:aws:iam::596601390909:user/infra-jongwon",
    "arn:aws:iam::596601390909:user/infra-youngheon",
    "arn:aws:iam::596601390909:user/infra-mingyu",
    "arn:aws:iam::596601390909:user/infra-jaehyeok",
    "arn:aws:iam::596601390909:user/infra-jiyoon",
    # 2026-09-28 인프라팀 회신 — 백엔드 개발팀 개발/운영 점검용 IAM 사용자
    "arn:aws:iam::596601390909:user/be-user1",
    "arn:aws:iam::596601390909:user/be-user2",
    "arn:aws:iam::596601390909:user/be-user3",
    # 2026-09-28 인프라팀 회신 — 백엔드 배포 작업 시 DB 인증 정보 조회용 목적별 Role(위 2026-09-18 안내의 DB Secret 접근용)
    "arn:aws:iam::596601390909:role/db-admin-secret-reader",
    # EKS 서비스 연결 역할(AWS 관리형) — 클러스터 운영용으로 AWS가 생성·관리
    "arn:aws:iam::596601390909:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
    # 2026-09-28 인프라팀 회신(목적별 Role)
    "arn:aws:iam::596601390909:role/eks-cluster-access",            # 인프라 운영 공통 조회용(MFA 필수, 클러스터 조회만·변경 불가)
    "arn:aws:iam::596601390909:role/rabbitmq-redis-secret-reader",  # RabbitMQ/Redis Secret 조회 전용(담당: 지윤, 종원)
    "arn:aws:iam::596601390909:role/target-infra",                  # EKS 전체 관리 권한(자동화 계정 — 개인 계정 대신 클러스터 접근에 사용)
    "arn:aws:iam::596601390909:role/total-workload-publication",    # 워크로드 Secret 최소권한 배포용
]

# 1.12 EKS 서비스 어카운트 토큰 자동 마운트 — 판정 범위
# [2026-09-24 보안팀 판단(사용자 확정)] 원문은 "애플리케이션이 K8s API를 호출할 필요가
# 없는 경우" 자동 마운트를 끄라고 하므로, API 호출이 본업인 컨트롤러/오퍼레이터 SA(argocd,
# karpenter, cert-manager 등)는 대상에서 제외한다. 판정 대상: 모든 네임스페이스의 default SA
# + 아래 앱 네임스페이스의 SA. 앱 네임스페이스 안에서도 K8s API가 실제로 필요한 SA는
# 인프라팀 확인 후 "네임스페이스/SA이름" 형식으로 예외에 추가한다.
EKS_APP_NAMESPACES = ["backend", "frontend", "dev"]
EKS_SA_API_ACCESS_EXCEPTIONS = [
    "backend/shared-pg",   # 2026-09-24 — CNPG DB 파드용 SA(인스턴스 매니저가 K8s API로 클러스터 상태를 관리)
    "backend/moco-shared-mysql",     # 2026-09-28 인프라팀 회신 — MOCO MySQL 인스턴스 라이프사이클 관리·모니터링
    "backend/shared-mysql-backup",   # 2026-09-28 인프라팀 회신 — 백업 실행 및 백업 상태 CRD/Secret 갱신
]

# 2.1(인스턴스 서비스) — EKS 워커노드/NAT 인스턴스 IAM 역할에 허용된 관리형 정책
# [확정 — 2026-09-13 인프라팀 직접 질의 회신] 이름 외 정책이 붙어 있으면(초과) FAIL,
# 누락돼도 FAIL(권한 부족으로 오작동 가능성). ARN 전체가 아니라 정책 이름만 비교.
EKS_WORKER_NODE_REQUIRED_POLICIES = [
    "AmazonEKSWorkerNodePolicy",
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonSSMManagedInstanceCore",
    "AmazonEKS_CNI_Policy",
    "test-eks-node-ansible-s3",   # 2026-09-28 인프라팀 회신 — Ansible(aws_ssm 연결) 통신·산출물 임시 저장용 S3 정책
]
NAT_INSTANCE_REQUIRED_POLICIES = [
    "AmazonSSMManagedInstanceCore",
    "test-eks-node-ansible-s3",   # 2026-09-28 인프라팀 회신 — 위와 동일
]

# 2.2(네트워크 서비스) — ALB(aws-load-balancer-controller IRSA) + VPC CNI
# [확정 — 2026-09-13 인프라팀 직접 질의 회신]
# ALB: 실제 역할의 권한이 reference/alb_iam_policy.json(공식 정책, 2026-09-13 고정)의
#   부분집합인지 대조(초과 권한만 FAIL). K8s ServiceAccount 이름/네임스페이스는 AWS Load
#   Balancer Controller Helm 차트 기본값을 그대로 사용한다는 전제.
ALB_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-load-balancer-controller"}
# VPC CNI IRSA [2026-09-20 인프라팀 회신 — 트래킹표 9번, 구현 완료]
#   기존엔 워커노드 IAM 역할의 AmazonEKS_CNI_Policy를 그대로 상속받는 구조라 항상 REVIEW
#   고정이었으나, `infra/irsa.tf`에 aws-node 전용 IRSA Role을 신규 생성해 애드온에 바인딩,
#   노드 그룹의 `iam_role_attach_cni_policy = false`로 워커노드 IAM 역할에서 CNI 권한을
#   회수했다고 확인 — 이제 kube-system/aws-node ServiceAccount의 IRSA annotation 실측
#   여부로 실제 판정한다(annotation 있으면 PASS, 없으면 아직 미반영 — REVIEW).
VPC_CNI_IRSA_SERVICE_ACCOUNT = {"namespace": "kube-system", "name": "aws-node"}
VPC_CNI_IRSA_NOT_SEPARATED_NOTE = (
    "VPC CNI가 전용 IRSA 없이 워커노드 IAM 역할의 AmazonEKS_CNI_Policy를 상속받는 구조"
    " — 2026-09-20 인프라팀 회신으로는 이미 분리 완료라 했으나 aws-node ServiceAccount에서"
    " IRSA annotation을 확인하지 못함(반영 전이거나 조회 실패), REVIEW 권장"
)

# 2.3(기타 서비스) 인스턴스/네트워크 외 서비스별 IAM 최소권한 정의서
# [2026-09-22] 인프라팀이 공용 ServiceAccount(backend-common-sa) 공유 구조를 폐기하고
# 서비스별 전용 SA + 1:1 IRSA Role로 분리 완료(트래킹표 8-1번) — 서비스별로 SA를 각각
# 조회해서 S3/SecretManager 과잉권한(전원 미보유가 baseline) + KMS(auth-service만
# kms:Sign/kms:GetPublicKey 보유, 나머지는 미보유가 baseline)를 대조한다.
# ⚠ kubectl 확인 결과 ai-sa(kurly-ai-serving)도 존재하나 원래 2.3 스코프(8개 서비스)
# 밖이라 아래 매핑에는 포함하지 않음 — 스코프에 넣을지는 별도 확인 필요.
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
# 2026-09-28 인프라팀 회신 — auth-service는 KMS 비대칭 키(alias/auth-jwt-signing)로 JWT 서명·검증,
# kms:Verify·kms:DescribeKey도 필수 호출(IRSA auth-service-irsa)
SERVICE_IAM_KMS_ALLOWED_ACTIONS = ["kms:Sign", "kms:GetPublicKey", "kms:Verify", "kms:DescribeKey"]

# 3.2 보안그룹 인/아웃바운드 규칙 baseline
# [확정 — 2026-09-13 인프라팀 노션 회신] 인바운드는 VPC 내부 대역만 전체 허용, 외부
# 인터넷(0.0.0.0/0) 인바운드는 전면 차단. 아웃바운드의 0.0.0.0/0은 정상(방향 구분 필수).
SG_ALLOWED_INBOUND_CIDR = "10.0.0.0/16"
# [2026-09-28 인프라팀 회신] 외부 인바운드가 있던 SG(sg-000532a79a28df296)는 ALB용 — internet-facing
# ALB에 붙은 SG는 아래 포트의 외부(0.0.0.0/0, ::/0) 인바운드를 허용. SG ID는 인프라 재생성 때
# 바뀌므로(9/23→9/24 확인) ID 대신 ALB 연결 여부로 자동 탐지(checks/network_checks.py).
ALB_PUBLIC_INBOUND_PORTS = [80, 443]

# 3.6 NAT 연결 "목적 확인된 리소스" 목록 [확정 — 2026-09-13 인프라팀 노션 회신]
# source/dest check 비활성화 여부는 절대기준으로 자동판정(기존 로직 유지).
NAT_PURPOSE_CONFIRMED_RESOURCES = {
    "nat_instance_names": ["eks-nat-instance-2a", "eks-nat-instance-2c"],
    "nat_public_subnet_cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
    "allowed_private_subnet_cidrs": ["10.0.16.0/20", "10.0.32.0/20"],
}

# 3.10 — [2026-09-28] 원문(ELB 제어 정책 ELB.1~16) 기준으로 재작성하면서 원문에 없는 Idle Timeout
# (ELB_IDLE_TIMEOUT_SECONDS)·헬스체크 경로 예외(ELB_HEALTHCHECK_PATH_EXCEPTIONS) 기준값은 삭제.
# 판정 정책·기준은 checks/elb_checks.py 참고(기준값이 원문 고정값이라 설정 불필요).

# 4.12 로그 보관 기간 최소 기준(일) [확정]
LOG_RETENTION_MIN_DAYS = 365

# EKS 클러스터 이름 목록 [TODO — 실행 시 --eks-clusters 옵션으로도 전달 가능]
EKS_CLUSTER_NAMES = None

# EKS kubeconfig 컨텍스트 중복 해소 [확정 — 2026-09-20 인프라팀 회신(트래킹표 6번)]
# mgmt 서버 kubeconfig에 "test-eks"로 매칭되는 컨텍스트가 여러 개 있어 1.11/1.12/1.13/3.9가
# SKIP 처리되던 문제. 인프라팀이 정확한 클러스터 ARN을 확정 회신함 — 클러스터 이름을 키로
# 강제 지정할 컨텍스트 이름을 매핑해두면 eks_checks._resolve_context()가 목록 중 여러 개가
# 매칭돼도 이 값을 우선 사용한다(mgmt 서버 kubeconfig 자체의 중복 정리는 별도 사안).
EKS_KUBECONFIG_CONTEXT_OVERRIDE = {
    "test-eks": "arn:aws:eks:ap-northeast-2:596601390909:cluster/test-eks",
}

# -----------------------------------------------------------------------------
# 인증_인가(SVC-08) [2026-09-16 신규 코드화] — SG 22번 차단·SSM 세션로그 연동·SSM 접근 MFA 강제 자동판정
# -----------------------------------------------------------------------------
# [2026-09-28] SVC-08 MFA를 직접 판정(IAM 사용자별 MFA 없이 ssm:StartSession 허용 여부 시뮬레이션)하면서
# 기존 SVC08_MFA_CROSS_CHECK_DONE 플래그 삭제. 아래는 운영 관리자가 아닌 자동화 계정 — 점검 스크립트(Ansible
# aws_ssm 연결)가 SSM 세션을 여는 계정이라 MFA를 쓸 수 없어 판정에서 제외(상세에 표시).
SVC08_MFA_EXCEPTIONS = ["mgmt-automation-user"]
