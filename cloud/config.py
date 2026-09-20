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
# [2026-09-17] S3/SecretManager baseline 확정(윤지수 확인 + total-infra/infra/secrets.tf
# 실측 대조): ESO 미사용, 개별 서비스 파드의 SecretManager 직접 호출 없음 — Terraform이
# total-client-secret을 Secrets Manager에 생성 후 frontend/dev 네임스페이스 K8s Secret
# 으로만 배포하는 구조. 8개 백엔드 서비스 전부 S3·SecretManager 관련 IAM 권한 미보유가 정상.
#
# ⚠ KMS는 baseline 자체는 확정(auth-service만 kms:Sign/kms:GetPublicKey, 서명 키 1개
# 한정, 나머지 7개는 미보유)이나 코드화는 보류. 2026-09-17 total-k8s/total-infra 실측
# 결과 8개 백엔드 서비스(auth 포함) 전부가 ServiceAccount `backend-common-sa` 하나를
# 공유하고 있고(k8s/backend/*/deployment.yaml의 serviceAccountName 전부 동일), 이 SA엔
# eks.amazonaws.com/role-arn annotation이 없음(IRSA 미바인딩) — total-infra의 어떤 .tf
# 파일에도 backend-common-sa용 aws_iam_role이 없음(2.2 ALB IRSA·EBS CSI IRSA·Karpenter
# IRSA와 달리 backend 서비스용 IRSA 자체가 아직 구축 안 됨). 게다가 서비스가 SA를
# 공유하는 구조라, 나중에 IRSA를 붙이더라도 "auth만 KMS 보유"가 구조적으로 불가능
# (권한을 그 SA에 주면 8개 서비스 전부 상속받음) — 인프라팀에 확인요청 전달함
# (인프라점검_확인요청_트래킹.md 참고). 그래서 KMS 하위 체크는 SERVICE_IAM_KMS_CHECK_ENABLED
# 로 게이트해서 SKIP 고정, S3/SecretManager만 우선 코드화.
SERVICE_IAM_POLICY_MAP = {
    "backend_service_account": {"namespace": "backend", "name": "backend-common-sa"},
    "backend_services": [
        "auth-service", "order-service", "payment-service", "product-service",
        "user-service", "oms-service", "wms-service", "scm-service",
    ],
}
SERVICE_IAM_KMS_CHECK_ENABLED = False

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

# 3.10⑥ 헬스체크 경로 예외 [2026-09-20 인프라팀 요청 — 트래킹표 7번]
# "일괄 '/' 기준 적용에 따른 오탐" 소명 — ArgoCD(`/healthz`), Prometheus(`/api/health`)는
# 자체 표준 헬스체크 엔드포인트를 쓰는 정상 구조라 예외 처리 요청. 대상 타겟그룹명을
# 특정하지 않고 경로 값 자체를 허용목록으로 둔다(그 외 서비스가 이 경로를 쓰면 같이
# PASS되지만, 이 두 값 외에는 여전히 '/'만 허용 — 오탐 범위를 요청받은 두 값으로 한정).
ELB_HEALTHCHECK_PATH_EXCEPTIONS = ["/healthz", "/api/health"]

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
# 인증_인가(SVC-08) [2026-09-16 신규 코드화]
#   SG 22번 차단·SSM 세션로그 연동은 자동판정, MFA 강제 여부는 클라우드 1.9(MFA 설정)와
#   판정이 겹쳐서 중복 방지를 위해 True로 확정되기 전까지는 REVIEW로 보류한다.
# -----------------------------------------------------------------------------
SVC08_MFA_CROSS_CHECK_DONE = False   # TODO: 1.9와 담당 정리 끝나면 True로 변경
