"""클라우드(AWS CLI/boto3) 점검 기준값.

Ansible의 group_vars/all.yml과 동일한 원칙: 로직은 항상 작성하고, 값이 없으면(None)
해당 항목은 SKIP으로 떨어진다. 값이 정해지면 이 파일만 수정하면 되고 checks/*.py
로직은 건드릴 필요가 없다.

⚠ 이 파일은 실제 운영용이다 — 로컬 테스트용 임의값은 절대 여기 넣지 말고
`config_test.py`(테스트 전용, `cloud_check.py --test-config`로만 로드됨)에 넣을 것.

출처: 인프라점검_항목분류표_v0_3.xlsx 클라우드 시트 "확정 기준값" 컬럼
"""

# 1.1 업무상 인가된 관리자(AdministratorAccess 직접보유) 화이트리스트 [TODO] — 확인요청 표 14번
IAM_ADMIN_WHITELIST = None

# 1.1 테스트/불필요 계정 네이밍 블랙리스트 [확정] — 정적 판정, 외부 확인 불필요
TEST_ACCOUNT_NAME_PATTERNS = [r"^testuser$", r"^test\d+$"]

# 1.2 IAM 계정-담당자 매핑표(1인 1계정 검증용) [TODO] — 확인요청 표 15번, {user_name: owner_id}
IAM_ACCOUNT_OWNER_MAP = None

# 1.8 Admin Console Access Key 사용주기 [확정] — AWS Config Rule로 구현(인프라팀 회신 2026-09-10)
# maxAccessKeyAge=60으로 이미 Terraform 배포됨. 자체 계산 대신 컴플라이언스 상태를 그대로 매핑.
ACCESS_KEY_ROTATION_CONFIG_RULE = "access-keys-rotated"

# 1.4 IAM 그룹 사용자 화이트리스트 [TODO] — {group_name: [allowed_user_names]}
IAM_GROUP_WHITELIST = None

# 1.6 Key Pair 보관 위치 [TODO] — 코드 조회보다 수동확인에 가까운 항목, 자동화 대상 아님
KEY_PAIR_STORAGE_CHECK_NOTE = "Key Pair(PEM) 보관 위치는 코드로 조회 불가 — 수동 확인 필요"

# 1.11 EKS 접근 인가 사용자 화이트리스트(aws-auth ConfigMap) [TODO]
EKS_ACCESS_WHITELIST = None

# 2.1~2.3 서비스별 IAM 최소권한 정의서 [TODO — BE팀 API 명세서 기반 매핑 진행 중]
SERVICE_IAM_POLICY_MAP = None

# 3.2 보안그룹 인/아웃바운드 필요 규칙 화이트리스트 [TODO]
SG_ALLOWED_RULES_WHITELIST = None

# 3.6 NAT 연결 "목적 확인된 리소스" 목록 [TODO] — source/dest check 비활성화 여부는 절대기준으로 자동판정
NAT_PURPOSE_CONFIRMED_RESOURCES = None

# 3.10⑤ ELB Idle Timeout 기준(초) [TODO] — BE(Payment)-인프라팀 협의 중(60~300초 범위)
# 나머지 7개 항목(리스너/SSL Policy/액세스로그/Deletion Protection/헬스체크/보안그룹/Cross-Zone)은 확정, 항상 판정
ELB_IDLE_TIMEOUT_SECONDS = None

# 4.12 로그 보관 기간 최소 기준(일) [확정]
LOG_RETENTION_MIN_DAYS = 365

# EKS 클러스터 이름 목록 [TODO — 실행 시 --eks-clusters 옵션으로도 전달 가능]
EKS_CLUSTER_NAMES = None
