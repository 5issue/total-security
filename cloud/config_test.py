"""⚠ 테스트 전용 — 실제 값 아님. config.py에 반영 금지.

로컬 테스트 시에만 사용: `python3 cloud_check.py --test-config`
config.py의 None(TODO) 값들을 임의값으로 채워, SKIP 게이트가 풀렸을 때
PASS/FAIL 판정 로직이 기준값에 맞게 정상 동작하는지 확인하기 위한 용도.
실제 조직 값이 확정되면 이 파일이 아니라 config.py를 수정한다.
"""

# 1.4 — 테스트 계정 그룹 예시
IAM_GROUP_WHITELIST = {
    "Admins": ["test-admin"],
    "Developers": ["test-dev1", "test-dev2"],
}

# 1.11 — 테스트 EKS 접근 화이트리스트
EKS_ACCESS_WHITELIST = ["test-admin"]

# 2.1~2.3 — 테스트 서비스별 IAM 정책 매핑 예시
SERVICE_IAM_POLICY_MAP = {
    "order-service": ["dynamodb:*", "sqs:*"],
}

# 3.2 — 테스트 보안그룹 허용 규칙 예시
SG_ALLOWED_RULES_WHITELIST = ["sg-test-allow-1"]

# 3.6 — 테스트 NAT 목적 확인 리소스 예시
NAT_PURPOSE_CONFIRMED_RESOURCES = ["i-testnat01"]

# EKS 클러스터 이름(테스트 계정에 실제 클러스터 없으면 빈 리스트 유지 — 자동탐색으로 대체됨)
EKS_CLUSTER_NAMES = []
