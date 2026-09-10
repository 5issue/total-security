# 1.9 MFA 미설정 검증용 — 콘솔 로그인 프로필은 있지만 MFA 디바이스는 등록하지 않은 사용자
# (iam_checks.py check_1_9_mfa 는 로그인 프로필 있는 사용자만 MFA 대상으로 봄)

resource "aws_iam_user" "nomfa" {
  name = "${var.name_prefix}-nomfa"
  path = "/infra-check-test/"
}

resource "aws_iam_user_login_profile" "nomfa" {
  user                    = aws_iam_user.nomfa.name
  password_reset_required = true
  # password는 read-only(computed) 속성이라 직접 지정 불가 — AWS가 자동 생성.
  # 콘솔 로그인 자체를 테스트할 필요는 없음(1.9는 login_profile 존재 여부 + MFA 미등록만 확인).
  # pgp_key 미지정 시 생성된 비밀번호가 state에 평문 저장됨 — 테스트 전용 일회성 계정이라 무해, destroy로 정리.
}
