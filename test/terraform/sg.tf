# 3.1 보안그룹 ANY(0.0.0.0/0) 인바운드 검증용 — 인스턴스에 붙이지 않는 독립 SG
# (network_checks.py check_3_1_sg_any 는 계정 내 전체 SG를 스캔하므로 연결 여부와 무관하게 탐지됨)

resource "aws_security_group" "open_ingress" {
  name        = "${var.name_prefix}-open-ingress"
  description = "infra-check 3.1 test - intentional 0.0.0.0/0 ingress (not attached to any instance)"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "intentional FAIL - 3.1 test"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
