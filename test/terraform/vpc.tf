# 계정에 default VPC가 없어서(기본프로젝트가 커스텀 VPC를 씀) 3.1 테스트 SG를 위한
# 최소 전용 VPC를 따로 만든다 — fintech-platform 네트워크와 완전히 분리, 라우팅/피어링 없음.
resource "aws_vpc" "test" {
  cidr_block = "10.99.0.0/24"

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}
