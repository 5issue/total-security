# 3.7 S3 퍼블릭 액세스 차단 검증용
#   ⚠ storage_checks.py의 3.7 로직은 버킷 단위가 아니라 계정 전체
#     (s3control.get_public_access_block, AccountId 단위) 설정을 본다.
#     즉 FAIL을 재현하려면 계정 전체 Public Access Block을 꺼야 한다 — 사용자 확인 후 진행.
#     fintech-platform의 버킷별 자체 차단이 켜져있는 버킷은 영향 없으나, 버킷별 차단이
#     없는 버킷은 이 기간 동안 노출 위험이 있으므로 테스트 완료 즉시 destroy 권장.

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_account_public_access_block" "test" {
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 스펙 6.5절 예시("퍼블릭 액세스 열린 S3 버킷 1개") 패턴 재현용 — 현재 3.7 코드는 계정레벨만
# 보지만, 버킷레벨까지 함께 열어두면 이후 점검항목이 버킷단위로 보강돼도 바로 검증 가능.
resource "aws_s3_bucket" "public_test" {
  bucket        = "${var.name_prefix}-public-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_test" {
  bucket                  = aws_s3_bucket.public_test.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false

  depends_on = [aws_s3_account_public_access_block.test]
}
