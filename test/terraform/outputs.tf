output "nomfa_iam_user" {
  value = aws_iam_user.nomfa.name
}

output "open_sg_id" {
  value = aws_security_group.open_ingress.id
}

output "public_test_bucket" {
  value = aws_s3_bucket.public_test.bucket
}

output "reminder" {
  value = "테스트 끝나면 반드시 'terraform destroy' 실행 — 계정 S3 Public Access Block이 꺼진 채로 방치하지 말 것"
}
