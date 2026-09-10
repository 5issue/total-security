# cloud_check.py 검증용 — 계정 893961164525(default AWS CLI profile) 안에
# 의도적 FAIL 패턴 몇 개만 최소로 만든다 (spec 6.5절 참고).
# 실제 fintech-platform 리소스는 건드리지 않음 — 전부 신규 생성 + infracheck-test- 접두어.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "infra-check-test"
      ManagedBy = "terraform"
      Purpose   = "cloud_check.py local test - destroy after use"
    }
  }
}
