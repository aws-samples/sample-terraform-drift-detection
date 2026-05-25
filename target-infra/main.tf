# =============================================================================
# Target Infrastructure — Sample resources for drift detection testing
# =============================================================================
# Deploy this first, then use scripts/introduce-drift.sh to create drift.
# The pipeline will detect and classify changes to these resources.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Configure your own S3 backend for state storage
  # Configure your own S3 backend for state storage. See README Step 1.
  # backend "s3" {
  #   bucket         = "<YOUR_STATE_BUCKET>"      # e.g. terraform-drift-detect-state-<account-id>
  #   key            = "target-infra/terraform.tfstate"
  #   region         = "<YOUR_REGION>"
  #   dynamodb_table = "terraform-drift-detect-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
}

variable "project_name" {
  description = "Name prefix for all target resources"
  type        = string
  default     = "terraform-drift-detect"
}

variable "aws_region" {
  description = "AWS Region for target infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID for the security group (use your default VPC)"
  type        = string
}

# --- S3 Bucket (low-risk drift target: tags) ---
resource "aws_s3_bucket" "test_bucket" {
  bucket = "${var.project_name}-drift-test-data"

  tags = {
    Environment = "test"
    ManagedBy   = "terraform"
    Purpose     = "drift-detection-test"
  }
}

resource "aws_s3_bucket_versioning" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "test_bucket" {
  bucket        = aws_s3_bucket.test_bucket.id
  target_bucket = aws_s3_bucket.test_bucket.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_policy" "test_bucket_tls" {
  bucket = aws_s3_bucket.test_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.test_bucket.arn,
          "${aws_s3_bucket.test_bucket.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# --- Security Group (critical drift target: ingress rules) ---
resource "aws_security_group" "test_sg" {
  name        = "${var.project_name}-drift-test-sg"
  description = "Security group for drift detection testing"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

# --- IAM Role (critical drift target: policy changes) ---
resource "aws_iam_role" "test_role" {
  name = "${var.project_name}-drift-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy" "test_policy" {
  name = "${var.project_name}-drift-test-policy"
  role = aws_iam_role.test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# =============================================================================
# Outputs
# =============================================================================
output "bucket_name" {
  description = "Name of the test S3 bucket"
  value       = aws_s3_bucket.test_bucket.id
}

output "security_group_id" {
  description = "ID of the test security group"
  value       = aws_security_group.test_sg.id
}

output "iam_role_arn" {
  description = "ARN of the test IAM role"
  value       = aws_iam_role.test_role.arn
}
