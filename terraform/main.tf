# =============================================================================
# Terraform Drift Detection & Auto-Remediation Pipeline
# =============================================================================
# Deploys: EventBridge, Step Functions, CodeBuild, Lambda, SNS, S3, CloudWatch
#
# This module creates a fully automated pipeline that:
# 1. Runs terraform plan on a schedule to detect drift
# 2. Classifies drift by severity (critical/high/low)
# 3. Auto-remediates low-risk drift
# 4. Notifies and requires approval for high/critical drift
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# =============================================================================
# S3 Bucket — Drift Reports and Audit Trail
# =============================================================================
resource "aws_s3_bucket" "drift_reports" {
  bucket        = "${var.project_name}-reports-${local.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Purpose = "Terraform drift detection audit trail"
  })
}

resource "aws_s3_bucket_versioning" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sns_encryption.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "drift_reports_tls" {
  bucket = aws_s3_bucket.drift_reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.drift_reports.arn,
          "${aws_s3_bucket.drift_reports.arn}/*",
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

resource "aws_s3_bucket_lifecycle_configuration" "drift_reports" {
  bucket = aws_s3_bucket.drift_reports.id

  rule {
    id     = "expire-old-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

# Note: For production, configure a separate logging bucket to avoid
# self-referential logging. Using self-logging with prefix for simplicity in this sample.
resource "aws_s3_bucket_logging" "drift_reports" {
  bucket        = aws_s3_bucket.drift_reports.id
  target_bucket = aws_s3_bucket.drift_reports.id
  target_prefix = "s3-access-logs/"
}

# =============================================================================
# KMS Key — Encryption for SNS Topic
# =============================================================================
resource "aws_kms_key" "sns_encryption" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${var.project_name}-sns-key-policy"
    Statement = [
      {
        Sid    = "EnableKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowKeyUsageForSNS"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "sns.${local.region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowKeyUsageForEventBridge"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyUsageForLambdaDLQ"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyUsageForCodeBuild"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.codebuild_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyUsageForLambdaRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyUsageForSFNRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.sfn_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyUsageForCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${local.region}:${local.account_id}:*"
          }
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_kms_alias" "sns_encryption" {
  name          = "alias/${var.project_name}-sns"
  target_key_id = aws_kms_key.sns_encryption.key_id
}

# =============================================================================
# SNS Topic — Notifications and Approval Requests
# =============================================================================
resource "aws_sns_topic" "drift_alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.sns_encryption.arn
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.drift_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# =============================================================================
# IAM Role — CodeBuild
# =============================================================================
resource "aws_iam_role" "codebuild_role" {
  name = "${var.project_name}-codebuild-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "codebuild_policy" {
  name = "${var.project_name}-codebuild-policy"
  role = aws_iam_role.codebuild_role.id

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
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [
          "arn:aws:s3:::${var.terraform_source_bucket}",
          "arn:aws:s3:::${var.terraform_source_bucket}/*",
          "arn:aws:s3:::${var.terraform_state_bucket}",
          "arn:aws:s3:::${var.terraform_state_bucket}/*",
          aws_s3_bucket.drift_reports.arn,
          "${aws_s3_bucket.drift_reports.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.terraform_lock_table}"
      },
      {
        # Terraform plan requires read access to managed resources.
        # These Describe/Get/List actions do not support resource-level permissions
        # and require Resource = "*" per AWS IAM documentation.
        Sid    = "TerraformPlanReadAccess"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "s3:GetBucketAcl",
          "s3:GetBucketTagging",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:GetBucketPolicy",
          "s3:GetBucketLocation",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketRequestPayment",
          "s3:GetAccelerateConfiguration",
          "s3:GetBucketCORS",
          "s3:GetBucketWebsite",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = "*"
      },
      {
        # Terraform apply: IAM write actions scoped to project roles
        Sid    = "TerraformApplyIAM"
        Effect = "Allow"
        Action = [
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/${var.project_name}-*"
      },
      {
        # Terraform apply: S3 tagging scoped to project buckets
        Sid    = "TerraformApplyS3"
        Effect = "Allow"
        Action = [
          "s3:PutBucketTagging",
        ]
        Resource = "arn:aws:s3:::${var.project_name}-*"
      },
      {
        # Terraform apply: Security group modifications scoped to account
        Sid    = "TerraformApplyEC2"
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
        ]
        Resource = "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.sns_encryption.arn
      },
    ]
  })
}

# =============================================================================
# CloudWatch Log Groups — CodeBuild and Step Functions
# =============================================================================
resource "aws_cloudwatch_log_group" "codebuild" {
  name              = "/aws/codebuild/${var.project_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.sns_encryption.arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${var.project_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.sns_encryption.arn
  tags              = var.tags
}

# =============================================================================
# CodeBuild Project — terraform plan (Drift Detection)
# =============================================================================
resource "aws_codebuild_project" "drift_plan" {
  name           = "${var.project_name}-plan"
  description    = "Runs terraform plan to detect infrastructure drift"
  service_role   = aws_iam_role.codebuild_role.arn
  build_timeout  = 10
  encryption_key = aws_kms_key.sns_encryption.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"

    environment_variable {
      name  = "REPORTS_BUCKET"
      value = aws_s3_bucket.drift_reports.id
    }

    environment_variable {
      name  = "TF_VERSION"
      value = var.terraform_version
    }

    environment_variable {
      name  = "VPC_ID"
      value = var.vpc_id
    }
  }

  source {
    type      = "S3"
    location  = "${var.terraform_source_bucket}/${var.terraform_source_key}"
    buildspec = file("${path.module}/buildspecs/buildspec-plan.yml")
  }

  logs_config {
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = aws_cloudwatch_log_group.codebuild.name
    }
  }

  tags = var.tags
}

# =============================================================================
# CodeBuild Project — terraform apply (Remediation)
# =============================================================================
resource "aws_codebuild_project" "drift_apply" {
  name           = "${var.project_name}-apply"
  description    = "Runs terraform apply to remediate detected drift"
  service_role   = aws_iam_role.codebuild_role.arn
  build_timeout  = 10
  encryption_key = aws_kms_key.sns_encryption.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"

    environment_variable {
      name  = "TF_VERSION"
      value = var.terraform_version
    }

    environment_variable {
      name  = "VPC_ID"
      value = var.vpc_id
    }
  }

  source {
    type      = "S3"
    location  = "${var.terraform_source_bucket}/${var.terraform_source_key}"
    buildspec = file("${path.module}/buildspecs/buildspec-apply.yml")
  }

  logs_config {
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = aws_cloudwatch_log_group.codebuild.name
    }
  }

  tags = var.tags
}

# =============================================================================
# Lambda — Drift Classifier
# =============================================================================
data "archive_file" "classifier" {
  type        = "zip"
  source_file = "${path.module}/../lambda/classifier.py"
  output_path = "${path.module}/../lambda/classifier.zip"
}

resource "aws_lambda_function" "classifier" {
  function_name    = "${var.project_name}-classifier"
  role             = aws_iam_role.lambda_role.arn
  handler          = "classifier.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.classifier.output_path
  source_code_hash = data.archive_file.classifier.output_base64sha256

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sns_topic.drift_alerts.arn
  }

  environment {
    variables = {
      REPORTS_BUCKET = aws_s3_bucket.drift_reports.id
    }
  }

  tags = var.tags
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.drift_reports.arn,
          "${aws_s3_bucket.drift_reports.arn}/*",
        ]
      },
      {
        # Lambda needs KMS decrypt to read from KMS-encrypted reports bucket
        Sid    = "KMSDecryptForS3"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = aws_kms_key.sns_encryption.arn
      },
      {
        # cloudwatch:PutMetricData does not support resource-level permissions.
        # See: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "TerraformDrift"
          }
        }
      },
      {
        # X-Ray tracing actions do not support resource-level permissions.
        # See: https://docs.aws.amazon.com/xray/latest/devguide/security_iam_id-based-policy-examples.html
        Sid      = "XRayTracing"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.drift_alerts.arn
      },
    ]
  })
}

# =============================================================================
# Step Functions — Orchestrator
# =============================================================================
resource "aws_sfn_state_machine" "drift_detector" {
  name     = "${var.project_name}-orchestrator"
  role_arn = aws_iam_role.sfn_role.arn

  definition = templatefile("${path.module}/state-machine/definition.json", {
    codebuild_plan_project  = aws_codebuild_project.drift_plan.name
    codebuild_apply_project = aws_codebuild_project.drift_apply.name
    classifier_lambda_arn   = aws_lambda_function.classifier.arn
    reports_bucket          = aws_s3_bucket.drift_reports.id
    sns_topic_arn           = aws_sns_topic.drift_alerts.arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tags = var.tags
}

resource "aws_iam_role" "sfn_role" {
  name = "${var.project_name}-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "sfn_policy" {
  name = "${var.project_name}-sfn-policy"
  role = aws_iam_role.sfn_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["codebuild:StartBuild", "codebuild:StopBuild", "codebuild:BatchGetBuilds"]
        Resource = [
          aws_codebuild_project.drift_plan.arn,
          aws_codebuild_project.drift_apply.arn,
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.classifier.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.drift_alerts.arn
      },
      {
        # Step Functions needs KMS access to publish to encrypted SNS topic
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = aws_kms_key.sns_encryption.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
        Resource = "arn:aws:events:${local.region}:${local.account_id}:rule/StepFunctionsGetBuild*"
      },
      {
        # Required for Step Functions to create managed rules for .sync integrations
        Effect = "Allow"
        Action = [
          "events:PutTargets",
          "events:PutRule",
          "events:DescribeRule",
          "events:DeleteRule",
          "events:RemoveTargets",
        ]
        Resource = "arn:aws:events:${local.region}:${local.account_id}:rule/StepFunctions*"
      },
    ]
  })
}

# =============================================================================
# EventBridge — Scheduled Trigger
# =============================================================================
resource "aws_cloudwatch_event_rule" "drift_schedule" {
  name                = "${var.project_name}-schedule"
  description         = "Trigger drift detection on schedule"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sfn_target" {
  rule     = aws_cloudwatch_event_rule.drift_schedule.name
  arn      = aws_sfn_state_machine.drift_detector.arn
  role_arn = aws_iam_role.eventbridge_role.arn

  input = jsonencode({ triggered_by = "scheduled" })
}

resource "aws_iam_role" "eventbridge_role" {
  name = "${var.project_name}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "eventbridge_policy" {
  name = "${var.project_name}-eventbridge-policy"
  role = aws_iam_role.eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.drift_detector.arn
    }]
  })
}

# =============================================================================
# CloudWatch Dashboard — Drift Metrics
# =============================================================================
resource "aws_cloudwatch_dashboard" "drift" {
  dashboard_name = "${var.project_name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["TerraformDrift", "DriftDetected", { stat = "Sum", period = 86400 }],
            ["TerraformDrift", "NoDrift", { stat = "Sum", period = 86400 }],
          ]
          title  = "Drift Detection (Daily)"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["TerraformDrift", "Drift_Critical", { stat = "Sum", period = 86400 }],
            ["TerraformDrift", "Drift_High", { stat = "Sum", period = 86400 }],
            ["TerraformDrift", "Drift_Low", { stat = "Sum", period = 86400 }],
          ]
          title  = "Drift by Severity (Daily)"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          metrics = [
            ["TerraformDrift", "DriftResourceCount", { stat = "Sum", period = 86400 }],
          ]
          title  = "Drifted Resources Count (Daily)"
          region = local.region
        }
      },
    ]
  })
}
