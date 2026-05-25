#!/bin/bash
# =============================================================================
# Introduce Drift — Simulates manual changes outside Terraform
# =============================================================================
# Run this AFTER deploying target infrastructure to create intentional drift.
# This simulates someone making changes via the AWS Console or CLI.
#
# Usage:
#   ./scripts/introduce-drift.sh <project-name> <region>
#
# Example:
#   ./scripts/introduce-drift.sh terraform-drift-detect us-east-1
# =============================================================================

set -euo pipefail

PROJECT_NAME="${1:-terraform-drift-detect}"
REGION="${2:-us-east-1}"

echo "=== Introducing drift to test resources ==="
echo "Project: ${PROJECT_NAME}"
echo "Region:  ${REGION}"
echo ""

# --- Low-risk drift: Change tags on S3 bucket ---
echo "1. Adding unauthorized tag to S3 bucket (low-risk drift)..."
aws s3api put-bucket-tagging \
  --bucket "${PROJECT_NAME}-drift-test-data" \
  --tagging 'TagSet=[{Key=Environment,Value=test},{Key=ManagedBy,Value=terraform},{Key=Purpose,Value=drift-detection-test},{Key=UnauthorizedTag,Value=added-via-console}]' \
  --region "$REGION"
echo "   ✓ Tag 'UnauthorizedTag=added-via-console' added"

# --- Critical drift: Add ingress rule to security group ---
echo ""
echo "2. Adding unauthorized SSH ingress rule to security group (critical drift)..."
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=${PROJECT_NAME}-drift-test-sg" \
  --query 'SecurityGroups[0].GroupId' \
  --output text \
  --region "$REGION")

aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "0.0.0.0/0" \
  --region "$REGION" 2>/dev/null || echo "   (rule may already exist)"
echo "   ✓ SSH (port 22) from 0.0.0.0/0 added to $SG_ID"

# --- Critical drift: Modify IAM role policy ---
echo ""
echo "3. Adding unauthorized S3 access to IAM role policy (critical drift)..."
# INTENTIONALLY INSECURE: Adding s3:* permission for drift detection testing.
# This simulates a dangerous policy change made outside Terraform that the
# drift detection pipeline should flag as CRITICAL severity.
aws iam put-role-policy \
  --role-name "${PROJECT_NAME}-drift-test-role" \
  --policy-name "${PROJECT_NAME}-drift-test-policy" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource": "arn:aws:logs:*:*:*"
      },
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
      }
    ]
  }'
echo "   ✓ s3:* permission added to role policy"

echo ""
echo "=== Drift introduced successfully ==="
echo ""
echo "Expected detection results:"
echo "  - S3 bucket tags:  LOW severity (tag-only change)"
echo "  - Security group:  CRITICAL severity (ingress rule added)"
echo "  - IAM policy:      CRITICAL severity (permissions expanded)"
echo ""
echo "Next step: Run terraform plan to detect the drift"
echo "  cd target-infra && terraform plan"
