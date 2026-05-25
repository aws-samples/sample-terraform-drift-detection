# =============================================================================
# Variables for Terraform Drift Detection Pipeline
# =============================================================================

variable "project_name" {
  description = "Name prefix for all resources created by this pattern"
  type        = string
  default     = "terraform-drift-detect"
}

variable "aws_region" {
  description = "AWS Region where the pipeline will be deployed"
  type        = string
  default     = "us-east-1"
}

variable "notification_email" {
  description = "Email address to receive drift notifications and approval requests"
  type        = string
}

variable "terraform_source_bucket" {
  description = "S3 bucket containing the Terraform source code (ZIP archive)"
  type        = string
}

variable "terraform_source_key" {
  description = "S3 key for the Terraform source code ZIP archive"
  type        = string
  default     = "source/target-infra.zip"
}

variable "terraform_state_bucket" {
  description = "S3 bucket used for Terraform remote state"
  type        = string
}

variable "terraform_lock_table" {
  description = "DynamoDB table used for Terraform state locking"
  type        = string
  default     = "terraform-drift-detect-locks"
}

variable "vpc_id" {
  description = "VPC ID for the target infrastructure security group"
  type        = string
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for drift detection frequency"
  type        = string
  default     = "rate(6 hours)"
}

variable "terraform_version" {
  description = "Terraform version to install in CodeBuild"
  type        = string
  default     = "1.9.8"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Pattern   = "drift-detection"
  }
}
