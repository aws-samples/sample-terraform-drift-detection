# =============================================================================
# Outputs
# =============================================================================

output "state_machine_arn" {
  description = "ARN of the Step Functions state machine"
  value       = aws_sfn_state_machine.drift_detector.arn
}

output "state_machine_console_url" {
  description = "AWS Console URL for the Step Functions state machine"
  value       = "https://console.aws.amazon.com/states/home#/statemachines/view/${aws_sfn_state_machine.drift_detector.arn}"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for drift notifications"
  value       = aws_sns_topic.drift_alerts.arn
}

output "codebuild_plan_project" {
  description = "Name of the CodeBuild project that runs terraform plan"
  value       = aws_codebuild_project.drift_plan.name
}

output "codebuild_apply_project" {
  description = "Name of the CodeBuild project that runs terraform apply"
  value       = aws_codebuild_project.drift_apply.name
}

output "drift_reports_bucket" {
  description = "S3 bucket storing drift reports and audit trail"
  value       = aws_s3_bucket.drift_reports.id
}

output "classifier_lambda_arn" {
  description = "ARN of the drift classifier Lambda function"
  value       = aws_lambda_function.classifier.arn
}

output "cloudwatch_dashboard_url" {
  description = "AWS Console URL for the CloudWatch drift metrics dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home#dashboards:name=${var.project_name}-dashboard"
}
