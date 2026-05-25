"""
Drift Classifier Lambda — Parses terraform plan JSON and classifies drift by severity.

This Lambda function is invoked by AWS Step Functions after CodeBuild runs
terraform plan. It reads the plan output from S3, classifies each resource
change by severity, and returns an action recommendation.

Classification Rules:
- Critical: Security groups, IAM policies, KMS keys (any modify/delete)
- High: EC2 instances, RDS, Lambda functions, ECS, Load Balancers
- Low: Tag-only changes, description changes, non-functional metadata
- None: No drift detected
"""

import json
import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Resource types that require manual approval if drifted
CRITICAL_RESOURCES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy",
    "aws_kms_key",
    "aws_kms_alias",
}

HIGH_RISK_RESOURCES = {
    "aws_instance",
    "aws_db_instance",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_lb",
    "aws_lb_listener",
}

s3 = boto3.client("s3")
cloudwatch = boto3.client("cloudwatch")


def handler(event, context):
    """
    Classify drift from the latest terraform plan output stored in S3.

    Args:
        event: Contains reports_bucket and buildResult from Step Functions
        context: Lambda context object

    Returns:
        dict with severity, action, message, and categorized changes
    """
    logger.info(f"Event: {json.dumps(event, default=str)}")

    reports_bucket = event.get("reports_bucket") or os.environ.get("REPORTS_BUCKET", "")

    # Find the latest plan output in S3
    try:
        response = s3.list_objects_v2(
            Bucket=reports_bucket,
            Prefix="plans/",
            MaxKeys=100,
        )
        if "Contents" not in response:
            logger.info("No plan outputs found in S3")
            return _no_drift_result("No plan outputs found")

        # Get the most recent file
        objects = sorted(
            response["Contents"], key=lambda x: x["LastModified"], reverse=True
        )
        latest_key = objects[0]["Key"]
        logger.info(f"Reading latest plan: s3://{reports_bucket}/{latest_key}")

        obj = s3.get_object(Bucket=reports_bucket, Key=latest_key)
        plan_data = json.loads(obj["Body"].read().decode("utf-8"))
    except Exception as e:
        logger.error(f"Error reading plan from S3: {e}")
        return {"severity": "error", "action": "none", "message": f"Error: {e}"}

    # Check if drift was detected
    if not plan_data.get("drift_detected", True):
        if not plan_data.get("resource_changes"):
            _publish_metric("NoDrift", 1)
            return _no_drift_result("No drift detected")

    resource_changes = plan_data.get("resource_changes", [])

    # Filter to actual changes (exclude no-op)
    actual_changes = [
        rc
        for rc in resource_changes
        if rc.get("change", {}).get("actions", ["no-op"]) != ["no-op"]
    ]

    if not actual_changes:
        _publish_metric("NoDrift", 1)
        return _no_drift_result("No actionable drift")

    # Classify each change
    critical_changes = []
    high_changes = []
    low_changes = []

    for change in actual_changes:
        resource_type = change.get("type", "")
        actions = change.get("change", {}).get("actions", [])
        address = change.get("address", "unknown")

        entry = {"address": address, "type": resource_type, "actions": actions}

        if resource_type in CRITICAL_RESOURCES:
            critical_changes.append(entry)
        elif resource_type in HIGH_RISK_RESOURCES:
            high_changes.append(entry)
        elif _is_tag_only_change(change):
            low_changes.append(entry)
        else:
            # Default: treat unknown resource types as high risk
            high_changes.append(entry)

    # Determine overall severity and action
    if critical_changes:
        severity = "critical"
        action = "notify_and_approve"
    elif high_changes:
        severity = "high"
        action = "notify_and_approve"
    else:
        severity = "low"
        action = "auto_remediate"

    total = len(critical_changes) + len(high_changes) + len(low_changes)
    _publish_metric("DriftDetected", 1)
    _publish_metric("DriftResourceCount", total)
    _publish_metric(f"Drift_{severity.capitalize()}", 1)

    message = (
        f"{total} drifted resource(s): "
        f"{len(critical_changes)} critical, "
        f"{len(high_changes)} high, "
        f"{len(low_changes)} low"
    )
    logger.info(f"Classification: {severity} — {message}")

    return {
        "severity": severity,
        "action": action,
        "message": message,
        "critical_changes": critical_changes,
        "high_changes": high_changes,
        "low_changes": low_changes,
    }


def _no_drift_result(message):
    """Return a standardized no-drift result."""
    return {
        "severity": "none",
        "action": "none",
        "message": message,
        "critical_changes": [],
        "high_changes": [],
        "low_changes": [],
    }


def _is_tag_only_change(change):
    """Check if the change only affects tags (low-risk)."""
    before = change.get("change", {}).get("before", {}) or {}
    after = change.get("change", {}).get("after", {}) or {}

    before_no_tags = {k: v for k, v in before.items() if k not in ("tags", "tags_all")}
    after_no_tags = {k: v for k, v in after.items() if k not in ("tags", "tags_all")}

    return before_no_tags == after_no_tags


def _publish_metric(name, value):
    """Publish drift metric to CloudWatch custom namespace."""
    try:
        cloudwatch.put_metric_data(
            Namespace="TerraformDrift",
            MetricData=[{"MetricName": name, "Value": value, "Unit": "Count"}],
        )
    except Exception as e:
        logger.warning(f"Failed to publish metric {name}: {e}")
