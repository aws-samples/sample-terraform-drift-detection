#!/usr/bin/env python3
"""
Test the drift classifier Lambda locally.

Run this after introducing drift and running terraform plan to validate
the classification logic without deploying the Lambda function.

Usage:
  cd target-infra
  terraform plan -out=plan.tfplan
  terraform show -json plan.tfplan > ../drift_result.json
  cd ..
  python3 scripts/test-classifier-locally.py drift_result.json
"""

import json
import os
import sys
from pathlib import Path

# Classification rules (same as Lambda)
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


def is_tag_only_change(change):
    """Check if the change only affects tags."""
    before = change.get("change", {}).get("before", {}) or {}
    after = change.get("change", {}).get("after", {}) or {}

    before_no_tags = {k: v for k, v in before.items() if k not in ("tags", "tags_all")}
    after_no_tags = {k: v for k, v in after.items() if k not in ("tags", "tags_all")}

    return before_no_tags == after_no_tags


def classify_drift(plan_path: str):
    """Classify drift from a terraform show -json output."""
    if not Path(plan_path).exists():
        print(f"Error: {plan_path} not found.")
        sys.exit(1)

    try:
        with open(plan_path) as f:
            plan_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    if not isinstance(plan_data, dict) or "resource_changes" not in plan_data:
        print("Error: Invalid plan format. Expected terraform show -json output with 'resource_changes' key.")
        sys.exit(1)

    resource_changes = plan_data.get("resource_changes", [])

    # Filter to actual changes
    actual_changes = [
        rc
        for rc in resource_changes
        if rc.get("change", {}).get("actions", ["no-op"]) != ["no-op"]
    ]

    if not actual_changes:
        print("✓ No drift detected!")
        return

    print(f"⚠ Drift detected: {len(actual_changes)} resource(s) changed\n")
    print("=" * 70)

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
        elif is_tag_only_change(change):
            low_changes.append(entry)
        else:
            high_changes.append(entry)

    # Print results
    if critical_changes:
        print("\n🔴 CRITICAL (requires manual approval):")
        for c in critical_changes:
            print(f"   {c['address']} [{', '.join(c['actions'])}]")

    if high_changes:
        print("\n🟠 HIGH (requires manual approval):")
        for c in high_changes:
            print(f"   {c['address']} [{', '.join(c['actions'])}]")

    if low_changes:
        print("\n🟢 LOW (auto-remediate):")
        for c in low_changes:
            print(f"   {c['address']} [{', '.join(c['actions'])}]")

    # Overall verdict
    print("\n" + "=" * 70)
    if critical_changes:
        severity = "CRITICAL"
        action = "NOTIFY + REQUIRE APPROVAL"
    elif high_changes:
        severity = "HIGH"
        action = "NOTIFY + REQUIRE APPROVAL"
    else:
        severity = "LOW"
        action = "AUTO-REMEDIATE"

    print(f"\nOverall severity: {severity}")
    print(f"Recommended action: {action}")
    print(f"\nSummary:")
    print(f"  Critical: {len(critical_changes)}")
    print(f"  High:     {len(high_changes)}")
    print(f"  Low:      {len(low_changes)}")


if __name__ == "__main__":
    plan_file = sys.argv[1] if len(sys.argv) > 1 else "drift_result.json"

    # Validate file path to prevent path traversal
    plan_file = os.path.normpath(plan_file)
    if ".." in plan_file or os.path.isabs(plan_file):
        print("Error: Invalid file path. File must be in current directory.")
        sys.exit(1)

    classify_drift(plan_file)
