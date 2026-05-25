# Security

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you notify AWS Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

## AWS Services Used

This pattern deploys and interacts with the following AWS services:

- Amazon EventBridge (scheduled triggers)
- AWS Step Functions (workflow orchestration)
- AWS CodeBuild (Terraform plan/apply execution)
- AWS Lambda (drift classification)
- Amazon SNS (notifications)
- Amazon S3 (plan outputs, audit trail)
- AWS KMS (encryption at rest)
- Amazon CloudWatch (metrics, logs, dashboard)
- AWS IAM (service roles and policies)
- Amazon DynamoDB (Terraform state locking)

## Known Security Considerations

The following items are accepted security trade-offs for this sample pattern. Each is documented
inline in the Terraform code with rationale.

| # | Item | Rationale |
|---|------|-----------|
| D1 | `Resource = "*"` on EC2/IAM/S3 Describe/Get/List in CodeBuild role | These APIs do not support resource-level permissions per AWS IAM documentation |
| D2 | `Resource = "*"` on `cloudwatch:PutMetricData` and X-Ray actions | API constraint; PutMetricData is restricted by `cloudwatch:namespace` condition |
| D3 | `iam:PutRolePolicy` / `iam:DeleteRolePolicy` on apply role | Required for IAM drift remediation; scoped to `${project_name}-*` ARNs |
| D4 | Lambda environment variables not customer-KMS encrypted | Only env var is the non-sensitive reports bucket name |
| D5 | Lambda not deployed in VPC | Stateless function with AWS-internal API traffic only |
| D6 | Target-infra test bucket uses SSE-AES256 instead of SSE-KMS | Test resource for drift demonstration purposes |
| D7 | Target-infra security group has 0.0.0.0/0 egress | Default Terraform behavior on test resource; intentional drift target |
| D8 | MFA Delete not configured on S3 buckets | Operational complexity outside Terraform; see Production Hardening |

## Production Hardening Recommendations

Before using this pattern in a production environment, implement the following. Recommendations are listed in priority order:

1. **Enable MFA Delete** on the state and reports S3 buckets via AWS CLI:
   ```bash
   aws s3api put-bucket-versioning \
     --bucket <BUCKET_NAME> \
     --versioning-configuration Status=Enabled,MFADelete=Enabled \
     --mfa "<MFA_SERIAL_NUMBER> <MFA_CODE>"
   ```

2. **Deploy Lambda in a VPC** if your Terraform state or target resources are in private subnets.

3. **Enable Lambda reserved concurrency** to prevent runaway invocations:
   ```hcl
   reserved_concurrent_executions = 5
   ```

4. **Add Lambda code signing** to prevent unauthorized code deployment.

5. **Enable X-Ray tracing on Step Functions** for end-to-end observability:
   ```hcl
   tracing_configuration {
     enabled = true
   }
   ```

6. **Restrict CodeBuild network access** using a VPC configuration with private subnets and NAT gateway.

7. **Add abort_incomplete_multipart_upload** to S3 lifecycle rules to prevent storage cost leaks.

8. **Create a threat model** documenting trust boundaries between EventBridge → Step Functions → CodeBuild → Lambda → S3.

9. **Rotate the SNS email subscription** or replace with a Slack/PagerDuty integration for operational alerting.

10. **Scope the CodeBuild apply role** to specific resource ARNs rather than pattern-based wildcards when the target infrastructure is known.

## Resource Cleanup

To remove all resources deployed by this pattern:

```bash
# 1. Destroy the pipeline
cd terraform
terraform destroy

# 2. Destroy target infrastructure
cd ../target-infra
terraform destroy -var="vpc_id=<YOUR_VPC_ID>"

# 3. Delete state backend
aws s3 rb "s3://<YOUR_STATE_BUCKET>" --force --region <YOUR_REGION>
aws dynamodb delete-table --table-name "terraform-drift-detect-locks" --region <YOUR_REGION>
```

## Shared Responsibility Model

This sample follows the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/).
AWS manages the security **of** the cloud infrastructure. You are responsible for security **in** the cloud,
including IAM policies, encryption configuration, network access controls, and operational procedures
deployed by this pattern.
