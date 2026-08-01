# S3 Security Auditor

Scheduled Lambda that scans every S3 bucket in an account for security misconfigurations and emails a single findings digest via SNS.

## What it checks

| Severity | Check |
|----------|-------|
| CRITICAL | Public ACL (AllUsers or AuthenticatedUsers grant) |
| CRITICAL | Bucket policy evaluated as public by AWS |
| HIGH | Public Access Block missing, or not all four settings enabled |
| MEDIUM | No default encryption |
| LOW | Versioning disabled |
| LOW | Server access logging disabled |
| ERROR | A check could not complete (see below) |

## How it works

**Public is not one check.** A bucket can be exposed through an ACL, through a bucket policy, or through a gap in the Public Access Block configuration, and the three can disagree. The auditor evaluates all three rather than trusting any one.

**Policy evaluation is delegated to AWS.** The policy check calls `GetBucketPolicyStatus` instead of parsing the document. Hand-rolled logic gets this wrong in both directions: `Principal: "*"` scoped by a condition such as `aws:SourceVpce` or `aws:PrincipalOrgID` is not actually public, and the list form `{"AWS": ["*"]}` is public but does not match a string comparison against `"*"`. AWS already evaluates the whole policy including conditions, so the API is the correct source of truth.

**Unknown is not clean.** If a check fails, on AccessDenied or throttling, the auditor emits an ERROR finding instead of silently returning nothing. A security tool that reports a bucket it could not read as having no issues is worse than one that reports nothing at all. The digest also prints buckets found against buckets scanned so a gap is visible.

**Buckets are queried in their own region.** `ListBuckets` returns buckets globally, but a `GetBucket*` call against a bucket in another region returns a 301 redirect. The auditor resolves each bucket's region with `GetBucketLocation` first, mapping the null response for us-east-1 to that region explicitly.

**Failures are isolated per check.** One unexpected error cannot abort the run and leave the remaining buckets unaudited.

## Sample alert

```
S3 Security Audit Summary
==========================

Buckets Found:   2
Buckets Scanned: 2
Total Issues:    7

Severity Breakdown:
  - CRITICAL: 0
  - HIGH:     2
  - MEDIUM:   2
  - LOW:      3
  - ERROR:    0 (checks that could not complete)

DETAILED FINDINGS:
==================================================

[HIGH] Finding #1
  Bucket: company-public-assets
  Issue: Public Access Block Not Configured
  Details: Bucket has no public access block configuration

[MEDIUM] Finding #2
  Bucket: company-public-assets
  Issue: Encryption Not Enabled
  Details: Bucket does not have default encryption enabled

[LOW] Finding #3
  Bucket: company-public-assets
  Issue: Versioning Not Enabled
  Details: Bucket versioning status is Disabled
```

## Deployment

Prerequisites: AWS CLI and SAM CLI.

```bash
sam build
sam deploy --guided
```

You will be prompted for the alert email address and the schedule (default daily). Confirm the SNS subscription in your email after deployment.

The function's IAM policy grants read-only S3 configuration calls plus publish on its own topic. `s3:ListAllMyBuckets` is account-scoped and can only be granted on `*`. The per-bucket getters do support resource-level permissions, so they could be narrowed to `arn:aws:s3:::*` or to a named set of buckets; they are left at `*` here because the auditor is meant to scan every bucket including ones created after deployment.

## Limitations

- Bucket-level configuration only. Object-level ACLs are not inspected.
- Cross-account access granted by policy is not distinguished from public access beyond what `GetBucketPolicyStatus` reports.
- No suppression or allowlist. A bucket that is intentionally public will be reported on every run.
- Findings are not deduplicated across runs, so a standing misconfiguration produces a daily email.

## Project structure

```
.
├── lambda_function.py    # Audit logic
├── template.yaml         # SAM infrastructure template
└── README.md
```

## Notes

The exception handling is the part I would flag to anyone building something similar. Several S3 error codes, including `NoSuchBucketPolicy` and `ServerSideEncryptionConfigurationNotFoundError`, are returned by the API but are not modelled in botocore, so `client.exceptions.NoSuchBucketPolicy` does not exist. Catching them that way raises `AttributeError` at handling time, and that error is not caught by a sibling `except Exception` in the same try statement. Catch `ClientError` and switch on `e.response['Error']['Code']` instead.