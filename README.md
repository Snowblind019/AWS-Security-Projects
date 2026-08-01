# AWS Security Automation Projects

Three serverless security auditing tools: scheduled Lambda functions that scan an AWS account for misconfigurations and suspicious activity, then alert on findings. All deployed via SAM, all running on free tier.

Portfolio companion to my [main AWS Security Specialty repo](https://github.com/Snowblind019/AWS-Security-Specialty-The-Long-Road), which holds the study notes and lab work.

## Projects

### 1. [S3 Security Auditor](./s3-security-auditor)

Scans every bucket in the account for public access, missing default encryption, and disabled versioning or access logging, then groups findings by severity into a single SNS digest.

The interesting part is that "public" is not one check. A bucket can be exposed through an ACL, a bucket policy, or a gap in the Public Access Block configuration, and the three can disagree with each other. The auditor evaluates all three rather than trusting any one of them.

**Stack:** Lambda (Python 3.12), SNS, EventBridge, SAM

---

### 2. [Security Group Auditor](./security-group-auditor)

Scans every EC2 security group for unrestricted inbound rules, covering both `0.0.0.0/0` and `::/0`, and alerts on each finding.

IPv6 is the part worth calling out. IPv4 and IPv6 ranges live in separate structures on the same rule (`IpRanges` and `Ipv6Ranges`), so a group can look clean on every IPv4 check while being wide open on `::/0`. I missed them entirely on the first pass.

**Stack:** Lambda (Python 3.12), SNS, EventBridge, SAM

---

### 3. [CloudTrail Log Analyzer](./cloudtrail-log-analyzer)

Runs Athena queries against CloudTrail logs in S3 for root account usage, failed authentication, IAM policy changes, and other suspicious API activity.

This one is the most involved. Athena queries are asynchronous, so the function submits, polls for execution state, and handles failure and timeout rather than blocking. Partitioning the Glue table by date is what keeps the scan cost near zero instead of reading the entire log history on every run.

**Stack:** Lambda (Python 3.12), Athena, Glue, SNS, EventBridge, SAM

## Design

All three share the same shape:

- **Serverless and scheduled.** EventBridge triggers, no infrastructure to maintain.
- **Scoped permissions.** Each function's SAM template grants only the specific read actions it needs, plus publish on its own topic. Where wildcards appear on the resource, it is because the action does not support resource-level permissions: account-wide calls like `ec2:DescribeSecurityGroups` and `s3:ListAllMyBuckets` can only be granted on `*`.
- **Infrastructure as code.** Everything is in the SAM template, deployable into a clean account.
- **Cost.** Under one dollar per month each on free tier.

## Deployment

Each project deploys independently:

```bash
cd s3-security-auditor/
sam build
sam deploy --guided
```

The guided prompts cover the notification email and schedule.

## Stack

Python 3.12, boto3, AWS SAM and CloudFormation, Lambda, SNS, EventBridge, Athena, Glue.