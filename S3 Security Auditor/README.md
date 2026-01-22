# AWS S3 Security Auditor

Automated Lambda function that scans all S3 buckets in an AWS account for security misconfigurations and sends alerts via SNS when issues are detected.

## Why I Built This

I built multiple projects whilst learning boto3 as that's how I learn best. I thought I'd try putting all the things I've learned into a bigger project. This took a while, and I had to reference docs and the internet quite a lot, but I can say I have a way better understanding of this than I ever did.

## What It Does

Runs on a schedule (daily) and checks every S3 bucket for:

**Critical Issues:**
- Public ACLs (AllUsers or AuthenticatedUsers access)
- Public bucket policies (Principal: "*")

**High Severity:**
- Public access block settings not fully enabled

**Medium Severity:**
- Missing default encryption

**Low Severity:**
- Versioning disabled
- Access logging disabled

Sends detailed email alerts via SNS when problems are found, grouped by severity level.

## Tech Stack

- **AWS Lambda** - Python 3.12 runtime
- **AWS SNS** - Email notifications
- **AWS EventBridge** - Scheduled triggers
- **Boto3** - AWS SDK for Python
- **SAM/CloudFormation** - Infrastructure as Code

## Deployment

Prerequisites: AWS CLI and SAM CLI installed

```bash
sam build
sam deploy --guided
```

You'll be prompted for your email address for alerts. Confirm the SNS subscription in your email after deployment.

## What I Learned

- How S3's public access block works (4 separate settings that work together)
- Difference between bucket ACLs and bucket policies for access control
- How to handle various boto3 exceptions (NoSuchBucketPolicy, ServerSideEncryptionConfigurationNotFoundError, etc.)
- Structuring security findings by severity for prioritization
- Using SAM for deploying serverless applications

The public access block check was particularly interesting - some buckets don't have it configured at all, which throws a specific exception that needs separate handling from buckets that have it partially configured.