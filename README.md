# AWS Security Automation Projects

Collection of serverless security auditing tools built while learning AWS security fundamentals and preparing for the AWS Security Specialty certification.

## Why These Projects

I'm transitioning from NOC work into cloud security engineering, and I learn best by building things. These three projects are what I have to show for learning boto3, AWS security services, and automation. Each project builds on concepts from the previous one, getting progressively more complex.

I created this separate repo to showcase these as portfolio pieces as they're more polished and complete than my other learning projects and study notes in my [main AWS Security Specialty repo](https://github.com/Snowblind019/AWS-Security-Specialty-The-Long-Road).

## Projects

### 1. [S3 Security Auditor](./s3-security-auditor)
**What it does**: Scans all S3 buckets for security misconfigurations (public access, missing encryption, etc.) and sends SNS alerts.

**What I learned**: Boto3 S3 operations, handling different security configurations, working with bucket policies vs ACLs.

**Tech**: Lambda (Python), SNS, EventBridge, SAM

---

### 2. [Security Group Auditor](./security-group-auditor)
**What it does**: Scans EC2 security groups for overly permissive rules (0.0.0.0/0 access) and sends individual alerts for each finding.

**What I learned**: Security group rule structures, iterating through nested AWS data, difference between IPv4 and IPv6 checks.

**Tech**: Lambda (Python), SNS, EventBridge, SAM

---

### 3. [CloudTrail Log Analyzer](./cloudtrail-log-analyzer)
**What it does**: Uses Athena SQL queries to analyze CloudTrail logs for suspicious activities (root usage, failed auth, policy changes).

**What I learned**: SQL fundamentals, AWS Glue data catalog, querying logs at scale with Athena, asynchronous query handling.

**Tech**: Lambda (Python), Athena, Glue, SNS, EventBridge, SAM

## Common Patterns

All three projects follow similar patterns:

- **Serverless**: No servers to manage, runs on schedule
- **Event-driven**: Automatically triggers on schedule
- **Cost-effective**: Runs on free tier (< $1/month each)
- **Infrastructure as Code**: Everything deployed via SAM templates

## Technologies Used

- **Python 3.12** - All Lambda functions
- **Boto3** - AWS SDK for Python
- **AWS SAM** - Serverless Application Model for deployment
- **AWS Lambda** - Serverless compute
- **AWS SNS** - Email notifications
- **AWS EventBridge** - Scheduled triggers
- **CloudFormation** - Infrastructure provisioning

## Deployment

Each project can be deployed independently:

```bash
cd project-name/
sam build
sam deploy --guided
```

Follow the prompts for email address and configuration options.

## Skills Demonstrated

- AWS security best practices and common misconfigurations
- Serverless architecture design
- Python automation with boto3
- SQL for log analysis
- Infrastructure as Code with SAM/CloudFormation
- Security monitoring and alerting workflows