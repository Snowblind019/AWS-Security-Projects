# AWS Security Group Auditor

Automated Lambda function that scans EC2 security groups for overly permissive rules and sends email alerts via SNS.

## Why I Built This

After building the S3 Security Auditor, I wanted to go a step further and create something to audit EC2 security groups. Open ports to the internet are a common way systems get compromised, so detecting these automatically seemed like a good next project.

## What It Does

Runs on a schedule (daily) and scans all EC2 security groups for rules that allow unrestricted internet access:

**What Gets Flagged:**
- Rules allowing inbound traffic from `0.0.0.0/0` (entire IPv4 internet)
- Rules allowing inbound traffic from `::/0` (entire IPv6 internet)

**Common risky configurations:**
- SSH (port 22) open to the internet
- RDP (port 3389) open to the internet  
- Databases (ports 3306, 5432, etc.) open to the internet
- All ports open to the internet

Sends individual email alerts via SNS for each overly permissive rule found.

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

## Sample Alert

```
Subject: AWS Security Alert: Unrestricted Security Group Rule

WARNING: Security Group with Unrestricted Access

Security Group ID: sg-0a3b4c5d6e7f8g9h
Security Group Name: snowy-server
Protocol: tcp
Port Range: 22 - 22
Source: 0.0.0.0/0 (entire internet)
Description: None
```

## What I Learned

- How EC2 security group rules are structured (IP permissions, port ranges, protocols)
- Difference between IPv4 (0.0.0.0/0) and IPv6 (::/0) unrestricted access
- Using boto3's EC2 resource interface vs client interface
- Iterating through nested rule structures (IpRanges, Ipv6Ranges)
- Sending individual alerts vs batched summaries (different approach than S3 auditor)

The nested structure of security group rules was interesting - each rule has multiple IpRanges and Ipv6Ranges that need separate checking. Initially I missed IPv6 ranges entirely.

## Project Structure

```
.
├── lambda_function.py    # Main security audit logic
├── template.yaml         # SAM infrastructure template
└── README.md            # This file
```