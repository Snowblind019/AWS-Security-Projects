# CloudTrail Log Analyzer (SQL/Athena)

AWS serverless security monitoring tool that analyzes CloudTrail logs using Athena SQL queries to detect suspicious activities and security threats.

## Why I Built This

After building the S3 and Security Group auditors, I wanted to try my hand at adding SQL for log analysis. When I started this project, I didn't know any SQL, and I was learning the basics of each function as I needed it. Now that I've finished, I'm going back to learn SQL fundamentals properly to fill in the gaps. This was a challenging project but it felt good seeing it work in the end. Honestly, Google was definitely my best friend throughout this.

## What It Does

Runs on a schedule (daily) and uses Athena SQL queries to scan CloudTrail logs for suspicious activities:

**Critical Findings:**
- Root account usage
- CloudTrail modifications (someone trying to disable logging)

**High Severity:**
- Failed authentication attempts
- IAM policy changes

**Medium Severity:**
- Security group modifications
- S3 bucket policy changes

Sends email alerts via SNS when suspicious activities are detected, grouped by severity.

## Tech Stack

- **AWS Lambda** - Python 3.12 runtime
- **AWS Athena** - SQL query engine for S3 data
- **AWS Glue** - Data catalog for CloudTrail log schema
- **AWS SNS** - Email notifications
- **AWS EventBridge** - Scheduled triggers
- **SAM/CloudFormation** - Infrastructure as Code

## Deployment

Prerequisites: AWS CLI, SAM CLI, and CloudTrail enabled

```bash
sam build
sam deploy --guided
```

You'll be prompted for:
- Email address for alerts
- CloudTrail S3 bucket name
- Athena output bucket name (will be created)
- Schedule (default: daily)

Confirm the SNS subscription in your email after deployment.

## Sample SQL Query

Here's how the root account detection works:

```sql
SELECT 
    eventtime,
    eventname,
    sourceipaddress,
    awsregion
FROM cloudtrail_logs.cloudtrail_table
WHERE useridentity.type = 'Root'
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '24' hour
ORDER BY eventtime DESC
LIMIT 100
```

Breaking it down:
- `WHERE useridentity.type = 'Root'` - filters for root account events
- `from_iso8601_timestamp(eventtime)` - converts timestamp and filters to last 24 hours
- `ORDER BY eventtime DESC` - most recent events first
- Uses dot notation (`useridentity.type`) because CloudTrail logs are JSON

## What I Learned

- How Athena queries work and how to write SQL for log analysis
- Setting up AWS Glue data catalog to make S3 data queryable
- CloudTrail log structure and common attack patterns (root usage, failed auth, etc.)
- Difference between querying data vs downloading/parsing it (massive performance difference)
- Managing asynchronous Athena queries - you start a query, poll for completion, then get results

The hardest part was understanding the Glue table schema. CloudTrail logs have nested JSON structures, and figuring out how to query nested fields like `useridentity.type` took some trial and error in the Athena console.

Also learned that Athena queries are asynchronous - you can't just run a query and immediately get results. You have to poll the query status, which required different error handling than I'm used to with synchronous API calls.