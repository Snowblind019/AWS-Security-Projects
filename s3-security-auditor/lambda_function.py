import boto3
import logging
import os
import json
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def error_code(exc):
    """Extract the AWS error code from a ClientError."""
    return exc.response.get('Error', {}).get('Code', '')


def lambda_handler(event, context):
    """
    Scans all S3 buckets for common security misconfigurations.

    Checks for:
    - Public access (public access block, ACLs, bucket policies)
    - Encryption status
    - Versioning status
    - Logging status
    """

    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')

    if not sns_topic_arn:
        logger.error("SNS_TOPIC_ARN environment variable not set")
        return {
            'statusCode': 500,
            'body': 'Configuration error: SNS_TOPIC_ARN not set'
        }

    try:
        s3_client = boto3.client('s3')
        sns_client = boto3.client('sns')

        # Paginate: list_buckets returns a continuation token above 10,000 buckets
        buckets = []
        paginator = s3_client.get_paginator('list_buckets')
        for page in paginator.paginate():
            buckets.extend(page.get('Buckets', []))

        logger.info(f"Scanning {len(buckets)} S3 bucket(s)")

        findings = []

        for bucket in buckets:
            bucket_name = bucket['Name']
            logger.info(f"Checking bucket: {bucket_name}")

            # A bucket outside the Lambda's region must be queried with a client
            # in that region, otherwise every call returns a 301 redirect.
            regional_client = client_for_bucket(s3_client, bucket_name)

            if regional_client is None:
                findings.append({
                    'bucket': bucket_name,
                    'severity': 'ERROR',
                    'issue': 'Bucket Could Not Be Scanned',
                    'details': 'Unable to determine bucket region. This bucket was NOT audited.'
                })
                continue

            findings.extend(check_bucket_security(regional_client, bucket_name))

        scanned = len(buckets) - len([f for f in findings if f['severity'] == 'ERROR'])

        if findings:
            send_alert(sns_client, sns_topic_arn, findings, len(buckets), scanned)
            logger.warning(f"S3 security audit found {len(findings)} issue(s)")
        else:
            logger.info("S3 security audit completed with no findings")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'S3 security audit complete',
                'buckets_found': len(buckets),
                'buckets_scanned': scanned,
                'findings_count': len(findings)
            })
        }

    except Exception as e:
        logger.error(f"Error during S3 security audit: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }


def client_for_bucket(s3_client, bucket_name):
    """
    Return an S3 client bound to the bucket's own region.

    get_bucket_location returns None for us-east-1 (a historical quirk of the
    API), so that case is mapped explicitly.
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        region = response.get('LocationConstraint') or 'us-east-1'
        return boto3.client('s3', region_name=region)
    except ClientError as e:
        logger.error(f"Cannot determine region for {bucket_name}: {error_code(e)}")
        return None


def check_bucket_security(s3_client, bucket_name):
    """
    Check a single bucket for security issues.
    Returns a list of findings for this bucket.
    """
    findings = []

    checks = [
        check_public_access_block,
        check_bucket_acl,
        check_bucket_policy,
        check_encryption,
        check_versioning,
        check_logging,
    ]

    for check in checks:
        try:
            result = check(s3_client, bucket_name)
        except Exception as e:
            # Defense in depth: one unexpected failure must not abort the scan
            # and leave every remaining bucket unaudited.
            result = check_failed(bucket_name, check.__name__, type(e).__name__)

        if result:
            findings.append(result)

    return findings


def check_public_access_block(s3_client, bucket_name):
    """Check if public access block is enabled"""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']

        if not all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ]):
            return {
                'bucket': bucket_name,
                'severity': 'HIGH',
                'issue': 'Public Access Block Not Fully Enabled',
                'details': 'Bucket does not have all four public access block settings enabled',
                'current_config': config
            }
    except ClientError as e:
        code = error_code(e)
        if code == 'NoSuchPublicAccessBlockConfiguration':
            return {
                'bucket': bucket_name,
                'severity': 'HIGH',
                'issue': 'Public Access Block Not Configured',
                'details': 'Bucket has no public access block configuration'
            }
        return check_failed(bucket_name, 'public access block', code)

    return None


def check_bucket_acl(s3_client, bucket_name):
    """Check bucket ACL for public access"""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)

        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')

            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return {
                        'bucket': bucket_name,
                        'severity': 'CRITICAL',
                        'issue': 'Bucket Has Public ACL',
                        'details': f'Bucket grants {permission} to {uri}'
                    }
    except ClientError as e:
        return check_failed(bucket_name, 'bucket ACL', error_code(e))

    return None


def check_bucket_policy(s3_client, bucket_name):
    """
    Check bucket policy for public access.

    Uses GetBucketPolicyStatus rather than parsing the policy by hand. AWS
    evaluates the full policy including conditions, which hand-rolled logic
    gets wrong in both directions: a Principal of "*" scoped by a condition
    such as aws:SourceVpce or aws:PrincipalOrgID is not actually public, and
    the list form {"AWS": ["*"]} is public but does not match a string compare
    against "*".
    """
    try:
        status = s3_client.get_bucket_policy_status(Bucket=bucket_name)

        if status.get('PolicyStatus', {}).get('IsPublic'):
            return {
                'bucket': bucket_name,
                'severity': 'CRITICAL',
                'issue': 'Bucket Policy Allows Public Access',
                'details': 'AWS evaluates this bucket policy as public'
            }
    except ClientError as e:
        code = error_code(e)
        if code == 'NoSuchBucketPolicy':
            # No policy at all is fine
            return None
        return check_failed(bucket_name, 'bucket policy', code)

    return None


def check_encryption(s3_client, bucket_name):
    """Check if bucket has default encryption enabled"""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return None
    except ClientError as e:
        code = error_code(e)
        if code == 'ServerSideEncryptionConfigurationNotFoundError':
            return {
                'bucket': bucket_name,
                'severity': 'MEDIUM',
                'issue': 'Encryption Not Enabled',
                'details': 'Bucket does not have default encryption enabled'
            }
        return check_failed(bucket_name, 'encryption', code)


def check_versioning(s3_client, bucket_name):
    """Check if bucket has versioning enabled"""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')

        if status != 'Enabled':
            return {
                'bucket': bucket_name,
                'severity': 'LOW',
                'issue': 'Versioning Not Enabled',
                'details': f'Bucket versioning status is {status}'
            }
    except ClientError as e:
        return check_failed(bucket_name, 'versioning', error_code(e))

    return None


def check_logging(s3_client, bucket_name):
    """Check if bucket has access logging enabled"""
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)

        if 'LoggingEnabled' not in response:
            return {
                'bucket': bucket_name,
                'severity': 'LOW',
                'issue': 'Access Logging Not Enabled',
                'details': 'Bucket does not have server access logging enabled'
            }
    except ClientError as e:
        return check_failed(bucket_name, 'access logging', error_code(e))

    return None


def check_failed(bucket_name, check_name, code):
    """
    Turn an unexpected API failure into a reported finding.

    A security tool must never let "could not check" look identical to
    "checked and clean", so an AccessDenied or throttling error surfaces in
    the alert rather than only in the logs.
    """
    logger.error(f"Check '{check_name}' failed for {bucket_name}: {code}")
    return {
        'bucket': bucket_name,
        'severity': 'ERROR',
        'issue': f'Check Failed: {check_name}',
        'details': f'Could not evaluate {check_name} ({code}). Status unknown, not clean.'
    }


def send_alert(sns_client, topic_arn, findings, total_buckets, scanned_buckets):
    """Send a single SNS digest with all findings, grouped by severity"""
    try:
        by_severity = {
            level: [f for f in findings if f['severity'] == level]
            for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ERROR')
        }

        subject = f"AWS S3 Security Audit - {len(findings)} Issue(s) Found"

        message = f"""S3 Security Audit Summary
==========================

Buckets Found:   {total_buckets}
Buckets Scanned: {scanned_buckets}
Total Issues:    {len(findings)}

Severity Breakdown:
  - CRITICAL: {len(by_severity['CRITICAL'])}
  - HIGH:     {len(by_severity['HIGH'])}
  - MEDIUM:   {len(by_severity['MEDIUM'])}
  - LOW:      {len(by_severity['LOW'])}
  - ERROR:    {len(by_severity['ERROR'])} (checks that could not complete)

"""

        message += "\nDETAILED FINDINGS:\n"
        message += "=" * 50 + "\n\n"

        sorted_findings = (
            by_severity['CRITICAL'] + by_severity['HIGH'] + by_severity['MEDIUM']
            + by_severity['LOW'] + by_severity['ERROR']
        )

        for i, finding in enumerate(sorted_findings, 1):
            message += f"[{finding['severity']}] Finding #{i}\n"
            message += f"  Bucket: {finding['bucket']}\n"
            message += f"  Issue: {finding['issue']}\n"
            message += f"  Details: {finding['details']}\n"
            if 'current_config' in finding:
                message += f"  Current Config: {json.dumps(finding['current_config'], indent=2)}\n"
            message += "\n"

        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info(f"SNS alert sent to {topic_arn}")

    except ClientError as e:
        logger.error(f"Failed to send SNS alert: {error_code(e)}")