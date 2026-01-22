import boto3
import logging
import os
import json

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Scans all S3 buckets for common security misconfigurations.
    
    Checks for:
    - Public access (ACLs and bucket policies)
    - Encryption status
    - Versioning status
    - Logging status
    """
    
    # Get SNS topic from environment variable
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
        
        # Get list of all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        logger.info(f"Scanning {len(buckets)} S3 bucket(s)")
        
        findings = []
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            logger.info(f"Checking bucket: {bucket_name}")
            
            bucket_findings = check_bucket_security(s3_client, bucket_name)
            
            if bucket_findings:
                findings.extend(bucket_findings)
        
        # Send alert if there are findings
        if findings:
            send_alert(sns_client, sns_topic_arn, findings, len(buckets))
            logger.warning(f"S3 security audit found {len(findings)} issue(s)")
        else:
            logger.info("S3 security audit completed with no findings")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'S3 security audit complete',
                'buckets_scanned': len(buckets),
                'findings_count': len(findings)
            })
        }
    
    except Exception as e:
        logger.error(f"Error during S3 security audit: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }


def check_bucket_security(s3_client, bucket_name):
    """
    Check a single bucket for security issues.
    Returns a list of findings for this bucket.
    """
    findings = []
    
    # Check public access block configuration
    public_access_finding = check_public_access_block(s3_client, bucket_name)
    if public_access_finding:
        findings.append(public_access_finding)
    
    # Check bucket ACL for public access
    acl_finding = check_bucket_acl(s3_client, bucket_name)
    if acl_finding:
        findings.append(acl_finding)
    
    # Check bucket policy for public access
    policy_finding = check_bucket_policy(s3_client, bucket_name)
    if policy_finding:
        findings.append(policy_finding)
    
    # Check encryption
    encryption_finding = check_encryption(s3_client, bucket_name)
    if encryption_finding:
        findings.append(encryption_finding)
    
    # Check versioning
    versioning_finding = check_versioning(s3_client, bucket_name)
    if versioning_finding:
        findings.append(versioning_finding)
    
    # Check logging
    logging_finding = check_logging(s3_client, bucket_name)
    if logging_finding:
        findings.append(logging_finding)
    
    return findings


def check_public_access_block(s3_client, bucket_name):
    """Check if public access block is enabled"""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        
        # Check if all settings are enabled
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
                'details': 'Bucket does not have all public access block settings enabled',
                'current_config': config
            }
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            'bucket': bucket_name,
            'severity': 'HIGH',
            'issue': 'Public Access Block Not Configured',
            'details': 'Bucket has no public access block configuration'
        }
    except Exception as e:
        logger.error(f"Error checking public access block for {bucket_name}: {str(e)}")
    
    return None


def check_bucket_acl(s3_client, bucket_name):
    """Check bucket ACL for public access"""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            # Check for public access via ACL
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return {
                        'bucket': bucket_name,
                        'severity': 'CRITICAL',
                        'issue': 'Bucket Has Public ACL',
                        'details': f'Bucket grants {permission} to {uri}'
                    }
    except Exception as e:
        logger.error(f"Error checking ACL for {bucket_name}: {str(e)}")
    
    return None


def check_bucket_policy(s3_client, bucket_name):
    """Check bucket policy for public access"""
    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(policy_response['Policy'])
        
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', '')
            
            # Check for public access via bucket policy
            if effect == 'Allow':
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    return {
                        'bucket': bucket_name,
                        'severity': 'CRITICAL',
                        'issue': 'Bucket Policy Allows Public Access',
                        'details': f'Bucket policy has statement allowing public access: {statement.get("Sid", "No SID")}'
                    }
    except s3_client.exceptions.NoSuchBucketPolicy:
        # No policy is fine
        pass
    except Exception as e:
        logger.error(f"Error checking policy for {bucket_name}: {str(e)}")
    
    return None


def check_encryption(s3_client, bucket_name):
    """Check if bucket has default encryption enabled"""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return None
    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        return {
            'bucket': bucket_name,
            'severity': 'MEDIUM',
            'issue': 'Encryption Not Enabled',
            'details': 'Bucket does not have default encryption enabled'
        }
    except Exception as e:
        logger.error(f"Error checking encryption for {bucket_name}: {str(e)}")
    
    return None


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
                'details': 'Bucket does not have versioning enabled for data protection'
            }
    except Exception as e:
        logger.error(f"Error checking versioning for {bucket_name}: {str(e)}")
    
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
                'details': 'Bucket does not have access logging enabled'
            }
    except Exception as e:
        logger.error(f"Error checking logging for {bucket_name}: {str(e)}")
    
    return None


def send_alert(sns_client, topic_arn, findings, total_buckets):
    """Send SNS notification with all findings"""
    try:
        # Group findings by severity
        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        high = [f for f in findings if f['severity'] == 'HIGH']
        medium = [f for f in findings if f['severity'] == 'MEDIUM']
        low = [f for f in findings if f['severity'] == 'LOW']
        
        # Build message
        subject = f"AWS S3 Security Audit - {len(findings)} Issue(s) Found"
        
        message = f"""S3 Security Audit Summary
==========================

Total Buckets Scanned: {total_buckets}
Total Issues Found: {len(findings)}

Severity Breakdown:
  - CRITICAL: {len(critical)}
  - HIGH: {len(high)}
  - MEDIUM: {len(medium)}
  - LOW: {len(low)}

"""
        
        # Add detailed findings
        message += "\nDETAILED FINDINGS:\n"
        message += "=" * 50 + "\n\n"
        
        # Sort by severity
        sorted_findings = critical + high + medium + low
        
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
        
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {str(e)}")