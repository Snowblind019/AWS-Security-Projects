import boto3
import json
import logging
import os
import time
from datetime import datetime, timedelta

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Analyzes CloudTrail logs using Athena SQL queries for suspicious activities.
    
    Detects:
    - Root account usage
    - Failed authentication attempts
    - IAM policy changes
    - Security group modifications
    - S3 bucket policy changes
    - CloudTrail modifications
    """
    
    # Get configuration from environment variables
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    athena_database = os.environ.get('ATHENA_DATABASE')
    athena_table = os.environ.get('ATHENA_TABLE')
    athena_output_location = os.environ.get('ATHENA_OUTPUT_LOCATION')
    hours_to_analyze = int(os.environ.get('HOURS_TO_ANALYZE', '24'))
    
    required_vars = {
        'SNS_TOPIC_ARN': sns_topic_arn,
        'ATHENA_DATABASE': athena_database,
        'ATHENA_TABLE': athena_table,
        'ATHENA_OUTPUT_LOCATION': athena_output_location
    }
    
    missing_vars = [k for k, v in required_vars.items() if not v]
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Configuration error: Missing {", ".join(missing_vars)}')
        }
    
    try:
        athena_client = boto3.client('athena')
        sns_client = boto3.client('sns')
        
        logger.info(f"Starting CloudTrail analysis using Athena for last {hours_to_analyze} hours")
        
        findings = []
        
        # Run all security checks
        logger.info("Checking for root account usage...")
        root_findings = check_root_usage(
            athena_client, athena_database, athena_table, 
            athena_output_location, hours_to_analyze
        )
        findings.extend(root_findings)
        logger.info(f"Found {len(root_findings)} root account usage events")
        
        logger.info("Checking for failed authentication attempts...")
        auth_findings = check_failed_auth(
            athena_client, athena_database, athena_table,
            athena_output_location, hours_to_analyze
        )
        findings.extend(auth_findings)
        logger.info(f"Found {len(auth_findings)} failed auth attempts")
        
        logger.info("Checking for IAM policy changes...")
        iam_findings = check_iam_changes(
            athena_client, athena_database, athena_table,
            athena_output_location, hours_to_analyze
        )
        findings.extend(iam_findings)
        logger.info(f"Found {len(iam_findings)} IAM policy changes")
        
        logger.info("Checking for security group modifications...")
        sg_findings = check_security_group_changes(
            athena_client, athena_database, athena_table,
            athena_output_location, hours_to_analyze
        )
        findings.extend(sg_findings)
        logger.info(f"Found {len(sg_findings)} security group modifications")
        
        logger.info("Checking for S3 bucket policy changes...")
        s3_findings = check_s3_policy_changes(
            athena_client, athena_database, athena_table,
            athena_output_location, hours_to_analyze
        )
        findings.extend(s3_findings)
        logger.info(f"Found {len(s3_findings)} S3 policy changes")
        
        logger.info("Checking for CloudTrail modifications...")
        ct_findings = check_cloudtrail_changes(
            athena_client, athena_database, athena_table,
            athena_output_location, hours_to_analyze
        )
        findings.extend(ct_findings)
        logger.info(f"Found {len(ct_findings)} CloudTrail modifications")
        
        logger.info(f"Analysis complete: {len(findings)} total suspicious activities found")
        
        # Send alert if there are findings
        if findings:
            send_alert(sns_client, sns_topic_arn, findings, hours_to_analyze)
            logger.warning(f"Sent alert for {len(findings)} suspicious activity(ies)")
        else:
            logger.info("No suspicious activities detected")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'CloudTrail analysis complete',
                'findings_count': len(findings),
                'root_usage': len(root_findings),
                'failed_auth': len(auth_findings),
                'iam_changes': len(iam_findings),
                'sg_changes': len(sg_findings),
                's3_changes': len(s3_findings),
                'cloudtrail_changes': len(ct_findings)
            })
        }
    
    except Exception as e:
        logger.error(f"Error during CloudTrail analysis: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }


def execute_athena_query(athena_client, query, database, output_location):
    """
    Execute an Athena query and wait for results.
    Returns a list of dictionaries representing the query results.
    """
    try:
        # Start query execution
        response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location}
        )
        
        query_execution_id = response['QueryExecutionId']
        logger.debug(f"Started query execution: {query_execution_id}")
        
        # Wait for query to complete (max 60 seconds)
        max_attempts = 30
        attempt = 0
        
        while attempt < max_attempts:
            query_status = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            
            status = query_status['QueryExecution']['Status']['State']
            
            if status == 'SUCCEEDED':
                logger.debug(f"Query {query_execution_id} succeeded")
                break
            elif status in ['FAILED', 'CANCELLED']:
                reason = query_status['QueryExecution']['Status'].get(
                    'StateChangeReason', 'Unknown error'
                )
                logger.error(f"Query {query_execution_id} {status}: {reason}")
                return []
            
            time.sleep(2)
            attempt += 1
        
        if attempt >= max_attempts:
            logger.error(f"Query {query_execution_id} timed out after {max_attempts * 2} seconds")
            return []
        
        # Get query results
        result_paginator = athena_client.get_paginator('get_query_results')
        results = []
        
        for page in result_paginator.paginate(QueryExecutionId=query_execution_id):
            rows = page['ResultSet']['Rows']
            
            # First page contains headers
            if not results:
                if len(rows) <= 1:
                    # Only header row, no data
                    return []
                headers = [col['VarCharValue'] for col in rows[0]['Data']]
                rows = rows[1:]  # Skip header
            
            # Parse data rows
            for row in rows:
                row_data = {}
                for i, col in enumerate(row['Data']):
                    row_data[headers[i]] = col.get('VarCharValue', '')
                results.append(row_data)
        
        logger.debug(f"Query returned {len(results)} rows")
        return results
    
    except Exception as e:
        logger.error(f"Error executing Athena query: {str(e)}")
        return []


def check_root_usage(athena_client, database, table, output_location, hours):
    """Check for root account usage"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        sourceipaddress,
        useragent,
        awsregion
    FROM {database}.{table}
    WHERE useridentity.type = 'Root'
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        findings.append({
            'severity': 'CRITICAL',
            'type': 'Root Account Usage',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': 'Root Account',
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'details': f"Root account used for: {result.get('eventname', 'Unknown')}"
        })
    
    return findings


def check_failed_auth(athena_client, database, table, output_location, hours):
    """Check for failed authentication attempts"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        useridentity.arn as user_arn,
        sourceipaddress,
        errorcode,
        errormessage,
        awsregion
    FROM {database}.{table}
    WHERE errorcode IN ('UnauthorizedOperation', 'AccessDenied', 'AuthFailure')
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        findings.append({
            'severity': 'HIGH',
            'type': 'Failed Authentication/Authorization',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': result.get('user_arn', 'Unknown'),
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'error': result.get('errorcode', 'Unknown'),
            'details': f"Failed: {result.get('eventname', 'Unknown')} - {result.get('errormessage', 'No message')}"
        })
    
    return findings


def check_iam_changes(athena_client, database, table, output_location, hours):
    """Check for IAM policy modifications"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        useridentity.arn as user_arn,
        sourceipaddress,
        awsregion
    FROM {database}.{table}
    WHERE eventname IN (
        'PutUserPolicy', 'PutGroupPolicy', 'PutRolePolicy',
        'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion',
        'DeletePolicyVersion', 'AttachUserPolicy', 'AttachGroupPolicy',
        'AttachRolePolicy', 'DetachUserPolicy', 'DetachGroupPolicy',
        'DetachRolePolicy'
    )
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        findings.append({
            'severity': 'HIGH',
            'type': 'IAM Policy Modification',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': result.get('user_arn', 'Unknown'),
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'details': f"IAM policy modified: {result.get('eventname', 'Unknown')}"
        })
    
    return findings


def check_security_group_changes(athena_client, database, table, output_location, hours):
    """Check for security group modifications"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        useridentity.arn as user_arn,
        sourceipaddress,
        awsregion
    FROM {database}.{table}
    WHERE eventname IN (
        'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
        'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
        'CreateSecurityGroup', 'DeleteSecurityGroup'
    )
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        findings.append({
            'severity': 'MEDIUM',
            'type': 'Security Group Modification',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': result.get('user_arn', 'Unknown'),
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'details': f"Security group modified: {result.get('eventname', 'Unknown')}"
        })
    
    return findings


def check_s3_policy_changes(athena_client, database, table, output_location, hours):
    """Check for S3 bucket policy changes"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        useridentity.arn as user_arn,
        sourceipaddress,
        requestparameters,
        awsregion
    FROM {database}.{table}
    WHERE eventname IN (
        'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl',
        'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock'
    )
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        # Try to extract bucket name from request parameters
        bucket_name = 'Unknown'
        try:
            req_params = result.get('requestparameters', '')
            if req_params:
                params_dict = json.loads(req_params)
                bucket_name = params_dict.get('bucketName', 'Unknown')
        except:
            pass
        
        findings.append({
            'severity': 'MEDIUM',
            'type': 'S3 Bucket Policy Modification',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': result.get('user_arn', 'Unknown'),
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'details': f"S3 bucket policy modified on {bucket_name}: {result.get('eventname', 'Unknown')}"
        })
    
    return findings


def check_cloudtrail_changes(athena_client, database, table, output_location, hours):
    """Check for CloudTrail modifications"""
    
    query = f"""
    SELECT 
        eventtime,
        eventname,
        useridentity.arn as user_arn,
        sourceipaddress,
        awsregion
    FROM {database}.{table}
    WHERE eventname IN (
        'StopLogging', 'DeleteTrail', 'UpdateTrail',
        'PutEventSelectors'
    )
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '{hours}' hour
    ORDER BY eventtime DESC
    LIMIT 100
    """
    
    results = execute_athena_query(athena_client, query, database, output_location)
    
    findings = []
    for result in results:
        findings.append({
            'severity': 'CRITICAL',
            'type': 'CloudTrail Modification',
            'event_name': result.get('eventname', 'Unknown'),
            'event_time': result.get('eventtime', 'Unknown'),
            'user': result.get('user_arn', 'Unknown'),
            'source_ip': result.get('sourceipaddress', 'Unknown'),
            'region': result.get('awsregion', 'Unknown'),
            'details': f"CloudTrail logging modified: {result.get('eventname', 'Unknown')}"
        })
    
    return findings


def send_alert(sns_client, topic_arn, findings, hours):
    """Send SNS notification with all findings"""
    try:
        # Group findings by severity
        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        high = [f for f in findings if f['severity'] == 'HIGH']
        medium = [f for f in findings if f['severity'] == 'MEDIUM']
        low = [f for f in findings if f['severity'] == 'LOW']
        
        # Build message
        subject = f"AWS CloudTrail Alert - {len(findings)} Suspicious Activity(ies) Detected"
        
        message = f"""CloudTrail Log Analysis Summary
================================

Time Range Analyzed: Last {hours} hours
Suspicious Activities Found: {len(findings)}

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
            message += f"  Type: {finding['type']}\n"
            message += f"  Event: {finding['event_name']}\n"
            message += f"  Time: {finding['event_time']}\n"
            message += f"  User: {finding['user']}\n"
            message += f"  Source IP: {finding['source_ip']}\n"
            message += f"  Region: {finding['region']}\n"
            if 'error' in finding:
                message += f"  Error: {finding['error']}\n"
            message += f"  Details: {finding['details']}\n"
            message += "\n"
        
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info(f"SNS alert sent to {topic_arn}")
        
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {str(e)}")
