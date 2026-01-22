import boto3
import logging
import os

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Scans all EC2 security groups for overly permissive inbound rules.
    Sends SNS alerts when security groups allow unrestricted access (0.0.0.0/0).
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
        ec2 = boto3.resource('ec2')
        sns_client = boto3.client('sns')
        
        security_groups = ec2.security_groups.all()
        
        findings_count = 0
        
        for sg in security_groups:
            logger.info(f"Checking security group '{sg.id}' ({sg.group_name})")
            
            # Check inbound rules for overly permissive access
            for rule in sg.ip_permissions:
                # Check IPv4 ranges
                for ip_range in rule.get('IpRanges', []):
                    # Flag any rule allowing unrestricted internet access (0.0.0.0/0)
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        protocol = rule.get('IpProtocol', 'All')
                        
                        message = (
                            f"WARNING: Security Group with Unrestricted Access\n\n"
                            f"Security Group ID: {sg.id}\n"
                            f"Security Group Name: {sg.group_name}\n"
                            f"Protocol: {protocol}\n"
                            f"Port Range: {from_port} - {to_port}\n"
                            f"Source: 0.0.0.0/0 (entire internet)\n"
                            f"Description: {ip_range.get('Description', 'None')}\n"
                        )
                        
                        logger.warning(message)
                        sns_client.publish(
                            TopicArn=sns_topic_arn,
                            Subject="AWS Security Alert: Unrestricted Security Group Rule",
                            Message=message
                        )
                        findings_count += 1
                
                # Check IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    if ipv6_range['CidrIpv6'] == '::/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        protocol = rule.get('IpProtocol', 'All')
                        
                        message = (
                            f"WARNING: Security Group with Unrestricted IPv6 Access\n\n"
                            f"Security Group ID: {sg.id}\n"
                            f"Security Group Name: {sg.group_name}\n"
                            f"Protocol: {protocol}\n"
                            f"Port Range: {from_port} - {to_port}\n"
                            f"Source: ::/0 (entire internet - IPv6)\n"
                            f"Description: {ipv6_range.get('Description', 'None')}\n"
                        )
                        
                        logger.warning(message)
                        sns_client.publish(
                            TopicArn=sns_topic_arn,
                            Subject="AWS Security Alert: Unrestricted Security Group Rule (IPv6)",
                            Message=message
                        )
                        findings_count += 1
        
        logger.info(f"Security audit complete. Found {findings_count} issue(s).")
        
        return {
            'statusCode': 200,
            'body': f'Security audit complete. Found {findings_count} overly permissive rule(s).'
        }
    
    except Exception as e:
        logger.error(f"Error during security audit: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'Error: {str(e)}'
        }
