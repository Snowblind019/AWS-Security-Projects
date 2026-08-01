import boto3
import logging
import os
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Ports that are especially dangerous when exposed to the whole internet
HIGH_RISK_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    445: 'SMB',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    6379: 'Redis',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
}


def lambda_handler(event, context):
    """
    Scans all EC2 security groups for overly permissive inbound rules and
    sends a single SNS digest of everything found.
    """

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

        findings = []
        groups_checked = 0

        for sg in ec2.security_groups.all():
            groups_checked += 1
            logger.info(f"Checking security group '{sg.id}' ({sg.group_name})")
            findings.extend(check_security_group(sg))

        logger.info(
            f"Audit complete. Checked {groups_checked} group(s), "
            f"found {len(findings)} issue(s)."
        )

        # One digest, not one email per finding. A single group with an
        # all-ports rule would otherwise flood the mailbox and risk SNS
        # throttling mid-scan.
        if findings:
            send_alert(sns_client, sns_topic_arn, findings, groups_checked)

        return {
            'statusCode': 200,
            'body': (
                f'Security audit complete. Checked {groups_checked} group(s), '
                f'found {len(findings)} overly permissive rule(s).'
            )
        }

    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        logger.error(f"Error during security audit: {code}")
        return {'statusCode': 500, 'body': f'Error: {code}'}
    except Exception as e:
        logger.error(f"Error during security audit: {str(e)}")
        return {'statusCode': 500, 'body': f'Error: {str(e)}'}


def check_security_group(sg):
    """Return every unrestricted inbound rule on this security group."""
    findings = []

    for rule in sg.ip_permissions:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        protocol = rule.get('IpProtocol', '-1')

        # IPv4 and IPv6 ranges live in separate structures on the same rule.
        # A group can pass every IPv4 check and still be wide open on ::/0.
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                findings.append(build_finding(
                    sg, protocol, from_port, to_port,
                    '0.0.0.0/0', 'IPv4', ip_range.get('Description')
                ))

        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                findings.append(build_finding(
                    sg, protocol, from_port, to_port,
                    '::/0', 'IPv6', ipv6_range.get('Description')
                ))

    return findings


def build_finding(sg, protocol, from_port, to_port, source, ip_version, description):
    """Assemble one finding, with severity based on what is exposed."""
    severity, exposed = classify(protocol, from_port, to_port)

    if protocol == '-1':
        port_display = 'All'
    elif from_port == to_port:
        port_display = str(from_port)
    else:
        port_display = f'{from_port} - {to_port}'

    return {
        'severity': severity,
        'group_id': sg.id,
        'group_name': sg.group_name,
        'vpc_id': sg.vpc_id,
        'protocol': 'All' if protocol == '-1' else protocol,
        'ports': port_display,
        'source': source,
        'ip_version': ip_version,
        'exposed': exposed,
        'description': description or 'None',
    }


def classify(protocol, from_port, to_port):
    """
    Decide severity for an unrestricted rule.

    All ports open is worse than one port open, and a well-known
    administrative or database port is worse than an arbitrary one.
    """
    if protocol == '-1' or from_port is None:
        return 'CRITICAL', 'All ports, all protocols'

    hits = [
        f'{name} ({port})'
        for port, name in HIGH_RISK_PORTS.items()
        if from_port <= port <= to_port
    ]

    if hits:
        return 'CRITICAL', ', '.join(hits)

    if to_port - from_port > 100:
        return 'HIGH', f'Wide port range ({to_port - from_port + 1} ports)'

    return 'MEDIUM', 'Port open to the internet'


def send_alert(sns_client, topic_arn, findings, groups_checked):
    """Send one SNS digest with all findings, grouped by severity."""
    try:
        by_severity = {
            level: [f for f in findings if f['severity'] == level]
            for level in ('CRITICAL', 'HIGH', 'MEDIUM')
        }

        subject = f"AWS Security Group Audit - {len(findings)} Issue(s) Found"

        message = f"""Security Group Audit Summary
=============================

Groups Checked: {groups_checked}
Total Issues:   {len(findings)}

Severity Breakdown:
  - CRITICAL: {len(by_severity['CRITICAL'])}
  - HIGH:     {len(by_severity['HIGH'])}
  - MEDIUM:   {len(by_severity['MEDIUM'])}

DETAILED FINDINGS:
"""
        message += "=" * 50 + "\n\n"

        ordered = by_severity['CRITICAL'] + by_severity['HIGH'] + by_severity['MEDIUM']

        for i, f in enumerate(ordered, 1):
            message += f"[{f['severity']}] Finding #{i}\n"
            message += f"  Group:       {f['group_id']} ({f['group_name']})\n"
            message += f"  VPC:         {f['vpc_id']}\n"
            message += f"  Protocol:    {f['protocol']}\n"
            message += f"  Ports:       {f['ports']}\n"
            message += f"  Source:      {f['source']} (entire internet, {f['ip_version']})\n"
            message += f"  Exposed:     {f['exposed']}\n"
            message += f"  Rule note:   {f['description']}\n\n"

        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info(f"SNS digest sent to {topic_arn}")

    except ClientError as e:
        logger.error(
            f"Failed to send SNS alert: {e.response.get('Error', {}).get('Code', '')}"
        )