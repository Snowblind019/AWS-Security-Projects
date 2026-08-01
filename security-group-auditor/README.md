# Security Group Auditor

Scheduled Lambda that scans every EC2 security group for inbound rules open to the entire internet and emails a single findings digest via SNS.

## What it checks

Inbound rules sourced from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6), classified by what the rule actually exposes:

| Severity | Condition |
|----------|-----------|
| CRITICAL | All ports and all protocols open |
| CRITICAL | A high-risk port in range: SSH, Telnet, RDP, SMB, MySQL, PostgreSQL, MSSQL, Redis, Elasticsearch, MongoDB |
| HIGH | A wide port range, more than 100 ports |
| MEDIUM | A single port or narrow range |

## How it works

**IPv4 and IPv6 live in separate structures on the same rule.** A rule carries `IpRanges` and `Ipv6Ranges` independently, so a group can pass every IPv4 check while being wide open on `::/0`. I missed IPv6 entirely on the first version of this, which is exactly the kind of gap an auditor is supposed to catch.

**One digest, not one email per finding.** The first version published to SNS from inside the rule loop. A single group with an all-ports rule floods the mailbox and risks SNS throttling partway through a scan, which silently truncates the audit. Findings are now collected and sent as one message.

**Severity comes from what is exposed, not from the fact of exposure.** Port 22 open to the world is a different problem from port 8080 open to the world, and the alert says so rather than making the reader look up every port.

## Sample alert

```
Security Group Audit Summary
=============================

Groups Checked: 3
Total Issues:   3

Severity Breakdown:
  - CRITICAL: 2
  - HIGH:     0
  - MEDIUM:   1

DETAILED FINDINGS:
==================================================

[CRITICAL] Finding #1
  Group:       sg-0a3b4c5d6e7f8g9h (exposed)
  VPC:         vpc-0f1e2d3c4b5a6978
  Protocol:    tcp
  Ports:       22
  Source:      0.0.0.0/0 (entire internet, IPv4)
  Exposed:     SSH (22)
  Rule note:   None

[CRITICAL] Finding #2
  Group:       sg-0a3b4c5d6e7f8g9h (exposed)
  VPC:         vpc-0f1e2d3c4b5a6978
  Protocol:    All
  Ports:       All
  Source:      0.0.0.0/0 (entire internet, IPv4)
  Exposed:     All ports, all protocols
  Rule note:   None

[MEDIUM] Finding #3
  Group:       sg-0a3b4c5d6e7f8g9h (exposed)
  VPC:         vpc-0f1e2d3c4b5a6978
  Protocol:    tcp
  Ports:       8080
  Source:      ::/0 (entire internet, IPv6)
  Exposed:     Port open to the internet
  Rule note:   None
```

## Deployment

Prerequisites: AWS CLI and SAM CLI.

```bash
sam build
sam deploy --guided
```

You will be prompted for the alert email address and the schedule (default daily). Confirm the SNS subscription in your email after deployment.

The function needs `ec2:DescribeSecurityGroups` and publish on its own topic, nothing else. The resource is `*` because `Describe*` actions do not support resource-level permissions.

## Limitations

- Ingress only. Unrestricted egress is not flagged.
- Only exact `0.0.0.0/0` and `::/0` are matched. A rule sourced from `0.0.0.0/1` is nearly as broad and is not caught.
- Attachment is not checked, so an unused security group with a permissive rule is reported the same as one attached to a live instance. Adding this needs `ec2:DescribeNetworkInterfaces`.
- No allowlist, so a deliberately open port such as 443 on a public load balancer is reported on every run.
- Single region, the one the Lambda runs in.

## Project structure

```
.
├── lambda_function.py    # Audit logic
├── template.yaml         # SAM infrastructure template
└── README.md
```