# CloudTrail Log Analyzer

Scheduled Lambda that queries CloudTrail logs with Athena SQL for suspicious activity and emails a findings digest via SNS.

## What it checks

Six queries over the last 24 hours (configurable):

| Severity | Check |
|----------|-------|
| CRITICAL | Root account usage |
| CRITICAL | CloudTrail modifications, someone disabling or altering logging |
| HIGH | Failed authentication and authorization (`UnauthorizedOperation`, `AccessDenied`, `AuthFailure`) |
| HIGH | IAM policy changes |
| MEDIUM | Security group modifications |
| MEDIUM | S3 bucket policy changes |

## How it works

**Query the logs where they are.** CloudTrail writes JSON to S3. Athena reads it in place through a Glue table, so there is nothing to download, parse, or store. The alternative, pulling objects and parsing them in the Lambda, is slower and more expensive by a wide margin.

**Partition projection, and actually using it.** The Glue table projects the `eventday` partition from the CloudTrail prefix layout, so no partitions have to be registered or repaired. The catch, and the mistake I made first: projection does nothing unless the query filters on the partition column. My original queries filtered only on `eventtime`, which is an ordinary column, so Athena had no way to prune and every query scanned the entire log history before discarding all but 24 hours of it. Six queries, six full scans, daily. Every query now leads with the partition predicate:

```sql
WHERE eventday >= '2026/07/30'
  AND useridentity.type = 'Root'
  AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '24' hour
```

The partition floor is computed with a day of slack so events near a UTC midnight boundary are not missed.

**Athena is asynchronous.** A query is submitted, then polled for state, with explicit handling for FAILED, CANCELLED, and timeout. This is a different shape from the synchronous boto3 calls in the other two projects: there is no call that just returns results.

**Nested fields need dot notation.** CloudTrail records `useridentity` as a struct, so the root check reads `useridentity.type` rather than a top-level column. Working out the struct definition for the Glue table was the slowest part of this project.

## Sample query

Root account detection:

```sql
SELECT eventtime, eventname, sourceipaddress, useragent, awsregion
FROM cloudtrail_logs.cloudtrail_table
WHERE eventday >= '2026/07/30'
    AND useridentity.type = 'Root'
    AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '24' hour
ORDER BY eventtime DESC
LIMIT 100
```

- `eventday >= ...` prunes partitions. Without it Athena scans everything regardless of the time filter below.
- `from_iso8601_timestamp(eventtime)` narrows within the pruned partitions to the exact window.
- `useridentity.type` uses dot notation because CloudTrail records it as a nested struct.

## Deployment

Prerequisites: AWS CLI, SAM CLI, and CloudTrail already enabled with logs delivering to S3.

```bash
sam build
sam deploy --guided
```

You will be prompted for the alert email, the CloudTrail log bucket, an Athena results bucket name (created by the stack), the schedule, and the lookback window in hours. Confirm the SNS subscription after deployment.

The stack creates the Glue database and table, the Athena results bucket (encrypted, public access blocked, with a 30-day lifecycle rule on query output), the SNS topic, and the function. Athena permissions are scoped to the primary workgroup.

## Limitations

- Single region and single account. The Glue table location is built from one region prefix, so an organization trail spanning regions needs the location template and projection widened.
- Each query caps at 100 rows, so a noisy day is truncated rather than paginated.
- Detections are event-name matches, not behavioural. Volume, timing, and correlation between events are not considered, so one finding is not the same as one incident.
- No suppression list, so expected activity such as a scheduled automation role changing security groups alerts every day.
- The lookback window and the schedule are set independently. Running more often than the window means duplicate findings, running less often means gaps.

## Project structure

```
.
├── lambda_function.py    # Query definitions, Athena polling, alerting
├── template.yaml         # SAM template: Glue database and table, Athena bucket, SNS, function
└── README.md
```

## Notes

I did not know SQL when I started this. The queries here were written a function at a time as I needed them, and I went back through SQL fundamentals afterwards to fill in what I had skipped. The partition mistake above is the clearest example of what that gap cost: the SQL was valid and returned correct results the whole time, and was quietly expensive for reasons that have nothing to do with the syntax.