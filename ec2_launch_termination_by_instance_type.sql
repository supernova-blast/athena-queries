/*
This query identifies all EC2 RunInstances events for the specified instance types within the defined date range and shows who launched them and when.
It then joins any corresponding TerminateInstances events to indicate whether and by whom those instances were later terminated.
*/

WITH launches AS (
  SELECT
    regexp_extract(responseelements, '"instanceId":"(i-[^"]+)"', 1) AS instance_id,
    CASE
      WHEN requestparameters LIKE '%"instanceType":"c5a.8xlarge"%' THEN 'c5a.8xlarge'  -- use your instance types you need
      WHEN requestparameters LIKE '%"instanceType":"c6a.8xlarge"%' THEN 'c6a.8xlarge'
    END AS instance_type,
    useridentity.arn AS started_by,
    eventtime        AS start_time
  FROM cloudtrail_log.events  -- adjust DB and table names
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname   = 'RunInstances'
    AND (
      requestparameters LIKE '%"instanceType":"c5a.8xlarge"%'  -- use your instance types you need
      OR requestparameters LIKE '%"instanceType":"c6a.8xlarge"%'
    )
    AND eventtime >= '2025-11-17T00:00:00Z'  -- adjust time and date
    AND eventtime <  '2025-11-22T00:00:00Z'
),
terminations AS (
  SELECT
    regexp_extract(requestparameters, '"instanceId":"(i-[^"]+)"', 1) AS instance_id,
    useridentity.arn AS terminated_by,
    eventtime        AS terminate_time
  FROM cloudtrail_log.events
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname   = 'TerminateInstances'

    AND eventtime >= '2025-11-17T00:00:00Z'  -- adjust time and date
    AND eventtime <  '2025-11-22T00:00:00Z'
)
SELECT
  l.instance_id,
  l.instance_type,
  l.started_by,
  l.start_time,
  t.terminated_by,
  t.terminate_time
FROM launches l
LEFT JOIN terminations t
  ON l.instance_id = t.instance_id
ORDER BY l.start_time;
