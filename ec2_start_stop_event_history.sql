/*
DESCRIPTION: EC2 Instance Start and Stop History Query

This query analyzes CloudTrail logs for a specified list of EC2 instance IDs.
It returns every matching StartInstances and StopInstances event, including when each action happened,
which action was performed, who performed it, and the source IP address.

Before running:
- Replace the sample instance IDs in target_instances.
- Replace the same instance IDs in the requestparameters LIKE filters.
- Replace cloudtrail_logs.events with your Athena CloudTrail database and table name.
*/

WITH target_instances AS (
  SELECT *
  FROM (
    VALUES ('i-qwerty12345'),  -- your instances here
           ('i-zxcvbn12345'),
           ('i-asdfgh12345')
  ) AS t(instance_id)
),
events AS (
  SELECT
    regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})') AS instance_id,
    eventtime,
    eventname,
    useridentity.username AS username,
    useridentity.arn AS arn,
    sourceipaddress
  FROM cloudtrail_logs.events  -- adjust the names of the DB and table
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname IN ('StartInstances', 'StopInstances')
    AND (
      requestparameters LIKE '%i-qwerty12345%' OR  -- your instances here
      requestparameters LIKE '%i-zxcvbn12345%' OR
      requestparameters LIKE '%i-asdfgh12345%'
    )
)
SELECT
  t.instance_id,
  e.eventtime,
  e.eventname,
  e.username,
  e.arn,
  e.sourceipaddress
FROM target_instances t
JOIN events e
  ON t.instance_id = e.instance_id
ORDER BY e.eventtime DESC, t.instance_id;
