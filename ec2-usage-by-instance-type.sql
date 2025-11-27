-- Find all launches of the specified instance types

WITH launches AS (
  SELECT
    -- Extract EC2 instance ID from the RunInstances response payload
    regexp_extract(responseelements, '"instanceId":"(i-[^"]+)"', 1) AS instance_id,

    -- Determine which of the two instance types was launched
    CASE
      WHEN requestparameters LIKE '%"instanceType":"c5a.8xlarge"%' THEN 'c5a.8xlarge'
      WHEN requestparameters LIKE '%"instanceType":"c6a.8xlarge"%' THEN 'c6a.8xlarge'
    END AS instance_type,
    useridentity.arn AS started_by,
    eventtime        AS start_time
  FROM cloudtrail_log.events  -- IMPORTANT: Adjust database.table name if yours differs
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname   = 'RunInstances'

    -- FILTER: adjust these if you add more instance types
    AND (
      requestparameters LIKE '%"instanceType":"c5a.8xlarge"%'
      OR requestparameters LIKE '%"instanceType":"c6a.8xlarge"%'
    )

    -- DATE RANGE: adjust here
    AND eventtime >= '2025-11-17T00:00:00Z'
    AND eventtime <  '2025-11-22T00:00:00Z'
),

-- Find termination events for the same date range
terminations AS (
  SELECT
    -- Extract instance ID from TerminateInstances request
    regexp_extract(requestparameters, '"instanceId":"(i-[^"]+)"', 1) AS instance_id,
    useridentity.arn AS terminated_by,
    eventtime        AS terminate_time
  FROM cloudtrail_log.events
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname   = 'TerminateInstances'

    -- Same date range as above – adjust here if needed
    AND eventtime >= '2025-11-17T00:00:00Z'
    AND eventtime <  '2025-11-22T00:00:00Z'
)

-- Join launches and terminations together
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
