/*
DESCRIPTION: EC2 Instance Start and Stop Audit Query

This query analyzes CloudTrail logs for a specified list of EC2 instance IDs.
It returns the most recent StopInstances and StartInstances events for each instance,
including who performed the action, when it happened, and the source IP address.

Before running:
- Replace the sample instance IDs in target_instances.
- Replace the same instance IDs in the requestparameters LIKE filters.
- Replace cloudtrail_log_full.events with your Athena CloudTrail database and table name.
*/

WITH target_instances AS (
    SELECT *
    FROM (
        VALUES ('i-12345qwerty'),  -- your instances here
               ('i-54321ytrewq')
    ) AS t(instance_id)
),
last_stop_events AS (
    SELECT regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})') as instance_id,
           eventtime as stop_time,
           useridentity.username as stop_username,
           useridentity.arn as stop_arn,
           sourceipaddress as stop_ip,
           ROW_NUMBER() OVER (
               PARTITION BY regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})')
               ORDER BY eventtime DESC
           ) as rn
    FROM cloudtrail_log_full.events
    WHERE eventname = 'StopInstances'
      AND eventsource = 'ec2.amazonaws.com'
      AND (
          requestparameters LIKE '%i-12345qwerty%'  -- your instances here
          OR requestparameters LIKE '%i-54321ytrewq%'
      )
),
last_start_events AS (
    SELECT regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})') as instance_id,
           eventtime as start_time,
           useridentity.username as start_username,
           useridentity.arn as start_arn,
           sourceipaddress as start_ip,
           ROW_NUMBER() OVER (
               PARTITION BY regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})')
               ORDER BY eventtime DESC
           ) as rn
    FROM cloudtrail_log_full.events  -- adjust the DB and table names
    WHERE eventname = 'StartInstances'
      AND eventsource = 'ec2.amazonaws.com'
      AND (
          requestparameters LIKE '%i-12345qwerty%'  -- your instances here
          OR requestparameters LIKE '%i-54321ytrewq%'
      )
),
final_results AS (
    SELECT t.instance_id,
           COALESCE(stop.stop_time, 'NO STOP EVENTS FOUND') as last_stopped_time,
           COALESCE(stop.stop_username, 'N/A') as last_stopped_by,
           COALESCE(stop.stop_arn, 'N/A') as last_stopped_by_arn,
           COALESCE(stop.stop_ip, 'N/A') as last_stopped_from_ip,
           COALESCE(start.start_time, 'NO START EVENTS FOUND') as last_started_time,
           COALESCE(start.start_username, 'N/A') as last_started_by,
           COALESCE(start.start_arn, 'N/A') as last_started_by_arn,
           COALESCE(start.start_ip, 'N/A') as last_started_from_ip,
           CASE
               WHEN stop.instance_id IS NULL AND start.instance_id IS NULL THEN 'NO DATA'
               WHEN stop.instance_id IS NULL THEN 'START DATA ONLY'
               WHEN start.instance_id IS NULL THEN 'STOP DATA ONLY'
               ELSE 'COMPLETE DATA'
           END as status
    FROM target_instances t
    LEFT JOIN (
        SELECT *
        FROM last_stop_events
        WHERE rn = 1
    ) stop ON t.instance_id = stop.instance_id
    LEFT JOIN (
        SELECT *
        FROM last_start_events
        WHERE rn = 1
    ) start ON t.instance_id = start.instance_id
)
SELECT instance_id,
       last_stopped_time,
       last_stopped_by,
       last_stopped_by_arn,
       last_stopped_from_ip,
       last_started_time,
       last_started_by,
       last_started_by_arn,
       last_started_from_ip,
       status
FROM final_results
ORDER BY CASE
             WHEN status = 'NO DATA' THEN 1 
             ELSE 0
         END,
         last_stopped_time DESC;
