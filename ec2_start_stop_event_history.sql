-- this query finds who and when started the given instances and also finds how and when the instances were stopped

WITH target_instances AS (
	SELECT *
	FROM (
			VALUES ('i-qwerty12345'),  -- your instances here
				('i-zxcvbn12345'),
				('i-asdfgh12345'),
		) AS t(instance_id)
),
last_stop_events AS (
	SELECT regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})') as instance_id,
		eventtime,
		useridentity.username,
		useridentity.arn,
		sourceipaddress,
		ROW_NUMBER() OVER (
			PARTITION BY regexp_extract(requestparameters, '(i-[a-f0-9]{8,17})')
			ORDER BY eventtime DESC
		) as rn
	FROM cloudtrail_logs.events  -- adjust the DB and table names if needed
	WHERE eventname = 'StopInstances'
		AND eventsource = 'ec2.amazonaws.com'
		AND (
			requestparameters LIKE '%i-qwerty12345%'  -- same instances here
			OR requestparameters LIKE '%i-zxcvbn12345%'
			OR requestparameters LIKE '%i-asdfgh12345%'
		)
),
final_results AS (
	SELECT t.instance_id,
		COALESCE(s.eventtime, 'NO STOP EVENTS FOUND') as last_stopped_time,
		COALESCE(s.username, 'N/A') as last_stopped_by,
		COALESCE(s.arn, 'N/A') as last_stopped_by_arn,
		COALESCE(s.sourceipaddress, 'N/A') as last_stopped_from_ip,
		CASE
			WHEN s.instance_id IS NULL THEN 'NO DATA' ELSE 'HAS DATA'
		END as status
	FROM target_instances t
		LEFT JOIN (
			SELECT *
			FROM last_stop_events
			WHERE rn = 1
		) s ON t.instance_id = s.instance_id
)
SELECT instance_id,
	last_stopped_time,
	last_stopped_by,
	last_stopped_by_arn,
	last_stopped_from_ip,
	status
FROM final_results
ORDER BY CASE
		WHEN status = 'NO DATA' THEN 1 ELSE 0
	END,
	last_stopped_time DESC;
