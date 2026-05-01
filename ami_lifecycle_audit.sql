/*
DESCRIPTION: AMI Usage and Creation Audit Query

This query analyzes CloudTrail logs for a specified list of AMIs.
It shows when each AMI was last used to launch an EC2 instance, who launched it,
and when the AMI was created, including who created it and from which source instance.

Before running:
- Replace the sample AMI IDs in target_amis.
- Replace the sample regions if needed.
- Replace cloudtrail_logs.events with your Athena CloudTrail database and table name.
*/

WITH target_amis AS (
    SELECT *
    FROM (
        VALUES
            ('eu-west-1', 'ami-0123456789abcdef0'),  -- replace with your AMI IDs and regions
            ('eu-west-1', 'ami-0abcdef1234567890'),
            ('us-west-2', 'ami-0fedcba9876543210')
    ) AS t(region, ami_id)
),

last_run_events AS (
    SELECT
        awsregion AS region,
        regexp_extract(requestparameters, '"imageId":"(ami-[^"]+)"', 1) AS ami_id,
        regexp_extract(responseelements, '"instanceId":"(i-[^"]+)"', 1) AS launched_instance_id,
        eventtime AS last_used_time,
        useridentity.username AS last_used_by_username,
        useridentity.arn AS last_used_by_arn,
        sourceipaddress AS last_used_from_ip,
        ROW_NUMBER() OVER (
            PARTITION BY
                awsregion,
                regexp_extract(requestparameters, '"imageId":"(ami-[^"]+)"', 1)
            ORDER BY eventtime DESC
        ) AS rn
    FROM cloudtrail_logs.events  -- replace with your Athena CloudTrail table
    WHERE eventsource = 'ec2.amazonaws.com'
      AND eventname = 'RunInstances'
      AND awsregion IN ('eu-west-1', 'us-west-2')  -- replace with your regions
      AND (
          requestparameters LIKE '%ami-0123456789abcdef0%' OR
          requestparameters LIKE '%ami-0abcdef1234567890%' OR
          requestparameters LIKE '%ami-0fedcba9876543210%'
      )
),

create_image_events AS (
    SELECT
        awsregion AS region,
        regexp_extract(responseelements, '"imageId":"(ami-[^"]+)"', 1) AS ami_id,
        regexp_extract(requestparameters, '"name":"([^"]+)"', 1) AS created_ami_name,
        regexp_extract(requestparameters, '"instanceId":"(i-[^"]+)"', 1) AS source_instance_id,
        eventtime AS ami_created_time,
        useridentity.username AS ami_created_by_username,
        useridentity.arn AS ami_created_by_arn,
        sourceipaddress AS ami_created_from_ip,
        ROW_NUMBER() OVER (
            PARTITION BY
                awsregion,
                regexp_extract(responseelements, '"imageId":"(ami-[^"]+)"', 1)
            ORDER BY eventtime DESC
        ) AS rn
    FROM cloudtrail_logs.events  -- replace with your Athena CloudTrail table
    WHERE eventsource = 'ec2.amazonaws.com'
      AND eventname = 'CreateImage'
      AND awsregion IN ('eu-west-1', 'us-west-2')  -- replace with your regions
      AND (
          responseelements LIKE '%ami-0123456789abcdef0%' OR
          responseelements LIKE '%ami-0abcdef1234567890%' OR
          responseelements LIKE '%ami-0fedcba9876543210%'
      )
)

SELECT
    t.region,
    t.ami_id,

    COALESCE(c.ami_created_time, 'NO CREATEIMAGE EVENT FOUND') AS ami_created_time,
    COALESCE(c.created_ami_name, 'N/A') AS created_ami_name,
    COALESCE(c.source_instance_id, 'N/A') AS source_instance_id,
    COALESCE(c.ami_created_by_username, 'N/A') AS ami_created_by_username,
    COALESCE(c.ami_created_by_arn, 'N/A') AS ami_created_by_arn,
    COALESCE(c.ami_created_from_ip, 'N/A') AS ami_created_from_ip,

    COALESCE(r.last_used_time, 'NO RUNINSTANCES EVENT FOUND') AS last_used_time,
    COALESCE(r.launched_instance_id, 'N/A') AS last_launched_instance_id,
    COALESCE(r.last_used_by_username, 'N/A') AS last_used_by_username,
    COALESCE(r.last_used_by_arn, 'N/A') AS last_used_by_arn,
    COALESCE(r.last_used_from_ip, 'N/A') AS last_used_from_ip,

    CASE
        WHEN c.ami_id IS NULL AND r.ami_id IS NULL THEN 'NO CREATE OR RUN DATA'
        WHEN c.ami_id IS NULL THEN 'RUN DATA ONLY'
        WHEN r.ami_id IS NULL THEN 'CREATE DATA ONLY'
        ELSE 'CREATE AND RUN DATA'
    END AS status
FROM target_amis t
LEFT JOIN (
    SELECT *
    FROM create_image_events
    WHERE rn = 1
) c
    ON t.region = c.region
   AND t.ami_id = c.ami_id
LEFT JOIN (
    SELECT *
    FROM last_run_events
    WHERE rn = 1
) r
    ON t.region = r.region
   AND t.ami_id = r.ami_id
ORDER BY
    t.region,
    last_used_time DESC,
    t.ami_id;
