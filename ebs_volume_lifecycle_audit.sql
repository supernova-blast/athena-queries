/*
DESCRIPTION: EBS Volume Forensic Analysis Query

This query analyzes CloudTrail logs for a specified list of EBS volumes.
It shows when each volume was created, who created it, when it was attached or detached,
whether snapshots were created, and provides a basic deletion-safety assessment.
*/

WITH volume_list AS (
    SELECT volume_id FROM (
        VALUES 
            ('vol-0123456789abcdef0'),  -- replace with your volume IDs here
            ('vol-0abcdef1234567890'),
            ('vol-0fedcba9876543210')
    ) AS t(volume_id)
),
volume_events AS (
    SELECT 
        vl.volume_id,
        e.eventtime,
        e.eventname,
        e.sourceipaddress,
        e.useragent,

        e.useridentity.type AS user_type,
        e.useridentity.principalid AS principal_id,
        e.useridentity.arn AS user_arn,
        e.useridentity.username AS username,
        COALESCE(
            e.useridentity.username, 
            SPLIT_PART(e.useridentity.principalid, ':', 2),
            e.useridentity.principalid
        ) AS actual_user,

        CASE 
            WHEN e.useragent LIKE '%console%' THEN 'AWS Console'
            WHEN e.useragent LIKE '%cli%' THEN 'AWS CLI'
            WHEN e.useragent LIKE '%terraform%' THEN 'Terraform'
            WHEN e.useragent LIKE '%cloudformation%' THEN 'CloudFormation'
            WHEN e.useragent LIKE '%autoscaling%' THEN 'Auto Scaling'
            WHEN e.useragent LIKE '%ec2%' THEN 'EC2 Service'
            WHEN e.sourceipaddress = 'AWS Internal' THEN 'AWS Service'
            ELSE e.useragent
        END AS creation_method,

        JSON_EXTRACT_SCALAR(e.requestparameters, '$.size') AS size_gb,
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.volumeType') AS volume_type,
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.snapshotId') AS source_snapshot,
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.zone') AS az,
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.encrypted') AS encrypted,

        JSON_EXTRACT_SCALAR(e.requestparameters, '$.instanceId') AS instance_id,
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.device') AS device,
        JSON_EXTRACT_SCALAR(e.responseelements, '$.state') AS state,
        JSON_EXTRACT_SCALAR(e.responseelements, '$.volumeId') AS response_volume_id,

        e.awsregion,
        e.recipientaccountid AS account_id,
        e.errorcode,
        e.errormessage

    FROM volume_list vl
    LEFT JOIN cloudtrail_logs.events e ON (  -- replace with your table name here
        JSON_EXTRACT_SCALAR(e.requestparameters, '$.volumeId') = vl.volume_id
        OR JSON_EXTRACT_SCALAR(e.responseelements, '$.volumeId') = vl.volume_id
    )
    WHERE e.eventname IN (
        'CreateVolume',
        'AttachVolume',
        'DetachVolume',
        'DeleteVolume',
        'ModifyVolume',
        'CreateSnapshot',
        'CopySnapshot',
        'RunInstances'
    )
),
volume_summary AS (
    SELECT 
        volume_id,

        MIN(CASE WHEN eventname = 'CreateVolume' THEN eventtime END) AS created_time,
        MIN(CASE WHEN eventname = 'CreateVolume' THEN actual_user END) AS created_by,
        MIN(CASE WHEN eventname = 'CreateVolume' THEN creation_method END) AS created_method,
        MIN(CASE WHEN eventname = 'CreateVolume' THEN sourceipaddress END) AS created_from_ip,
        MIN(CASE WHEN eventname = 'CreateVolume' THEN size_gb END) AS volume_size,
        MIN(CASE WHEN eventname = 'CreateVolume' THEN volume_type END) AS volume_type,

        COUNT(CASE WHEN eventname = 'AttachVolume' THEN 1 END) AS attach_count,
        COUNT(CASE WHEN eventname = 'DetachVolume' THEN 1 END) AS detach_count,

        MAX(CASE WHEN eventname = 'AttachVolume' THEN eventtime END) AS last_attached_time,
        MAX(CASE WHEN eventname = 'AttachVolume' THEN actual_user END) AS last_attached_by,
        MAX(CASE WHEN eventname = 'AttachVolume' THEN instance_id END) AS last_attached_to_instance,
        MAX(CASE WHEN eventname = 'AttachVolume' THEN device END) AS last_attached_device,

        MAX(CASE WHEN eventname = 'DetachVolume' THEN eventtime END) AS last_detached_time,
        MAX(CASE WHEN eventname = 'DetachVolume' THEN actual_user END) AS last_detached_by,
        MAX(CASE WHEN eventname = 'DetachVolume' THEN instance_id END) AS last_detached_from_instance,

        COUNT(CASE WHEN eventname = 'CreateSnapshot' THEN 1 END) AS snapshot_count,
        MAX(CASE WHEN eventname = 'CreateSnapshot' THEN eventtime END) AS last_snapshot_time,

        MIN(eventtime) AS first_activity,
        MAX(eventtime) AS last_activity,
        COUNT(*) AS total_events

    FROM volume_events
    GROUP BY volume_id
)
SELECT 
    vs.volume_id,

    vs.created_time,
    vs.created_by,
    vs.created_method,
    vs.created_from_ip,

    CASE 
        WHEN vs.volume_size IS NOT NULL AND vs.volume_type IS NOT NULL THEN 
            CAST(vs.volume_size AS VARCHAR) || 'GB ' || vs.volume_type
        WHEN vs.volume_size IS NOT NULL THEN 
            CAST(vs.volume_size AS VARCHAR) || 'GB unknown'
        ELSE 'unknown size/type'
    END AS volume_spec,

    CASE 
        WHEN vs.attach_count = 0 THEN 'NEVER ATTACHED'
        WHEN vs.attach_count = vs.detach_count THEN 
            'FULLY DETACHED (' || CAST(vs.attach_count AS VARCHAR) || ' times)'
        WHEN vs.attach_count > vs.detach_count THEN 
            'STILL ATTACHED (' || CAST(vs.attach_count - vs.detach_count AS VARCHAR) || ' active)'
        ELSE 'UNKNOWN STATE'
    END AS usage_status,

    vs.last_attached_time,
    vs.last_attached_by,
    vs.last_attached_to_instance,
    vs.last_attached_device,
    vs.last_detached_time,
    vs.last_detached_by,
    vs.last_detached_from_instance,

    CASE 
        WHEN vs.last_detached_time IS NOT NULL THEN 
            DATE_DIFF('day', DATE_PARSE(vs.last_detached_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE)
        WHEN vs.last_attached_time IS NOT NULL THEN 
            DATE_DIFF('day', DATE_PARSE(vs.last_attached_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE)
        WHEN vs.created_time IS NOT NULL THEN 
            DATE_DIFF('day', DATE_PARSE(vs.created_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE)
        ELSE NULL
    END AS days_since_last_activity,

    CASE 
        WHEN vs.attach_count = 0 THEN 'SAFE - Never used'
        WHEN vs.last_detached_time IS NOT NULL
             AND DATE_DIFF('day', DATE_PARSE(vs.last_detached_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE) > 365
             THEN 'SAFE - Unused >1 year'
        WHEN vs.last_detached_time IS NOT NULL
             AND DATE_DIFF('day', DATE_PARSE(vs.last_detached_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE) > 90
             THEN 'SAFE - Unused >3 months'
        WHEN vs.snapshot_count > 0 THEN 'SAFE - Has snapshots'
        WHEN vs.created_time IS NOT NULL
             AND DATE_DIFF('day', DATE_PARSE(vs.created_time, '%Y-%m-%dT%H:%i:%sZ'), CURRENT_DATE) > 365
             AND vs.attach_count = 0
             THEN 'SAFE - Old and never used'
        ELSE 'INVESTIGATE'
    END AS deletion_safety,

    vs.snapshot_count,
    vs.total_events AS total_cloudtrail_events

FROM volume_summary vs
ORDER BY 
    CASE WHEN vs.created_time IS NULL THEN 1 ELSE 0 END,
    vs.created_time DESC NULLS LAST;
