/*
DESCRIPTION: Athena CloudTrail Database and Table Setup

This script creates an Athena database and external table for querying AWS CloudTrail logs stored in S3.
Before running it, configure an Athena query result location, preferably in a separate S3 prefix from the CloudTrail log files.

Before running:
- Create or choose an S3 location for Athena query results, for example:
  s3://athena-query-results-1234567890/
- Replace cloudtrail_log_full with your preferred Athena database name.
- Replace events with your preferred table name if needed.
- Replace s3://<s3-bucket-name-for-cloudtrail-log-full>/AWSLogs/<account-id>/ with your CloudTrail S3 log location.
- Run CREATE DATABASE and CREATE EXTERNAL TABLE separately, because Athena usually runs one statement at a time.
*/

CREATE DATABASE cloudtrail_log_full;  -- you can give it any name

CREATE EXTERNAL TABLE cloudtrail_log_full.events (  -- you can choose another name for the table
    eventversion STRING,
    useridentity STRUCT<
        type: STRING,
        principalid: STRING,
        arn: STRING,
        accountid: STRING,
        invokedby: STRING,
        accesskeyid: STRING,
        username: STRING,
        sessioncontext: STRUCT<
            attributes: STRUCT<
                mfaauthenticated: STRING,
                creationdate: STRING>,
            sessionissuer: STRUCT<
                type: STRING,
                principalid: STRING,
                arn: STRING,
                accountid: STRING,
                username: STRING>>>,
    eventtime STRING,
    eventsource STRING,
    eventname STRING,
    awsregion STRING,
    sourceipaddress STRING,
    useragent STRING,
    errorcode STRING,
    errormessage STRING,
    requestparameters STRING,
    responseelements STRING,
    additionaleventdata STRING,
    requestid STRING,
    eventid STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountid: STRING,
        type: STRING>>,
    eventtype STRING,
    apiversion STRING,
    readonly STRING,
    recipientaccountid STRING,
    serviceeventdetails STRING,
    sharedeventid STRING,
    vpcendpointid STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<s3-bucket-name-for-cloudtrail-log-full>/AWSLogs/<account-id>/'  -- enter the S3 location to which your CloudTrail writes
TBLPROPERTIES ('classification'='cloudtrail');
