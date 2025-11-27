-- first, create an S3 bucket in which the query results will be stored; e.g.: s3://athena-query-results-1234567890/

-- then run in Athena (run these 2 CREATE commands separately, Athena does no allow to run serveral queries in one go):
CREATE DATABASE cloudtrail_log;  -- you can give it any name

-- then create table named 'events' (or choose another name for the table)
CREATE EXTERNAL TABLE cloudtrail_log.events (
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
LOCATION 's3://<s3-bucket-name-for-cloudtrail-log>/AWSLogs/<account-id>/'  -- enter the S3 location to which your CloudTrail writes
TBLPROPERTIES ('classification'='cloudtrail');

/*
Note: you can use the same S3 bucket where CloudTrail writes logs as the query result location for Athena, 
but it's not recommended as a best practice. However, if using the same bucket, create separate prefixes:
CloudTrail logs: s3://<s3-bucket-name-for-cloudtrail-log>/AWSLogs/
Athena results: s3://<s3-bucket-name-for-cloudtrail-log>/AthenaResults/
*/
