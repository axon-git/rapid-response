SELECT --- Details about relevant host
       AID,
       LAST_HOSTNAME,
       LAST_EXTERNAL_IP_ADDRESS,
       LAST_INTERNAL_IP_ADDRESS,
       OS_TYPE,
       LAST_OS_VERSION,
       LAST_OS_BUILD,
       --- Additional Information
       SPECIFIC_SOURCE_TYPE,
       FIRST_SEEN,
       LAST_SEEN,
       CLOUD_PROVIDER,
       LAST_CLOUD_PROVIDER_ACCOUNT_ID,
       LAST_CLOUD_PROVIDER_INSTANCE_ID
FROM INVESTIGATION.EDR_AGENT_INFO
WHERE AID IN (
    SELECT DISTINCT AGENT_ID                             AS AGENT_ID
    FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
    WHERE DEVICE_PLATFORM IN ('LINUX', 'MAC')
      AND  (PARENT_PROCESS_NAME ILIKE '%cups%' OR PARENT_PROCESS_NAME ILIKE '%foomatic-rip%')
      AND EVENT_TIME > current_timestamp - interval '7d'
);
