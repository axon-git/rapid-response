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
      AND TARGET_PROCESS_NAME IN ('bash', 'dash', 'sh', 'tcsh', 'csh', 'zsh', 'ksh', 'fish', 'rc', 'ash', 'yash', 'elvish', 'mksh', 'loksh', 'xonsh')
      AND (TARGET_PROCESS_COMMANDLINE NOT ILIKE '%/tmp/-foomatic%' OR TARGET_PROCESS_COMMANDLINE NOT ILIKE '%-sDEVICE=ps2write%')
      AND EVENT_TIME > current_timestamp - interval '7d'
);
