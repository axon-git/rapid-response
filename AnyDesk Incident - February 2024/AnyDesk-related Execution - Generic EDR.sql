--- Query A - Executions of AnyDesk Processes - By Target Process Name 
SELECT EVENT_TIME,
       AGENT_ID                                 AS AGENT_ID,
       AGENT_EXTERNAL_IP                        AS AGENT_EXTERNAL_IP,
       DEVICE_PLATFORM                          AS DEVICE_PLATFORM,
       INITIATING_PROCESS_NAME                  AS INITIATING_PROCESS_NAME,
       INITIATING_PROCESS_UID                   AS INITIATING_PROCESS_UID,
       TARGET_PROCESS_NAME                      AS TARGET_PROCESS_NAME,
       TARGET_PROCESS_PATH                      AS TARGET_PROCESS_PATH,
       TARGET_PROCESS_COMMANDLINE               AS TARGET_PROCESS_COMMANDLINE,
       TARGET_PROCESS_HASH_SHA256               AS TARGET_PROCESS_HASH_SHA256
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE TARGET_PROCESS_NAME ILIKE '%ANYDESK%'
--- Adjust the timeframe according to selection.
AND EVENT_TIME BETWEEN '2023-12-15 00:00:01' and '2024-02-05 00:00:59'
