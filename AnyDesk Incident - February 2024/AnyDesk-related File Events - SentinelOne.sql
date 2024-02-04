---- Query D -  AnyDesk File Events -- SentinelOne
SELECT TIMESTAMP,
       EVENT_TYPE,
       AGENT_UUID                       AS AGENT_ID,
       COMPUTER_NAME,
       OS_NAME,
       SRC_PROCESS_NAME,
       RAW:"src.process.publisher"      AS SRC_PROCESS_PUBLISHER,
       RAW:"src.process.signedStatus"   AS SRC_PROCESS_SIGNED_STATUS,
       RAW:"src.process.verifiedStatus" AS SRC_PROCESS_VERIFIED_STATUS,
       SRC_PROCESS_CMDLINE,
       SRC_PROCESS_IMAGE_PATH,
       SRC_PROCESS_IMAGE_SHA256,
       SRC_PROCESS_USER_NAME,
       TGT_FILE_PATH,
       TGT_FILE_SHA256
FROM RAW.SENTINELONE_RAW_EVENTS_V2
WHERE EVENT_TYPE IN ('File Modification', 'File Deletion', 'File Rename', 'File Creation')
AND (TGT_FILE_PATH ILIKE '%ANYDESK%' OR SRC_PROCESS_NAME ILIKE '%ANYDESK%')
AND TIMESTAMP BETWEEN '2023-12-15 00:00:01' and '2024-02-05 00:00:59'
