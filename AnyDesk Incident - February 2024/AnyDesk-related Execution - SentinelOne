---- Query C - AnyDesk Process Creation Events - SentinelOne
SELECT TIMESTAMP,
       EVENT_TYPE,
       AGENT_UUID,
       COMPUTER_NAME,
       OS_NAME,
       SRC_PROCESS_NAME,
       SRC_PROCESS_CMDLINE,
       SRC_PROCESS_IMAGE_PATH,
       SRC_PROCESS_IMAGE_SHA256,
       SRC_PROCESS_USER_NAME,
       RAW:src.process.publisher                                 AS SRC_PROCESS_PUBLISHER,
       RAW:src.process.signedStatus                              AS SRC_PROCESS_SIGNED_STATUS,
       TGT_PROCESS_NAME,
       TGT_PROCESS_CMDLINE,
       TGT_PROCESS_IMAGE_SHA256,
       RAW:"tgt.file.isSigned"                                   AS TGT_FILE_IS_SIGNED,
       RAW:"tgt.process.image.binaryIsExecutable"                AS TGT_PROCESS_IS_EXECUTABLE,
       RAW:"tgt.process.publisher"                               AS TGT_PROCESS_PUBLISHER,
       RAW:"tgt.process.signedStatus"                            AS TGT_PROCESS_SIGNED_STATUS,
       RAW
FROM RAW.SENTINELONE_RAW_EVENTS_V2
WHERE EVENT_TYPE = 'Process Creation'
AND (TGT_PROCESS_NAME ILIKE '%AnyDesk%' OR SRC_PROCESS_NAME ILIKE '%AnyDesk%')
AND TIMESTAMP BETWEEN '2023-12-15 00:00:01' and '2024-02-05 00:00:59'
