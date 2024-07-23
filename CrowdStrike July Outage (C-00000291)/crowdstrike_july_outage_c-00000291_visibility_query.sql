WITH driver_deletion AS (
 -- find indication for deletion events of C-00000291 drivers
 SELECT DISTINCT AGENT_ID
   FROM INVESTIGATION.EDR_FILE_EVENTS
  WHERE TARGET_FILE_NAME ILIKE '%C-00000291%'
    AND TARGET_FILE_ACTION = 'delete'
    AND TARGET_FILE_EXTENSION = 'sys'
    AND EVENT_TIME BETWEEN '2024-07-16 00:00:00' and '2024-07-25 00:00:00'
)

 SELECT
  -- find machines affected by Crowdstrike update
     MIN(EVENT_TIME),
     MAX(EVENT_TIME),
     CROWDSTRIKE_RAW_EVENTS.AID,
     LAST_HOSTNAME,
     AIP,
     ARRAY_AGG(DISTINCT TARGET_FILE_NAME) AS DRIVER_FILES_INDICATION,
     CASE
        WHEN CROWDSTRIKE_RAW_EVENTS.AID IN (SELECT AGENT_ID FROM driver_deletion) THEN TRUE ELSE FALSE
        END AS DRIVER_DELETED
   FROM RAW.CROWDSTRIKE_RAW_EVENTS
  LEFT JOIN INVESTIGATION.EDR_AGENT_INFO AGENT_INFO ON AGENT_INFO.AID  = CROWDSTRIKE_RAW_EVENTS.AID
  WHERE EVENT_SIMPLE_NAME  IN('LFODownloadConfirmation')
    AND TARGET_FILE_NAME ILIKE '%C-00000291%'
    AND EVENT_PLATFORM = 'Win'
    AND EVENT_TIME BETWEEN '2024-07-17 00:00:00' and '2024-07-20 00:00:00'
  GROUP BY CROWDSTRIKE_RAW_EVENTS.AID,
           LAST_HOSTNAME,
           AIP