-- This query detects commandlines which indicate for modification of the registry key \software\policies\microsoft\office\16.0\excel\security PythonFunctionWarnings to 0. This will allow Python code to be executed without any warning/permission by the user. 

SELECT *
  FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
 WHERE TARGET_PROCESS_COMMANDLINE ILIKE '%software\\policies\\microsoft\\office\\%\\excel\\security%' AND
       TARGET_PROCESS_COMMANDLINE ILIKE '%pythonfunctionwarnings%0%'
   AND EVENT_TIME >= CURRENT_TIMESTAMP - INTERVAL '30 days'
