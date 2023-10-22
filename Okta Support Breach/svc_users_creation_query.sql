-- svc users creations
SELECT TARGET_USER_ALTERNATE_ID,
       *
  FROM RAW.OKTA_LOGS
 WHERE PUBLISHED >= '2023-10-01'
   AND EVENT_TYPE IN ('user.lifecycle.create','user.lifecycle.activate')
   AND OKTA_LOGS.TARGET_USER_DISPLAY_NAME ILIKE '%svc%'
