-- Password health reports activity
SELECT DEBUG_CONTEXT:debugData:requestUri,
       *
  FROM RAW.OKTA_LOGS
 WHERE PUBLISHED >= '2023-10-01'
   AND DEBUG_CONTEXT:debugData:requestUri ILIKE '%/reports/password-health/%'
