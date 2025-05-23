SELECT EVENT_TIME,
       CALLER_IP_ADDRESS,
       CATEGORY,
       IDENTITY,
       LOCATION,
       OPERATION_NAME,
       PROPERTIES_APP_ID,
       PROPERTIES_CLIENT_APP_USED,
       PROPERTIES_CONDITIONAL_ACCESS_STATUS,
       PROPERTIES_IS_INTERACTIVE,
       PROPERTIES_TOKEN_ISSUER_TYPE,
       RESULT_DESCRIPTION,
       RESULT_TYPE,
       PROPERTIES_APP_DISPLAY_NAME,
       PROPERTIES_USER_PRINCIPAL_NAME,
       PROPERTIES:userAgent             AS USER_AGENT
FROM RAW.AZURE_SIGNIN
WHERE USER_AGENT ILIKE '%fasthttp%'
-- adjust the timeframe according to your needs
AND EVENT_TIME BETWEEN '2025-01-15 00:00:01' and '2025-03-02 23:59:01'
AND NOT RESULT_TYPE IN ('50053', '50056', '50126') -- to remove result types that are related to wrong credentials usage
