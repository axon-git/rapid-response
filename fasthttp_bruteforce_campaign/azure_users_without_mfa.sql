SELECT DISTINCT PROPERTIES_USER_PRINCIPAL_NAME,
       IDENTITY,
       PROPERTIES:authenticationRequirement AS AuthRequirement
FROM RAW.AZURE_SIGNIN
WHERE EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '3 days'
  AND AuthRequirement = 'singleFactorAuthentication'
  AND RESULT_TYPE = 0 -- only successful logins
GROUP BY 1,2,3
