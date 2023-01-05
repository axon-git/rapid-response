-- The following queries detect new IPs and new operations conducted by applied service_principal_id after CircleCI breach
-- Please insert the CircleCI service principal ID in the conditions

-- Azure Activity
WITH AZURE_LEARNING_EVENTS AS (SELECT IDENTITY_CLAIMS:"http://schemas.microsoft.com/identity/claims/objectidentifier" servicePrincipalId,
                                      CALLER_IP_ADDRESS,
                                      OPERATION_NAME
                               FROM RAW.AZURE_ACTIVITY AS ACTIVITY_TABLE
                                    -- Define Learning Period
                               WHERE ACTIVITY_TABLE.EVENT_TIME BETWEEN '2022-09-21 00:00:00' and '2022-12-21 00:00:00'
                                 -- relevant CIRCLECI Azure Service Principals
                  AND IDENTITY_CLAIMS:"http://schemas.microsoft.com/identity/claims/objectidentifier" IN('{CIRCLECI_SERVICE_PRINCIPAL_ID}'))
SELECT IDENTITY_CLAIMS:"http://schemas.microsoft.com/identity/claims/objectidentifier" servicePrincipalId,
       CALLER_IP_ADDRESS,
       ACTIVITY_TABLE.OPERATION_NAME
FROM RAW.AZURE_ACTIVITY AS ACTIVITY_TABLE
     -- CIRCLECI breach days
WHERE ACTIVITY_TABLE.EVENT_TIME BETWEEN '2022-12-21 00:00:00' AND '2023-01-04 00:00:00'
   AND servicePrincipalId IN ('{CIRCLECI_SERVICE_PRINCIPAL_ID}')
  -- Newly Seen IPs on breach dates
  AND NOT CALLER_IP_ADDRESS IN (SELECT CALLER_IP_ADDRESS FROM AZURE_LEARNING_EVENTS)
  AND NOT OPERATION_NAME IN (SELECT OPERATION_NAME FROM AZURE_LEARNING_EVENTS)
  
  
  
-- Azure Audit
WITH AZURE_LEARNING_EVENTS AS (SELECT PROPERTIES_INITIATED_BY:app.servicePrincipalId servicePrincipalId,
                                      CALLER_IP_ADDRESS,
                                      OPERATION_NAME
                               FROM RAW.AZURE_AUDIT
                                    -- Define Learning Period
                               WHERE AZURE_AUDIT.EVENT_TIME BETWEEN '2022-09-21 00:00:00' and '2022-12-21 00:00:00'
                                 AND NOT servicePrincipalId IS NULL
                                 -- relevant CIRCLECI Azure Service Principals
                  AND PROPERTIES_INITIATED_BY:app.servicePrincipalId IN('{CIRCLECI_SERVICE_PRINCIPAL_ID}'))
SELECT PROPERTIES_INITIATED_BY:app.servicePrincipalId servicePrincipalId,
       CALLER_IP_ADDRESS,
       OPERATION_NAME
FROM RAW.AZURE_AUDIT
     -- CIRCLECI breach days
WHERE EVENT_TIME BETWEEN '2022-12-21 00:00:00' AND '2023-01-04 00:00:00'
   AND PROPERTIES_INITIATED_BY:app.servicePrincipalId IN ('{CIRCLECI_SERVICE_PRINCIPAL_ID}')
  AND NOT servicePrincipalId IS NULL
  -- Newly Seen IPs on breach dates
  AND NOT CALLER_IP_ADDRESS IN (SELECT CALLER_IP_ADDRESS FROM AZURE_LEARNING_EVENTS)
  AND NOT OPERATION_NAME IN (SELECT OPERATION_NAME FROM AZURE_LEARNING_EVENTS)
