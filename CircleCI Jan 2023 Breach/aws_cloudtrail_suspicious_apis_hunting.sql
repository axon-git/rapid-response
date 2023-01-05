WITH LEARNING_EVENTS AS (
              SELECT SOURCE_IP_ADDRESS,
                     USER_AGENT,
                     EVENT_NAME
                FROM RAW.AWS_CLOUDTRAIL
               -- Define Learning Period
               WHERE EVENT_TIME BETWEEN '2022-09-21 00:00:00' and '2022-12-21 00:00:00'
                -- relevant CIRCLECI ARNS
                 AND USER_IDENTITY_ARN IN('{CIRCLECI_ARN}'))

SELECT EVENT_NAME,
       EVENT_SOURCE,
       EVENT_TYPE,
       USER_IDENTITY_ARN,
       USER_AGENT,
       SOURCE_IP_ADDRESS
         FROM RAW.AWS_CLOUDTRAIL
          -- CIRCLECI breach days
        WHERE EVENT_TIME > '2022-12-21 00:00:00'
          AND USER_IDENTITY_ARN IN('{CIRCLECI_ARN}')
           -- Newly Seen IPs on breach dates
           AND NOT SOURCE_IP_ADDRESS IN( SELECT SOURCE_IP_ADDRESS FROM LEARNING_EVENTS)
           AND (NOT USER_AGENT IN(SELECT USER_AGENT FROM LEARNING_EVENTS)
                OR EVENT_NAME IN(SELECT EVENT_NAME FROM LEARNING_EVENTS))