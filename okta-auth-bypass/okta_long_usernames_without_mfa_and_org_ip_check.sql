WITH long_usernames AS (
    SELECT ID, PROFILE_LOGIN
    FROM RAW.OKTA_USERS
    WHERE LENGTH(PROFILE_LOGIN) > 51
),
     mfa_events AS (
         SELECT ACTOR_ID, MIN(PUBLISHED) AS first_mfa_time
         FROM RAW.OKTA_LOGS
         WHERE EVENT_TYPE = 'user.authentication.auth_via_mfa'
         GROUP BY ACTOR_ID
     ),
     ad_users AS (
         SELECT DISTINCT ACTOR_ID
         FROM RAW.OKTA_LOGS
         WHERE EVENT_TYPE IN ('user.authentication.auth_via_AD_agent', 'user.authentication.auth_via_LDAP_agent')
     ),
     org_ip AS (
         SELECT DISTINCT IP AS ORG_IPS
         FROM INVESTIGATION.ORGANIZATIONAL_IP
     )

SELECT DISTINCT
    logs.UUID,
    logs.PUBLISHED,
    logs.EVENT_TYPE,
    logs.ACTOR_ID,
    long.PROFILE_LOGIN,
    logs.CLIENT_IP_ADDRESS,
    logs.CLIENT_USER_AGENT_OS,
    logs.CLIENT_USER_AGENT_BROWSER,
    CASE
        WHEN logs.CLIENT_IP_ADDRESS IN (SELECT ORG_IPS FROM org_ip) THEN True
        ELSE False
        END AS IS_ORGANIZATIONAL_IP
FROM RAW.OKTA_LOGS AS logs
         JOIN long_usernames AS long
              ON logs.ACTOR_ID = long.ID
         LEFT JOIN mfa_events AS mfa
                   ON logs.ACTOR_ID = mfa.ACTOR_ID
WHERE (mfa.first_mfa_time IS NULL
    OR logs.PUBLISHED <= mfa.first_mfa_time - INTERVAL '1 minute')
  AND logs.ACTOR_ID IN (SELECT ACTOR_ID FROM ad_users)
  AND logs.PUBLISHED BETWEEN '2024-07-22' AND '2024-10-31';
