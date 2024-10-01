SELECT --- Details about relevant host
       AID,
       LAST_HOSTNAME,
       LAST_EXTERNAL_IP_ADDRESS,
       LAST_INTERNAL_IP_ADDRESS,
       OS_TYPE,
       LAST_OS_VERSION,
       LAST_OS_BUILD,
       --- Additional Information
       SPECIFIC_SOURCE_TYPE,
       FIRST_SEEN,
       LAST_SEEN,
       CLOUD_PROVIDER,
       LAST_CLOUD_PROVIDER_ACCOUNT_ID,
       LAST_CLOUD_PROVIDER_INSTANCE_ID
FROM INVESTIGATION.EDR_AGENT_INFO
WHERE AID IN (
    SELECT DISTINCT AGENT_ID                             AS AGENT_ID
FROM INVESTIGATION.EDR_NETWORK_EVENTS
WHERE IS_INBOUND = 'true'
AND DEVICE_PLATFORM IN ('LINUX', 'MAC')
AND LOCAL_PORT = '631'
--- clean-up of internal and saved ip ranges - to get only access from external IP addresses ----
AND NOT (  -- 10.X.X.X
                  REGEXP_SUBSTR(remote_ip, '10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
               OR remote_ip LIKE '10.%'
                  -- 192.168.X.X
               OR REGEXP_SUBSTR(remote_ip, '192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
               OR remote_ip LIKE '192.168.%'
                  -- 127.X.X.X
               OR REGEXP_SUBSTR(remote_ip, '127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
               OR remote_ip LIKE '127.%'
                  -- 224.X.X.X
               OR REGEXP_SUBSTR(remote_ip, '224\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
               OR remote_ip LIKE '224.%'
                  -- 172.X.X.X/12
               OR REGEXP_SUBSTR(remote_ip, '172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
                  -- 169.254.X.X
               OR REGEXP_SUBSTR(remote_ip, '169\\.254\\.[0-9]{1,3}\\.[0-9]{1,3}') IS NOT NULL
               OR remote_ip LIKE '169.254.%'
               OR remote_ip LIKE '%0.0.0.0%'
               -- exclude IPv6 localhost address
               OR remote_ip LIKE '%0:0:0:0%'
               OR remote_ip LIKE '%::1%'
               OR remote_ip = '::'
              )
AND EVENT_TIME > current_timestamp - interval '7d'
AND PROTOCOL = 'UDP'
    )
