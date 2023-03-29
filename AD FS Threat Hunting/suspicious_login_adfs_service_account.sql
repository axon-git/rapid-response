
-- The AD FS Service account is a built-in user object which is generated during the creation of the AD FS service (server) in the on-premises AD. A threat hunting thesis would be identifying suspicious user logins that use login type codes other than service logins.


WITH ADFS_SERVICE_ACCOUNT AS
    -- get SIDs for AD FS service account objects
    (
      SELECT DISTINCT specific_attrs:windows_user_sid__windows_user_sid    windows_user_sid
        FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
       WHERE device_platform='WINDOWS'
         -- AD FS service host process
         AND LOWER(target_process_name) ='microsoft.identityserver.servicehost.exe'
         AND LOWER(target_process_path) LIKE '%\\windows\\adfs\\microsoft.identityserver.servicehost.exe%'
         AND event_time > dateadd(day, -30, current_timestamp)
         -- user accounts alone
         AND specific_attrs:windows_user_sid__windows_user_sid ilike 'S-1-5-21%')

SELECT ARRAY_AGG(DISTINCT event_time::timestampltz) within GROUP (ORDER BY event_time::timestampltz) AS LOGON_TIMES,
       LOGON_USERNAME,
       LOGON_USER_ID,
       LOGON_TYPE,
       ARRAY_AGG(DISTINCT AGENT_ID)                                                                  AS TARGET_HOSTS,
       ARRAY_AGG(DISTINCT LOGON_DC_SERVER_NAME)                                                      AS AUTH_DCS
  FROM INVESTIGATION.EDR_LOGON_EVENTS
 WHERE LOGON_USER_ID IN
                        (
                            SELECT windows_user_sid FROM ADFS_SERVICE_ACCOUNT
                            )
   -- excluding generic service logons by the service account. "Service" == '5' logon type.
   AND NOT LOGON_TYPE IN('Service')
   AND EVENT_TIME > dateadd(day, -30, current_timestamp)
 GROUP BY LOGON_USERNAME,
          LOGON_USER_ID,
          LOGON_TYPE
