
-- The threat hunting thesis catching LDAP packets to the DC from an unknown process on the AD FS server run under the AD FS service user context

WITH adfs_servers AS
    -- get AD FS machines and service account SIDs
(
       SELECT  AGENT_ID,
               SPECIFIC_ATTRS,
               SPECIFIC_ATTRS:windows_user_sid
        FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
       WHERE device_platform='WINDOWS'
         -- AD FS service host process
         AND LOWER(target_process_name) ='microsoft.identityserver.servicehost.exe'
         AND LOWER(target_process_path) LIKE '%\\windows\\adfs\\microsoft.identityserver.servicehost.exe%'
         AND event_time > dateadd(day, -30, current_timestamp)
         -- user accounts alone
         AND specific_attrs:windows_user_sid__windows_user_sid ilike 'S-1-5-21%')

   , adfs_proc AS
    -- processes under the AD FS service account context
(
       SELECT TARGET_PROCESS_UID
         FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
        WHERE specific_attrs:windows_user_sid__windows_user_sid IN
              (
                     SELECT specific_attrs:windows_user_sid__windows_user_sid
                     FROM   adfs_servers )
          AND event_time > DATEADD(day, - 30, CURRENT_TIMESTAMP) )


SELECT AGENT_ID,
       AGENT_EXTERNAL_IP,
       INITIATING_PROCESS_NAME,
       INITIATING_PROCESS_COMMANDLINE,
       INITIATING_PROCESS_HASH_SHA256,
       PARENT_PROCESS_NAME,
       REMOTE_IP,
       REMOTE_PORT
  FROM INVESTIGATION.EDR_NETWORK_EVENTS
 --INNER JOIN INVESTIGATION.EDR_AGENT_INFO ON REMOTE_PORT = INVESTIGATION.EDR_AGENT_INFO.LAST_INTERNAL_IP_ADDRESS
 WHERE initiating_process_uid IN
       (
              SELECT TARGET_PROCESS_UID
              FROM   adfs_proc )
   AND remote_port = '389'
   AND NOT INITIATING_PROCESS_NAME='Microsoft.IdentityServer.ServiceHost.exe'
   AND event_time > dateadd(day, - 30, CURRENT_TIMESTAMP);
