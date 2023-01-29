-- Title: Microsoft.IdentityServer.ServiceHost Child Execution
-- The service process of AD FS Microsoft.IdentityServer.ServiceHost.exe can be manipulated to execute payloads for persistence activity. A threat-hunting thesis would be to detect anomaly child process execution under the AD FS service host process. 

WITH ADFS_AIDS AS
    (
        SELECT VALUE
          FROM INVESTIGATION.ASSET_TAGGING
         WHERE ASSET_TAG='adfs_server'
    )
  SELECT  EVENT_TIME                                   AS EVENT_TIME,
          AGENT_ID                                     AS AID,
          --parent process attributes
          parent_process_name                          as parent_process_name,
          parent_process_commandline                   as parent_process_commandline,
          --initiating process attributes
          initiating_process_name                      as initiating_process_name,
          initiating_process_commandline               as process_commandline,
          initiating_process_hash_sha256               as initiating_process_hash_sha256,
          --target process attributes
          target_process_username                      as target_process_username,
          target_process_name                          as target_process_name,
          target_process_path                          as target_process_path,
          target_process_commandline                   as target_process_commandline,
          target_process_hash_sha256                   as target_process_hash_sha256
     FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
    WHERE device_platform = 'WINDOWS'
      -- AD FS AGENT IDs (for optimization)
      AND AGENT_ID IN (SELECT VALUE FROM ADFS_AIDS)
      -- AD FS service process
      AND LOWER(initiating_process_name) = 'microsoft.identityserver.servicehost.exe'
      AND TARGET_PROCESS_NAME is not null
      -- define time range
      AND EVENT_TIME > CURRENT_DATE() - interval '{days}d'
      
   
