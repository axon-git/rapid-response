-- Title: Creation of unknown DLLs under the AD FS GAC. 
-- The thesis detects writing on new AD FS DLL modules starting with a prefix of Microsoft.IdentityServer to AD FS’s GAC  


WITH ADFS_AIDS AS
    (
        SELECT VALUE
          FROM INVESTIGATION.ASSET_TAGGING
         WHERE ASSET_TAG='adfs_server'
    )
SELECT EVENT_TIME
       AGENT_ID,
       DEVICE_PLATFORM,
       --parent process attribute
       PARENT_PROCESS_NAME,
       --initiating process attributes
       INITIATING_PROCESS_NAME,
       INITIATING_PROCESS_PATH,
       INITIATING_PROCESS_COMMANDLINE,
       INITIATING_PROCESS_HASH_SHA256,
        --target file attributes
       TARGET_FILE_NAME,
       TARGET_FILE_PATH,
       TARGET_FILE_HASH_SHA256,
       TARGET_FILE_EXTENSION
    FROM INVESTIGATION.EDR_FILE_EVENTS
   WHERE TARGET_FILE_ACTION='create'
     AND DEVICE_PLATFORM = 'WINDOWS'
   -- IdentityServer DLLs written to GAC
     AND TARGET_FILE_PATH ILIKE '%Windows\\Microsoft.NET\\assembly\\GAC_%Microsoft.IdentityServer%'
   -- AD FS AGENT IDs
     AND AGENT_ID IN (SELECT VALUE FROM ADFS_AIDS)
   -- define time range
     AND EVENT_TIME > CURRENT_DATE() - interval '{days}d'
