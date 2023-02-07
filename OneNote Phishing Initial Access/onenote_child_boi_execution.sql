
SELECT EVENT_TIME                                   as EVENT_TIME,
       AGENT_ID                                     as AID,
       --parent process attributes
       parent_process_name                          as parent_process_name,
       parent_process_commandline                   as parent_process_commandline,
       --initiating process attributes
       initiating_process_name                      as process_name,
       initiating_process_commandline               as process_commandline,
       initiating_process_hash_sha256               as initiating_process_hash_sha256,
       --target process attributes
       target_process_username                      as target_process_username,
       target_process_name                          as target_process_name,
       target_process_path                          as target_process_path,
       target_process_commandline                   as target_process_commandline,
       target_process_hash_sha256                   as target_process_hash_sha256
  FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
     -- OneNote host process
 WHERE LOWER(INITIATING_PROCESS_NAME) IN('onenote.exe','onenotem.exe')
     -- commonly abused process for BOI child execution
     AND
        (
        TARGET_PROCESS_NAME IN('vssadmin.exe','certutil.exe','powershell.exe','at.exe','wmic.exe','netstat.exe',
                                'msxsl.exe','cmd.exe','change.exe','arp.exe','basename.exe','bcdedit.exe','bcp.exe',
                                'bitsadmin.exe','certutil.exe','cmstp.exe','curl.exe','dnscmd.exe','dsquery.exe','findstr.exe',
                                'gpresult.exe','hostname.exe','klist.exe','mofcomp.exe','msxsl.exe','nbtstat.exe',
                                'netstat.exe','nltest.exe','nslookup.exe','openfiles','psexec.exe','psexesvc.exe','qwinsta.exe',
                                 'regini.exe','robocopy.exe','runas.exe','rwinsta.exe','ssh.exe','systeminfo.exe','takeown.exe',
                                'tracert.exe','tree.com','uname.exe','vssadmin.exe','whoami.exe','wusa.exe','xcopy.exe','psexec.exe')
        OR
     -- Lolbins executions made with a target file parameter from the path \Temp\OneNote\16.0\Exported\ directory. This basically tells us the file was embedded in the Notebook and wasn’t already on the disk or public share.
        ( LOWER(TARGET_PROCESS_COMMANDLINE) LIKE '%onenote\\%\\exported\\%\\nt\\%'
         AND TARGET_PROCESS_NAME IN ('rundll32.exe','mshta.exe','wscript.exe'))
         )
   AND EVENT_TIME > dateadd(day, -{days_period}, current_timestamp)
