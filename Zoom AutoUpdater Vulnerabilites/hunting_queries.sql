--Hunting Query #1
--Package name change to a specific convention - as described above, some of the vulnerabilities relies on name changing of the package installed by the installer.
--The following query looks for executions which includes part of the string which Zoom AutoUpdater looks for to verify the installed package

SELECT *
    FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
    WHERE DEVICE_PLATFORM = 'MAC'
    AND TARGET_PROCESS_COMMANDLINE ILIKE '%Zoom Video Communications, Inc%'
    AND TARGET_PROCESS_NAME ILIKE 'pkgutil'
    

--Hunting Query #2
--Detects a suspicious writing of content towards the “zoomTmp.pkg” which may indicate for a malicious attempt to install unwanted package

SELECT *
    FROM INVESTIGATION.EDR_FILE_EVENTS
    WHERE DEVICE_PLATFORM = 'MAC'
    AND TARGET_FILE_NAME ILIKE 'zoomTmp.pkg'
    AND (INITIATING_PROCESS_PATH NOT IN ('/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon' , '/usr/sbin/pkgutil') OR INITIATING_PROCESS_PATH IS NULL)
