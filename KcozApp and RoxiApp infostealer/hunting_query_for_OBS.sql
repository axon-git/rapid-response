SELECT EVENT_TIME,
       AGENT_ID,
       DEVICE_NAME,
       TARGET_PROCESS_USERNAME,
       PARENT_PROCESS_NAME,
       INITIATING_PROCESS_NAME,
       INITIATING_PROCESS_PATH,
       INITIATING_PROCESS_COMMANDLINE,
       TARGET_PROCESS_NAME,
       TARGET_PROCESS_PATH,
       TARGET_PROCESS_COMMANDLINE
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE EVENT_TIME > current_timestamp - interval '30d'
   AND (
        INITIATING_PROCESS_PATH ILIKE '%appdata%app%obs-ffmpeg-mux.exe%' //The malicious files are stored in a randomly generated folder within the AppData directory, with the folder name following the format XXXXApp.
       OR TARGET_PROCESS_PATH ILIKE '%appdata%app%obs-ffmpeg-mux.exe%'
       OR PARENT_PROCESS_PATH ILIKE '%appdata%app%obs-ffmpeg-mux.exe%'
       OR TARGET_PROCESS_COMMANDLINE ILIKE '%explorer.exe explorer.exe' //Behavior noticed by the malicious process
    );
