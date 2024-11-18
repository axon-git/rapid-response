SELECT 
    EVENT_TIME,                              
    OPERATION,                               
    ORGANIZATION_ID,                         
    WORKLOAD,                                
    RESULT_STATUS,                          
    OBJECT_ID,                               
    USER_ID,                                 
    CLIENT_IP,                               
    RECORD_SPECIFIC_DETAILS:extended_properties.user_agent AS USER_AGENT
                                             -- The user agent string of the client, extracted from the extended properties
FROM 
    RAW.O365_AUDIT_LOGS                     
WHERE 
    USER_AGENT ILIKE ANY ('%axios/1%', '%axios/0%') 
                                             -- Filter events where the user agent string contains "axios/1" or "axios/0" (case-insensitive)
    AND EVENT_TIME > current_timestamp - interval '180d'
