SELECT DISTINCT ASSET_TAG,
                VALUE         as AGENT_ID,
                LAST_HOSTNAME as HOSTNAME,
                ASSET_TAGGING.LAST_SEEN
FROM INVESTIGATION.ASSET_TAGGING JOIN INVESTIGATION.EDR_AGENT_INFO ON VALUE = AID
WHERE ASSET_TAG = 'exchange_server'
  AND ASSET_TAGGING.LAST_SEEN >= CURRENT_TIMESTAMP - INTERVAL '30 days'
