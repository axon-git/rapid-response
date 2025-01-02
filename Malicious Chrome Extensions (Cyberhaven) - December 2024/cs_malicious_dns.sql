  WITH malicious_dns AS (
    SELECT *
    FROM RAW.CROWDSTRIKE_RAW_EVENTS
    WHERE EVENT_SIMPLE_NAME = 'DnsRequest'
    AND DOMAIN_NAME IN ('bookmarkfc.info', 'vpncity.live', 'castorus.info', 'parrottalks.info', 'primusext.pro', 'censortracker.pro', 'uvoice.live', 'iobit.pro', 'moonsift.store', 'yujaverity.info', 'wayinai.live', 'readermodeext.info', 'policyextension.info', 'yescaptcha.pro', 'internxtvpn.pro', 'wakelet.ink', 'linewizeconnect.com', 'bardaiforchrome.live', 'blockadsonyt.vip', 'chataiassistant.pro', 'chatgptextension.site', 'chatgptextent.pro', 'cyberhavenext.pro', 'dearflip.pro', 'geminiaigg.pro', 'goodenhancerblocker.site', 'gpt4summary.ink', 'linewizeconnect.com', 'locallyext.ink', 'proxyswitchyomega.pro', 'savegptforyou.live', 'savgptforchrome.pro', 'searchcopilot.co', 'tinamind.info', 'tkv2.pro', 'videodownloadhelper.pro', 'vidnozflex.live', 'youtubeadsblocker.live', 'checkpolicy.site', 'extensionbuysell.com', 'extensionpolicy.net', 'extensionpolicyprivacy.com', 'linewizeconnect.com', 'cyberhaven.pro', 'adskiper.net', 'aeromexi.co', 'aiforgemini.com', 'api.searchcopilot.co', 'apple-ads-metric.com', 'artseasy.com', 'barefootcontractor.com', 'blockforads.com', 'businessforai.com', 'capitalizerutc.com', 'chatgpt.forassistant.com', 'chatgptforsearch.com', 'com-freeapps.com', 'ext.businessforai.com', 'fadblock.pro', 'geminiforads.com', 'gosiridersite.com', 'gptdetector.live', 'gptforads.info', 'gptforbusiness.site', 'graphqlnetwork.pro', 'internetdownloadmanager.pro', 'liseng1998app.top', 'lltvmarkets.com', 'okta-onsolve.com', 'openaigptforgg.site', 'pieadblock.pro', 'plutonile.com', 'remiwantnun.com', 'savechatgpt.site', 'savegptforchrome.com', 'searchaiassitant.info', 'searchgptchat.info', 'seasonaldroughtwatch.site', 'seasonalweatherdatapro.site', 'seasonalweatheroutlookpro.site', 'seasonalweatherstatspro.site', 'seasonalwindtracker.site', 'taskthebox.net', 'tkpartner.pro', 'ultrablock.pro', 'upwordwave.com', 'ytbadblocker.com')
    AND EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '1 week'
),
    process_create AS (
        SELECT RAW:TargetProcessId::VARCHAR process_id, RAW:UserSid::VARCHAR sid
        FROM RAW.CROWDSTRIKE_RAW_EVENTS
        WHERE EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '1 week'
        AND EVENT_SIMPLE_NAME IN ('SyntheticProcessRollup2', 'ProcessRollup2')
    )

SELECT EVENT_TIME, AID, AIP, EVENT_PLATFORM, ID, DOMAIN_NAME, RAW, SID
FROM malicious_dns
LEFT JOIN process_create ON malicious_dns.RAW:ContextProcessId::VARCHAR = process_create.process_id
