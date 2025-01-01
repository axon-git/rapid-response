SELECT EVENT_TIME,
       AID,
       AIP,
       ID,
       RAW:BrowserExtensionId::VARCHAR extension_id,
       RAW:BrowserExtensionVersion::VARCHAR extension_version,
       RAW:BrowserExtensionName::VARCHAR extension_name,
       RAW:UserName::VARCHAR username,
       RAW:UserSid::VARCHAR sid
FROM RAW.CROWDSTRIKE_RAW_EVENTS
-- Adjust times based on your needs
WHERE EVENT_TIME BETWEEN '2024-01-01' AND '2025-01-01'
AND EVENT_SIMPLE_NAME = 'InstalledBrowserExtension'
AND (
    (RAW:BrowserExtensionId::VARCHAR = 'nnpnnpemnckcfdebeekibpiijlicmpom' AND RAW:BrowserExtensionVersion::VARCHAR = '2.0.1')
 OR (RAW:BrowserExtensionId::VARCHAR = 'kkodiihpgodmdankclfibbiphjkfdenh' AND RAW:BrowserExtensionVersion::VARCHAR = '1.16.2')
 OR (RAW:BrowserExtensionId::VARCHAR = 'oaikpkmjciadfpddlpjjdapglcihgdle' AND RAW:BrowserExtensionVersion::VARCHAR = '1.0.12')
 OR (RAW:BrowserExtensionId::VARCHAR = 'dpggmcodlahmljkhlmpgpdcffdaoccni' AND RAW:BrowserExtensionVersion::VARCHAR = '1.1.1')
 OR (RAW:BrowserExtensionId::VARCHAR = 'acmfnomgphggonodopogfbmkneepfgnh' AND RAW:BrowserExtensionVersion::VARCHAR = '4.00')
 OR (RAW:BrowserExtensionId::VARCHAR = 'mnhffkhmpnefgklngfmlndmkimimbphc' AND RAW:BrowserExtensionVersion::VARCHAR = '4.40')
 OR (RAW:BrowserExtensionId::VARCHAR = 'cedgndijpacnfbdggppddacngjfdkaca' AND RAW:BrowserExtensionVersion::VARCHAR = '0.0.11')
 OR (RAW:BrowserExtensionId::VARCHAR = 'bbdnohkpnbkdkmnkddobeafboooinpla' AND RAW:BrowserExtensionVersion::VARCHAR = '1.0.1')
 OR (RAW:BrowserExtensionId::VARCHAR = 'egmennebgadmncfjafcemlecimkepcle' AND RAW:BrowserExtensionVersion::VARCHAR = '2.2.7')
 OR (RAW:BrowserExtensionId::VARCHAR = 'bibjgkidgpfbblifamdlkdlhgihmfohh' AND RAW:BrowserExtensionVersion::VARCHAR = '0.1.3')
 OR (RAW:BrowserExtensionId::VARCHAR = 'cplhlgabfijoiabgkigdafklbhhdkahj' AND RAW:BrowserExtensionVersion::VARCHAR = '1.0.161')
 OR (RAW:BrowserExtensionId::VARCHAR = 'befflofjcniongenjmbkgkoljhgliihe' AND RAW:BrowserExtensionVersion::VARCHAR = '2.13.0')
 OR (RAW:BrowserExtensionId::VARCHAR = 'pkgciiiancapdlpcbppfkmeaieppikkk' AND RAW:BrowserExtensionVersion::VARCHAR = '1.3.7')
 OR (RAW:BrowserExtensionId::VARCHAR = 'llimhhconnjiflfimocjggfjdlmlhblm' AND RAW:BrowserExtensionVersion::VARCHAR = '1.5.7')
 OR (RAW:BrowserExtensionId::VARCHAR = 'oeiomhmbaapihbilkfkhmlajkeegnjhe' AND RAW:BrowserExtensionVersion::VARCHAR = '3.18.0')
 OR (RAW:BrowserExtensionId::VARCHAR = 'ekpkdmohpdnebfedjjfklhpefgpgaaji' AND RAW:BrowserExtensionVersion::VARCHAR = '1.3')
 OR (RAW:BrowserExtensionId::VARCHAR = 'epikoohpebngmakjinphfiagogjcnddm' AND RAW:BrowserExtensionVersion::VARCHAR = '2.7.3')
 OR (RAW:BrowserExtensionId::VARCHAR = 'miglaibdlgminlepgeifekifakochlka' AND RAW:BrowserExtensionVersion::VARCHAR = '1.4.5')
 OR (RAW:BrowserExtensionId::VARCHAR = 'eanofdhdfbcalhflpbdipkjjkoimeeod' AND RAW:BrowserExtensionVersion::VARCHAR = '1.4.9')
 OR (RAW:BrowserExtensionId::VARCHAR = 'ogbhbgkiojdollpjbhbamafmedkeockb' AND RAW:BrowserExtensionVersion::VARCHAR = '1.8.1')
 OR (RAW:BrowserExtensionId::VARCHAR = 'bgejafhieobnfpjlpcjjggoboebonfcg' AND RAW:BrowserExtensionVersion::VARCHAR = '1.1.1')
 OR (RAW:BrowserExtensionId::VARCHAR = 'igbodamhgjohafcenbcljfegbipdfjpk' AND RAW:BrowserExtensionVersion::VARCHAR = '2.3')
 OR (RAW:BrowserExtensionId::VARCHAR = 'mbindhfolmpijhodmgkloeeppmkhpmhc' AND RAW:BrowserExtensionVersion::VARCHAR = '1.44')
 OR (RAW:BrowserExtensionId::VARCHAR = 'hodiladlefdpcbemnbbcpclbmknkiaem' AND RAW:BrowserExtensionVersion::VARCHAR = '3.1.3')
 OR (RAW:BrowserExtensionId::VARCHAR = 'pajkjnmeojmbapicmbpliphjmcekeaac' AND RAW:BrowserExtensionVersion::VARCHAR = '24.10.4')
 OR (RAW:BrowserExtensionId::VARCHAR = 'ndlbedplllcgconngcnfmkadhokfaaln' AND RAW:BrowserExtensionVersion::VARCHAR = '2.22.6')
 OR (RAW:BrowserExtensionId::VARCHAR = 'epdjhgbipjpbbhoccdeipghoihibnfja' AND RAW:BrowserExtensionVersion::VARCHAR = '1.4')
 OR (RAW:BrowserExtensionId::VARCHAR = 'cplhlgabfijoiabgkigdafklbhhdkahj' AND RAW:BrowserExtensionVersion::VARCHAR = '1.0.161')
 OR (RAW:BrowserExtensionId::VARCHAR = 'eaijffijbobmnonfhilihbejadplhddo' AND RAW:BrowserExtensionVersion::VARCHAR = '2.4')
 OR (RAW:BrowserExtensionId::VARCHAR = 'hmiaoahjllhfgebflooeeefeiafpkfde' AND RAW:BrowserExtensionVersion::VARCHAR = '1.0.0')
    )
