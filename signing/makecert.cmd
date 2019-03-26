makecert -sv company.pvk -a sha1 -eku 1.3.6.1.5.5.7.3.3 -r -ss Root -len 1024 -sr localmachine -n "CN=company,O=product,E=company@email.com"  -b 01/01/2012 company.cer
cert2spc company.cer company.spc
pvk2pfx -pvk company.pvk -pi password -spc company.spc -pfx company.pfx -po password
signtool sign /f company.pfx /p password /d "company product" /v companyx64.sys