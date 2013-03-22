set makecert=makecert
cmd /c %~dp0\del_certs.cmd

%makecert% -pe -r -sr CurrentUser -ss ROOT -n "CN=mtls-root" -a sha1 -sky exchange -cy authority -len 2048 -b 04/01/2010 mtls-root.cer

%makecert% -pe -sr CurrentUser -ss MY -n "CN=mtls-mid" -in "mtls-root" -ir CurrentUser -is ROOT -a sha1 -sky exchange -cy authority -len 2048 -b 04/01/2010 mtls-mid.cer

%makecert% -pe -sr CurrentUser -ss MY -n "CN=mtls-test" -in "mtls-mid" -ir CurrentUser -is MY -a sha1 -sky exchange -cy end -len 2048 -b 04/01/2010 mtls-test.cer
