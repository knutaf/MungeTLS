set makecert=makecert
certutil -delstore -user -v ROOT mtls-root
%makecert% -pe -r -sr CurrentUser -ss ROOT -n "CN=mtls-root" -a sha1 -sky exchange -cy authority -len 2048 -b 04/01/2010 mtls-root.cer

certutil -delstore -user -v MY mtls-mid
%makecert% -pe -sr CurrentUser -ss MY -n "CN=mtls-mid" -in "mtls-root" -ir CurrentUser -is ROOT -a sha1 -sky exchange -cy authority -len 2048 -b 04/01/2010 mtls-mid.cer

certutil -delstore -user -v MY mtls-test
%makecert% -pe -sr CurrentUser -ss MY -n "CN=mtls-test" -in "mtls-mid" -ir CurrentUser -is MY -a sha1 -sky exchange -cy end -len 2048 -b 04/01/2010 mtls-test.cer
