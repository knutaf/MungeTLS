set makecert=makecert
certutil -delstore -user -v MY mtls-test
%makecert% -pe -r -sr CurrentUser -ss MY -n "CN=mtls-test" -a sha1 -sky exchange -cy end -len 1024 -b 04/01/2010 mtls-test.cer
