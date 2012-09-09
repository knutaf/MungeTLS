set version=%1
if not defined version set version=-tls1
openssl s_client -connect localhost:8879 -debug -state -pause -msg -legacy_renegotiation -tlsextdebug %version%
