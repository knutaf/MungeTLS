MungeTLS - a library + sample exe for testing TLS 1.0, 1.1, and 1.2

Installation/running instructions:
make sure makecert.exe is in your path. a copy has been included in ext\

certutil.exe should already be in your path from windows

run misc\create_cert.cmd
  accept whatever warnings it pops up

add the following line to your hosts file:
127.0.0.1 mtls-test

run exe\MungeTLS.exe

open a web browser and navigate to https://mtls-test:8879/
  IE has a problem with renegotiation that I haven't figured out yet, so hitting F5 won't work. chrome ought to be okay, though.

TIP: to make things go faster, redirect the output to a log file.



Build instructions:
open a visual studio 2010 or 2012 command prompt and just type nmake in the top-level folder. it's been tested with both of those


Code review suggestions:
Read the RFCs:
TLS 1.0 - http://www.ietf.org/rfc/rfc2246.txt
TLS 1.2 - http://www.ietf.org/rfc/rfc5246.txt

start with inc\MungeTLS.h, then do lib\MungeTLS.cpp
entrypoint is in exe\main.cpp
