MungeTLS - a library + sample exe for testing TLS 1.0, 1.1, and 1.2

-------------- Installation/running instructions --------------------------

make sure makecert.exe is in your path. a copy has been included in ext\

certutil.exe should already be in your path from windows

run misc\create_cert.cmd
  this requires having makecert.exe in your path somewhere. it comes with the Windows SDK
  accept whatever warnings it pops up

add the following line to your hosts file (on Windows, %windir%\system32\drivers\etc\hosts):
127.0.0.1 mtls-test

run exe\MungeTLS.exe

now see it in action:
open a web browser and navigate to https://mtls-test:8879/
  IE sometimes has a problem with renegotiation that I haven't figured out yet, so hitting F5 might not work. chrome ought to be okay, though.

TIP: to make things go faster, redirect the output to a log file.


--------------------- Writing apps that use MungeTLS ------------------------

Read inc\MungeTLS.h, especially the definition of ITLSLister. This is the contract that the calling app has to implement.

To see how to drive the TLS negotiation and act as a TLS server, it is best to read exe\main.cpp, a sample caller that exercises all of the features.


--------------------------- Porting notes ---------------------------------

If you are trying to use a different security library (not Windows' CryptoAPI), you will need to write implementations of PublicKeyCipherer, SymmetricCipherer, and Hasher (as found in MungeCrypto.h).

If you are trying to port to another platform entirely, you will need to search for "PLATFORM:" and implement all of the indicated functions and classes. As an example, plat_lib_windows does this


---------------------- Build instructions --------------------------------

open a visual studio 2010 or 2012 command prompt and just type nmake in the top-level folder. it's been tested with both of those


-------------------------- Code reading suggestions -----------------------

Read the RFCs:
TLS 1.0 - http://www.ietf.org/rfc/rfc2246.txt
TLS 1.2 - http://www.ietf.org/rfc/rfc5246.txt

start with inc\MungeTLS.h, then do lib\MungeTLS.cpp and spiral outwards as needed
entrypoint is in exe\main.cpp
all platform specific code is in plat_lib_windows\ or exe\
