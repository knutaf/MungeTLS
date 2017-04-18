# MungeTLS
### A library + sample web server for testing TLS 1.0, 1.1, and 1.2

## Installation/running instructions

Make sure you have [`makecert.exe`](http://msdn.microsoft.com/en-us/library/bfsktky3.aspx) in your PATH somewhere. It comes with the [Windows SDK](http://msdn.microsoft.com/en-us/windows/hardware/hh852363.aspx).

certutil.exe should already be in your PATH, since it comes with Windows.

Run `misc\add_certs.cmd`
This adds some test certificates for the server. Accept whatever warnings it pops up.
You should delete the certificates later by running `misc\del_certs.cmd`.

Add the following line to your hosts file (on Windows, `%windir%\system32\drivers\etc\hosts`):  
`127.0.0.1 mtls-test`

Run `exe\MungeTLS.exe`

Now see it in action: open a web browser and navigate to [`https://mtls-test:8879`](https://mtls-test:8879/).

TIP: to make things go faster, redirect the output to a log file.


## Writing apps that use MungeTLS

Read `inc\MungeTLS.h`, especially the definition of `ITLSServerLister`. This is the contract that the calling app has to implement.

To see how to drive the TLS negotiation and act as a TLS server, it is best to read `exe\main.cpp`, a sample caller that exercises all of the features.


## Porting notes

If you are trying to use a different security library (not Windows' CryptoAPI) or platform, you will need to search for "`PLATFORM:`" in the source tree and implement all of the indicated functions and classes. As an example, `plat_lib_windows` does this.


## Build instructions

Open a Visual Studio command prompt and just type `nmake` in the trunk folder. It's been tested with both 2010 and 2012. Builds with 2017, at least.


## Netmon Configuration

The application can work with [Netmon 3.4](http://www.microsoft.com/en-us/download/details.aspx?id=4865) to produce Netmon capture files with the unecrypted traffic, for very easy inspection. At compile-time, if `NMAPI.dll` is found in the PATH, the application will compile in Netmon support. Then at runtime, it again checks for `NMAPI.dll` before trying to invoke any Netmon functionality, allowing you to distribute the binary to someone who doesn't have it installed.

To process and display the capture properly, you will need to configure Netmon to pick up the parser file at `misc\mungetls.npl`.

1. In Netmon, go to your parser options and edit your current profile (might need to create a clone of it, if it's one of the built-in ones) and add the `misc` dir as part of your search path.
1. Also in your parser profile properties, make note of a directory that looks something like `C:\Users\knutaf\AppData\Roaming\Microsoft\Network Monitor 3\5E0BBCD3-BB76-444D-815C-40299B3FF858`. In that folder, edit `my_sparsers.npl` and add the following line to it:  
`include "mungetls.npl"`


## Code reading suggestions

Read the RFCs:
[TLS 1.0](http://www.ietf.org/rfc/rfc2246.txt)
[TLS 1.2](http://www.ietf.org/rfc/rfc5246.txt)

Start with `inc\MungeTLS.h`. The entrypoint is in `exe\main.cpp`. Read `lib\MungeTLS.cpp` and spiral outwards as needed. All platform specific code is in `plat_lib_windows\` and `exe\`.
