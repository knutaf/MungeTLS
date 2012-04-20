#define UNICODE 1
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <process.h>
#include <fcntl.h>
#include <errno.h>
#include <string>
#include <vector>
#include <urlmon.h>

using namespace std;

int __cdecl wmain(int argc, wchar_t* argv[])
{
    if (argc > 1)
    {
        HRESULT hr = S_OK;
        hr = URLDownloadToFile(
                 NULL,
                 argv[1],
                 argv[2],
                 0,
                 NULL);

        return hr;
    }
    else
    {
        wprintf(L"Usage: UrlDownloadToFile url file\n");
        return 1;
    }
}
