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
#include <iostream>
#include <functional>

#include <Ntddndis.h>

#include <nmapi.h>

using namespace std;

void Usage()
{
    printf("Usage: munge2netmon.exe directory\n");
}

HRESULT
ForEachFileInDirectory(
    PCWSTR wszDir,
    function<HRESULT (const WIN32_FIND_DATAW*)> fnBody
)
{
    HRESULT hr = S_OK;

    WIN32_FIND_DATAW findData = {0};
    HANDLE hFind = FindFirstFileW(wszDir, &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    while (hr == S_OK)
    {
        // only process files
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            wprintf(L"file: %s\n", findData.cFileName);

            fnBody(&findData);
        }

        if (!FindNextFile(hFind, &findData))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }

error:
    if (hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
    }

    return hr;
} // end function ForEachFileInDirectory

HRESULT GetFileContents(PCWSTR wszFilename, vector<BYTE>* pvbContents)
{
    wprintf(L"path: %s\n", wszFilename);
    return S_OK;
} // end function GetFileContents

HRESULT ConvertTrafficFiles(PCWSTR wszDir)
{
    DWORD dwError = ERROR_SUCCESS;
    HRESULT hr = S_OK;

    wstring wsFilespec(wszDir);
    wsFilespec += L"\\*";

    HANDLE hCaptureFile = NULL;
    ULONG cbReturnSize = 0;

    dwError = NmCreateCaptureFile(
                  L"cap.cap",
                  5000000,
                  0,
                  &hCaptureFile,
                  &cbReturnSize);

    if (dwError != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(dwError);
        goto error;
    }

    ForEachFileInDirectory(wsFilespec.c_str(),
    [&wszDir, &hCaptureFile]
    (const WIN32_FIND_DATAW* pFindData) -> HRESULT
    {
        HRESULT hr = S_OK;

        wstring wsFilePath(wszDir);
        wsFilePath += L"\\";
        wsFilePath += pFindData->cFileName;

        vector<BYTE> vbFrame;

        hr = GetFileContents(wsFilePath.c_str(), &vbFrame);
        return hr;
    });

error:
    if (hCaptureFile != NULL)
    {
        NmCloseHandle(hCaptureFile);
        hCaptureFile = NULL;
    }

    return hr;
} // end function ConvertTrafficFiles

int __cdecl wmain(int argc, wchar_t* argv[])
{
    if (argc > 1)
    {
        ConvertTrafficFiles(argv[1]);
    }
    else
    {
        Usage();
    }

    return 0;
}
