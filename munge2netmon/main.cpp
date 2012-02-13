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
#include <fstream>
#include <assert.h>

#include <Ntddndis.h>

#include <nmapi.h>

const NDIS_MEDIUM MediumMungeTLS = static_cast<NDIS_MEDIUM>(0x2323);

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

HRESULT GetFileContents(PCWSTR wszFilename, DWORD cbFileSize, vector<BYTE>* pvbContents)
{
    ifstream infile(wszFilename);

    if (infile.bad())
    {
        wprintf(L"couldn't open %s\n", wszFilename);
        goto error;
    }

    pvbContents->reserve(cbFileSize);
    while (!infile.bad() && cbFileSize > 0)
    {
        char c = static_cast<char>(infile.get());
        if (infile.eof())
        {
            break;
        }

        pvbContents->push_back(c);
    }

error:
    return S_OK;
} // end function GetFileContents

HRESULT ConvertTrafficFiles(PCWSTR wszDir)
{
    DWORD dwError = ERROR_SUCCESS;
    HRESULT hr = S_OK;
    ULONG nFile = 0;

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
    [&wszDir, &nFile, &hCaptureFile]
    (const WIN32_FIND_DATAW* pFindData) -> HRESULT
    {
        HRESULT hr = S_OK;
        DWORD dwError = ERROR_SUCCESS;
        wstring wsFilePath(wszDir);
        vector<BYTE> vbFrame;
        HANDLE hFrame = NULL;
        BYTE bFrameFlags = 0;

        if (pFindData->nFileSizeHigh != 0)
        {
            wprintf(L"large files not supported\n");
            hr = S_FALSE;
            goto error;
        }

        wsFilePath += L"\\";
        wsFilePath += pFindData->cFileName;

        hr = GetFileContents(wsFilePath.c_str(), pFindData->nFileSizeLow, &vbFrame);

        if (wsFilePath.back() == L'r')
        {
            bFrameFlags = 0;
        }
        else if (wsFilePath.back() == L'w')
        {
            bFrameFlags = 1;
        }
        else
        {
            assert(false);
        }

        vbFrame.insert(vbFrame.begin(), bFrameFlags);

        dwError = NmBuildRawFrameFromBuffer(
                      &vbFrame.front(),
                      static_cast<ULONG>(vbFrame.size()),
                      MediumMungeTLS,
                      nFile,
                      &hFrame);

        if (dwError != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(dwError);
            wprintf(L"failed to create frame: %08LX\n", hr);
            goto error;
        }

        dwError = NmAddFrame(hCaptureFile, hFrame);
        if (dwError != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(dwError);
            wprintf(L"failed to add frame: %08LX\n", hr);
            goto error;
        }

        nFile++;

error:
        if (hFrame != NULL)
        {
            NmCloseHandle(hFrame);
            hFrame = NULL;
        }

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
