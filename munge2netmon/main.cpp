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
#include <regex>

#include <Ntddndis.h>

#include <nmapi.h>

using namespace std;

const NDIS_MEDIUM MediumMungeTLS = static_cast<NDIS_MEDIUM>(0x2323);
static const wregex c_rxRead(L".*_r_.*");
static const wregex c_rxWrite(L".*_w_.*");
static const wregex c_rxEncrypted(L".*_c_.*");

const BYTE c_bFlags_Receive = 0x0;
const BYTE c_bFlags_Send = 0x1;
const BYTE c_bFlags_Encrypted = 0x2;

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
    HRESULT hr = S_OK;
    DWORD cbRead = 0;

    HANDLE hFile = CreateFileW(
                       wszFilename,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL |
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    pvbContents->clear();
    pvbContents->resize(cbFileSize, 0x23);

    if (!ReadFile(
             hFile,
             &(pvbContents->front()),
             static_cast<DWORD>(pvbContents->size()),
             &cbRead,
             NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    if (cbRead != pvbContents->size())
    {
        wprintf(L"only read %lu bytes out of %lu\n", cbRead, pvbContents->size());
        hr = E_FAIL;
        goto error;
    }

    wprintf(L"read %lu bytes from %s\n", pvbContents->size(), wszFilename);

error:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

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

        if (regex_match(wsFilePath, c_rxRead))
        {
            bFrameFlags |= c_bFlags_Receive;
        }
        else if (regex_match(wsFilePath, c_rxWrite))
        {
            bFrameFlags |= c_bFlags_Send;
        }
        else
        {
            assert(false);
        }

        if (regex_match(wsFilePath, c_rxEncrypted))
        {
            bFrameFlags |= c_bFlags_Encrypted;
        }

        wprintf(L"flags: %02X\n", bFrameFlags);

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
