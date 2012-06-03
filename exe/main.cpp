#include "precomp.h"
#include <windows.h>
#include <atlbase.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <vector>
#include "MungeTLS.h"


using namespace std;
using namespace MungeTLS;

HRESULT ProcessConnections();

int __cdecl wmain(int argc, wchar_t* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    HRESULT hr = S_OK;

    hr = ProcessConnections();

    return hr;
}

template <typename N>
wstring StringFromInt(N n)
{
    wstringstream s;
    s << n;
    return s.str();
} // end function StringFromInt

HRESULT LogTraffic(ULONG nFile, const wstring* pwsSuffix, const ByteVector* pvb)
{
    HRESULT hr = S_OK;
    wstring wsFilename(L"out\\");
    HANDLE hOutfile = INVALID_HANDLE_VALUE;

    for (ULONG i = nFile; i < 100; i *= 10)
    {
        if (i == 0)
        {
            i++;
        }

        wsFilename += L"0";
    }

    wsFilename += StringFromInt(nFile);
    wsFilename += L"_";
    wsFilename += *pwsSuffix;

    hOutfile = CreateFileW(
                   wsFilename.c_str(),
                   GENERIC_WRITE,
                   0,
                   NULL,
                   CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL);

    if (hOutfile != INVALID_HANDLE_VALUE)
    {
        DWORD cbWritten = 0;

        if (!WriteFile(
                 hOutfile,
                 &pvb->front(),
                 static_cast<DWORD>(pvb->size()),
                 &cbWritten,
                 NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        if (cbWritten != pvb->size())
        {
            wprintf(L"only wrote %lu bytes of %lu\n", cbWritten, pvb->size());
            hr = E_FAIL;
            goto error;
        }

        printf("logged %lu bytes of traffic '%s' to %s\n", cbWritten, pwsSuffix->c_str(), wsFilename.c_str());
    }
    else
    {
        printf("failed to create outfile: %s\n", wsFilename.c_str());
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

error:
    if (hOutfile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hOutfile);
        hOutfile = INVALID_HANDLE_VALUE;
    }

    return hr;
} // end function LogTraffic

HRESULT LogWrite(ULONG nFile, const ByteVector* pvb)
{
    static const wstring wsWrite(L"w");
    return LogTraffic(nFile, &wsWrite, pvb);
} // end function LogWrite

HRESULT LogRead(ULONG nFile, const ByteVector* pvb)
{
    static const wstring wsRead(L"r");
    return LogTraffic(nFile, &wsRead, pvb);
} // end function LogRead

HRESULT ProcessConnections()
{
    HRESULT hr = S_OK;
    SOCKET sockListen = INVALID_SOCKET;
    SOCKET sockAccept = INVALID_SOCKET;

    //----------------------
    // Initialize Winsock.

    WSADATA wsaData = {0};
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR)
    {
        wprintf(L"Error at WSAStartup(): %lu\n", iResult);
        hr = HRESULT_FROM_WIN32(iResult);
        goto error;
    }

    //----------------------
    // Create a SOCKET for listening for
    // incoming connection requests.
    sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockListen == INVALID_SOCKET)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"Error at socket(): %08LX\n", hr);
        goto error;
    }

    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = 0;
    service.sin_port = htons(8879);

    if (bind(sockListen,
                (SOCKADDR*) &service,
                sizeof(service)) == SOCKET_ERROR)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"bind() failed: %08LX\n", hr);
        goto error;
    }

    //----------------------
    // Listen for incoming connection requests.
    // on the created socket
    if (listen( sockListen, 1 ) == SOCKET_ERROR)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"Error listening on socket: %08LX\n", hr);
        goto error;
    }

    //----------------------
    // Create a SOCKET for accepting incoming requests.
    wprintf(L"Waiting for client to connect...\n");
    sockAccept = accept( sockListen, NULL, NULL );

    if (sockAccept == INVALID_SOCKET)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"accept failed: %08LX\n", hr);
        goto error;
    }

    // No longer need server socket
    closesocket(sockListen);
    sockListen = INVALID_SOCKET;

    wprintf(L"client connected with handle %d\n", sockAccept);

    {
        TLSConnection con;
        char c = 0;
        ByteVector vbData;
        ByteVector vbResponse;
        int cb;
        HRESULT hr = S_OK;
        ULONG cMessages = 0;

        hr = con.Initialize();
        if (hr != S_OK)
        {
            goto error;
        }

        cb = recv(sockAccept, &c, 1, 0);
        while (cb > 0)
        {
            printf("read %d chars. got char: %01X\n", cb, c);
            vbData.push_back(c);
            LogRead(cMessages, &vbData);

            hr = con.HandleMessage(&vbData.front(), vbData.size(), &vbResponse);
            if (hr == S_OK)
            {
                printf("finished parsing message of size %lu\n", vbData.size());
                cMessages++;
                vbData.clear();

                if (!vbResponse.empty())
                {
                    size_t cbPayload = vbResponse.size();

                    printf("responding with %d bytes\n", cbPayload);

                    while (cbPayload != 0)
                    {
                        assert(cbPayload == vbResponse.size());

                        LogWrite(cMessages, &vbResponse);
                        cMessages++;

                        assert(cbPayload <= INT_MAX);

                        cb = send(sockAccept,
                                  reinterpret_cast<char*>(&vbResponse.front()),
                                  static_cast<int>(cbPayload),
                                  0);

                        if (cb == SOCKET_ERROR)
                        {
                            hr = HRESULT_FROM_WIN32(WSAGetLastError());
                            printf("failed in send(): %08LX\n", hr);
                            break;
                        }

                        assert(cb >= 0);
                        assert(static_cast<ULONG>(cb) <= cbPayload);

                        cbPayload -= cb;
                        vbResponse.erase(
                            vbResponse.begin(),
                            vbResponse.begin() + cb);
                    }

                    if (hr == S_OK)
                    {
                        assert(vbResponse.empty());
                    }
                    else
                    {
                        printf("something failed. exiting\n");
                        break;
                    }
                }
            }
            else
            {
                printf("failed HandleMessage: %08LX\n", hr);
            }

            _fflush_nolock(stdout);

            cb = recv(sockAccept, &c, 1, 0);
        }
    }

    wprintf(L"done reading: %d", errno);

error:
    if (sockListen != INVALID_SOCKET)
    {
        closesocket(sockListen);
        sockListen = INVALID_SOCKET;
    }

    if (sockAccept != INVALID_SOCKET)
    {
        closesocket(sockAccept);
        sockAccept = INVALID_SOCKET;
    }

    WSACleanup();

    return hr;
}
