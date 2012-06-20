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
#include <strsafe.h>
#include "main.h"
#include "MungeTLS.h"
#include "MungeWinHelpers.h"


using namespace std;
using namespace MungeTLS;

HRESULT ProcessConnections();

int __cdecl wmain(int argc, wchar_t* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    HRESULT hr = S_OK;

    DummyServer ds;

    hr = ds.ProcessConnections();

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

HRESULT DummyServer::ProcessConnections()
{
    HRESULT hr = S_OK;
    SOCKET sockListen = INVALID_SOCKET;
    SOCKET sockAccept = INVALID_SOCKET;
    PCCERT_CHAIN_CONTEXT pCertChain = nullptr;

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
        const size_t c_cbReadBuffer = 5000;
        const size_t c_cbMaxRecvSize = 5000;

        assert(c_cbMaxRecvSize <= c_cbReadBuffer);

        ByteVector vbData;
        size_t cbConsumedBuffer = 0;
        int cb;
        int cbAvailable;
        HRESULT hr = S_OK;
        ULONG cMessages = 0;

        hr = LookupCertificate(
                 CERT_SYSTEM_STORE_CURRENT_USER,
                 L"my",
                 L"mtls-test",
                 &pCertChain);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = Connection()->Initialize(pCertChain);
        if (hr != S_OK)
        {
            goto error;
        }

        vbData.reserve(c_cbReadBuffer);
        vbData.resize(c_cbReadBuffer);

        hr = SizeTToInt32(vbData.size() - cbConsumedBuffer, &cbAvailable);
        if (hr != S_OK)
        {
            goto error;
        }

        if (cbAvailable > c_cbMaxRecvSize)
        {
            cbAvailable = c_cbMaxRecvSize;
        }

        cb = recv(
                 sockAccept,
                 reinterpret_cast<char*>(&vbData.front() + cbConsumedBuffer),
                 cbAvailable,
                 0);

        while (cb > 0)
        {
            printf("read %d bytes from the network\n", cb);

            assert(cb <= vbData.size());
            cbConsumedBuffer += cb;
            assert(cbConsumedBuffer <= vbData.size());
            vbData.resize(cbConsumedBuffer);

            LogRead(cMessages, &vbData);

            hr = Connection()->HandleMessage(&vbData);
            while (hr == S_OK)
            {
                printf("finished parsing message of size %lu\n", vbData.size());
                cMessages++;

                if (!PendingSends()->empty())
                {
                    size_t cbPayload = PendingSends()->size();

                    printf("responding with %d bytes\n", cbPayload);

                    while (cbPayload != 0)
                    {
                        assert(cbPayload == PendingSends()->size());

                        LogWrite(cMessages, PendingSends());
                        cMessages++;

                        assert(cbPayload <= INT_MAX);

                        cb = send(sockAccept,
                                  reinterpret_cast<char*>(&PendingSends()->front()),
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
                        PendingSends()->erase(
                            PendingSends()->begin(),
                            PendingSends()->begin() + cb);
                    }

                    if (hr == S_OK)
                    {
                        assert(PendingSends()->empty());
                    }
                    else
                    {
                        printf("something failed (%08LX). exiting\n", hr);
                        break;
                    }
                }

                hr = Connection()->HandleMessage(&vbData);
            }

            printf("failed HandleMessage (possibly expected): %08LX\n", hr);

            _fflush_nolock(stdout);

            assert(vbData.size() <= c_cbReadBuffer);

            /*
            ** HandleMessage, if it succeeds, resizes vector, so update our
            ** current knowledge of the consumed size of the vector, then
            ** inflate it to the buffer size
            */
            cbConsumedBuffer = vbData.size();
            vbData.resize(c_cbReadBuffer);

            hr = SizeTToInt32(vbData.size() - cbConsumedBuffer, &cbAvailable);
            if (hr != S_OK)
            {
                printf("failed second SizeTToInt32. %lu - %lu\n", vbData.size(), cbConsumedBuffer);
                goto error;
            }

            if (cbAvailable > c_cbMaxRecvSize)
            {
                cbAvailable = c_cbMaxRecvSize;
            }

            cb = recv(
                     sockAccept,
                     reinterpret_cast<char*>(&vbData.front() + cbConsumedBuffer),
                     cbAvailable,
                     0);
        }

        if (cb < 0)
        {
            printf("failed on recv: cb=%d, err=%08LX\n", cb, WSAGetLastError());
            goto error;
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

    if (pCertChain != nullptr)
    {
        CertFreeCertificateChain(pCertChain);
        pCertChain = nullptr;
    }

    WSACleanup();

    return hr;
} // end function ProcessConnections

HRESULT DummyServer::OnSend(const ByteVector* pvb)
{
    wprintf(L"queueing up %d bytes of data to send\n", pvb->size());
    PendingSends()->insert(PendingSends()->end(), pvb->begin(), pvb->end());
    return S_OK;
} // end function OnSend

HRESULT DummyServer::OnApplicationData(const ByteVector* pvb)
{
    HRESULT hr = S_OK;

    wprintf(L"got %d bytes of application data\n", pvb->size());

    if (!pvb->empty())
    {
        // first just append the new data to the pending request
        PendingRequest()->insert(
            PendingRequest()->end(),
            pvb->begin(),
            pvb->end());

        // do this after the insert, which invalidates iterators
        string::iterator itEndRequest(PendingRequest()->begin());

        const PCSTR rgszTerminators[] =
        {
            "\r\n\r\n",
            "\r\r",
            "\n\n"
        };

        /*
        ** try all the terminators to see if the request is complete. this is
        ** simplistic because it doesn't handle things like content-length in
        ** the request.
        */
        for (ULONG i = 0; i < ARRAYSIZE(rgszTerminators); i++)
        {
            // find the end terminator
            string::size_type posEndRequest = PendingRequest()->find(rgszTerminators[i]);

            if (posEndRequest != string::npos)
            {
                /*
                ** if it's found, set an iterator for the spot 1 past the end
                ** of the terminating string.
                */
                itEndRequest = PendingRequest()->begin() + posEndRequest + strlen(rgszTerminators[i]);

                printf("found terminator %d\n", i);

                break;
            }
        }

        /*
        ** the response body is going to be a copy of the request body. do this
        ** only if a whole request is found at this point (non-empty request)
        */
        if (itEndRequest - PendingRequest()->begin() > 0)
        {
            ByteVector vbApplicationData;

            const CHAR szApplicationDataTemplate[] =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %d\r\n"
                "Content-Type: text/plain\r\n"
                "\r\n";

            /*
            ** reserve (more than) enough space, and trim down later. the *2
            ** is the generous part of the size, and accounts for the content
            ** length in the string above. it is really *very* generous.
            */
            vbApplicationData.reserve(
                ARRAYSIZE(szApplicationDataTemplate) * 2 +
                (itEndRequest - PendingRequest()->begin()));

            // first get enough space for just the template part
            vbApplicationData.resize(ARRAYSIZE(szApplicationDataTemplate) * 2);

            // substituting in the real content length
            hr = StringCchPrintfA(
                     reinterpret_cast<PSTR>(&vbApplicationData.front()),
                     vbApplicationData.size(),
                     szApplicationDataTemplate,
                     itEndRequest - PendingRequest()->begin());

            if (hr != S_OK)
            {
                goto error;
            }

            // trim to just the part we sprintf'd. excludes null terminator
            vbApplicationData.resize(strlen(reinterpret_cast<PSTR>(&vbApplicationData.front())));

            // append the request
            vbApplicationData.insert(
                vbApplicationData.end(),
                PendingRequest()->begin(),
                itEndRequest);

            // erase just the portion we inserted
            PendingRequest()->erase(
                PendingRequest()->begin(),
                itEndRequest);

            hr = Connection()->EnqueueSendApplicationData(&vbApplicationData);
            if (hr != S_OK)
            {
                goto error;
            }

            hr = Connection()->SendQueuedMessages();
            if (hr != S_OK)
            {
                goto error;
            }
        }

        printf("pending request is: %s\n", PendingRequest()->c_str());
    }

done:
    return hr;

error:
    goto done;
} // end function OnApplicationData
