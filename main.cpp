#include <windows.h>
#include <atlbase.h>
#include <stdio.h>
#include <stdlib.h>
#include "MungeTLS.h"


using namespace std;
using namespace MungeTLS;

HRESULT ProcessConnections();

int __cdecl wmain(int argc, wchar_t* argv[])
{
    HRESULT hr = S_OK;

    hr = ProcessConnections();

    return hr;
}

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
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
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

    /*
    char szMsg[] = "testing\r\n";
    if (send(sockAccept, szMsg, ARRAYSIZE(szMsg), 0) <= 0)
    {
        wprintf(L"err in write: %d\n", errno);
    }
    */

    {
        char c = 0;
        MT_TLSPlaintext message;
        vector<BYTE> vbData;
        int cch = recv(sockAccept, &c, 1, 0);
        while (cch > 0)
        {
            printf("read %d chars. got char: %01LX\n", cch, c);
            vbData.push_back(c);

            HRESULT hr = ParseMessage(&vbData.front(), vbData.size());
            if (hr == S_OK)
            {
                printf("finished parsing message\n");
                vbData.clear();
            }

            cch = recv(sockAccept, &c, 1, 0);
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
