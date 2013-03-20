#include "precomp.h"
#include <windows.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <strsafe.h>
#include "main.h"
#include "mtls_plat_windows.h"
#include "MungeTLS.h"
#include "mtls_helper.h"


using namespace std;
using namespace MungeTLS;

/*
** Some of this is taken with little modification from an MSDN sockets sample,
** so the coding style differs a little from all the other code in the project.
*/
int __cdecl wmain(_In_ int argc, _In_reads_(argc) wchar_t* argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    HRESULT hr = S_OK;

    SOCKET sockListen = INVALID_SOCKET;

    //----------------------
    // Initialize Winsock.

    WSADATA wsaData = {0};
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR)
    {
        wprintf(L"Error at WSAStartup(): %d\n", iResult);
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

    if (bind(
          sockListen,
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

    // keep accepting connections one after another
    for(;;)
    {
        //----------------------
        // Create a SOCKET for accepting incoming requests.
        wprintf(L"Waiting for client to connect...\n");
        SOCKET sockAccept = accept( sockListen, NULL, NULL );

        if (sockAccept == INVALID_SOCKET)
        {
            hr = HRESULT_FROM_WIN32(WSAGetLastError());
            wprintf(L"accept failed: %08LX\n", hr);
            goto error;
        }

        {
            /*
            ** this simple web server is attached to the TLS connection and
            ** implements all its callbacks
            */
            SimpleHTTPServer server(sockAccept);
            hr = server.ProcessConnection();
            if (hr != S_OK)
            {
                wprintf(L"warning: failed in ProcessConnection: %08LX\n", hr);
            }
        }

        if (sockAccept != INVALID_SOCKET)
        {
            closesocket(sockAccept);
            sockAccept = INVALID_SOCKET;
        }
    }

done:
    if (sockListen != INVALID_SOCKET)
    {
        closesocket(sockListen);
        sockListen = INVALID_SOCKET;
    }

    WSACleanup();

    return hr;

error:
    goto done;
}

template <typename N>
_Check_return_
wstring
StringFromInt(
    _In_ N n)
{
    wstringstream s;
    s << n;
    return s.str();
} // end function StringFromInt

/*
** log traffic with a specific format that makes it suitable for parsing by
** the "munge2netmon" companion tool, which can take the raw traffic and turn
** it into a netmon capture, which can be viewed for debugging goodness
*/
HRESULT
LogTraffic(
    _In_ ULONG nFile,
    _In_ const wstring* pwsSuffix,
    _In_ const ByteVector* pvb)
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
    wsFilename += L"_";

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

        CHKWIN(WriteFile(
                 hOutfile,
                 &pvb->front(),
                 static_cast<DWORD>(pvb->size()),
                 &cbWritten,
                 NULL));

        if (cbWritten != pvb->size())
        {
            wprintf(L"only wrote %u bytes of %Iu\n", cbWritten, pvb->size());
            hr = E_FAIL;
            goto error;
        }

        wprintf(L"logged %u bytes of traffic '%s' to %s\n", cbWritten, pwsSuffix->c_str(), wsFilename.c_str());
    }
    else
    {
        hr = HRESULT_FROM_WIN32(GetLastError());

        static bool fWarnedAboutLogFile = false;

        if (!fWarnedAboutLogFile)
        {
            wprintf(L"warning: failed to create traffic log file: %s (%08LX)\n", wsFilename.c_str(), hr);
            fWarnedAboutLogFile = true;
        }
        goto error;
    }

done:
    if (hOutfile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hOutfile);
        hOutfile = INVALID_HANDLE_VALUE;
    }

    return hr;

error:
    goto done;
} // end function LogTraffic

/*
** expects a TCP connection to have already been established, and processes all
** data on it.
*/
HRESULT SimpleHTTPServer::ProcessConnection()
{
    const size_t c_cbReadBuffer = 5000;
    const size_t c_cbMaxRecvSize = 5000;

    C_ASSERT(c_cbMaxRecvSize <= c_cbReadBuffer);

    ByteVector vbData;
    size_t cbConsumedBuffer = 0;
    int cb;
    int cbAvailable;
    MTERR mr = MT_S_OK;
    HRESULT hr = S_OK;

    CHKOK(GetConnection()->Initialize());

    vbData.reserve(c_cbReadBuffer);
    ResizeVector(&vbData, c_cbReadBuffer);

    CHKWINOKM(SizeTToInt32(vbData.size() - cbConsumedBuffer, &cbAvailable));

    // even if our buffer size is bigger, limit how much we receive
    if (cbAvailable > c_cbMaxRecvSize)
    {
        cbAvailable = c_cbMaxRecvSize;
    }

    // start reading at the next valid spot in the buffer
    cb = recv(
             *GetSockClient(),
             reinterpret_cast<char*>(&vbData.front() + cbConsumedBuffer),
             cbAvailable,
             0);

    // cb < 0 means failure. cb == 0 means end of stream
    while (cb > 0)
    {
        wprintf(L"read %d bytes from the network\n", cb);

        assert(static_cast<ULONG>(cb) <= vbData.size());
        cbConsumedBuffer += cb;
        assert(cbConsumedBuffer <= vbData.size());
        ResizeVector(&vbData, cbConsumedBuffer);

        // keep processing messages until we can't anymore
        hr = GetConnection()->HandleMessage(&vbData);
        while (hr == S_OK)
        {
            /*
            ** HandleMessage reenters SimpleHTTPServer in callbacks, which can
            ** result in queuing up traffic to send. check right now and
            ** send any pending traffic
            */
            while (!GetPendingSends()->empty())
            {
                ByteVector vb(GetPendingSends()->front());
                size_t cbPayload = vb.size();

                GetPendingSends()->erase(GetPendingSends()->begin());

                wprintf(L"responding with %Iu bytes\n", cbPayload);

                // this loop sends the whole buffer, in pieces
                while (cbPayload != 0)
                {
                    assert(cbPayload == vb.size());

                    assert(cbPayload <= INT_MAX);

                    cb = send(*GetSockClient(),
                              reinterpret_cast<char*>(&vb.front()),
                              static_cast<int>(cbPayload),
                              0);

                    if (cb == SOCKET_ERROR)
                    {
                        hr = HRESULT_FROM_WIN32(WSAGetLastError());
                        wprintf(L"failed in send(): %08LX\n", hr);
                        break;
                    }

                    wprintf(L"sent %d bytes\n", cb);

                    assert(cb >= 0);
                    assert(static_cast<ULONG>(cb) <= cbPayload);

                    cbPayload -= cb;
                    vb.erase(
                        vb.begin(),
                        vb.begin() + cb);
                }

                if (hr == S_OK)
                {
                    assert(vb.empty());
                }
                else
                {
                    wprintf(L"something failed (%08LX). exiting\n", hr);
                    break;
                }
            }

            hr = GetConnection()->HandleMessage(&vbData);
        }

        wprintf(L"failed HandleMessage (possibly expected): %08LX\n", hr);

        // flush logging messages
        _fflush_nolock(stdout);

        if (FAILED(hr))
        {
            goto error;
        }

        assert(vbData.size() <= c_cbReadBuffer);

        /*
        ** SUCCEEDED instead of S_OK because HandleMessage returns S_FALSE
        ** if it handles an empty message
        */
        assert(SUCCEEDED(hr));
        hr = S_OK;

        /*
        ** HandleMessage, if it succeeds, resizes vector, so update our
        ** current knowledge of the consumed size of the vector, then
        ** inflate it to the buffer size
        */
        cbConsumedBuffer = vbData.size();
        ResizeVector(&vbData, c_cbReadBuffer);

        CHKWINOKM(SizeTToInt32(vbData.size() - cbConsumedBuffer, &cbAvailable));

        // even if our buffer size is bigger, limit how much we receive
        if (cbAvailable > c_cbMaxRecvSize)
        {
            cbAvailable = c_cbMaxRecvSize;
        }

        // again, start reading at latest unused spot in buffer
        cb = recv(
                 *GetSockClient(),
                 reinterpret_cast<char*>(&vbData.front() + cbConsumedBuffer),
                 cbAvailable,
                 0);
    }

    if (cb < 0)
    {
        wprintf(L"failed on recv: cb=%d, err=%08LX\n", cb, WSAGetLastError());
        goto error;
    }

    wprintf(L"done reading: %d\n", errno);

done:
    return mr;

error:
    goto done;
} // end function ProcessConnection

_Use_decl_annotations_
HRESULT SimpleHTTPServer::EnqueueSendApplicationData(const ByteVector* pvb)
{
    static const size_t cbChunkSize = 50;
    MTERR mr = MT_S_OK;

    auto iter = pvb->begin();
    while (iter < pvb->end())
    {
        ByteVector vbChunk;
        size_t cbRemaining = pvb->end() - iter;
        size_t cbNextChunk = cbChunkSize;
        if (cbNextChunk > cbRemaining)
        {
            cbNextChunk = cbRemaining;
        }

        vbChunk.assign(iter, iter + cbNextChunk);
        assert(vbChunk.size() <= cbChunkSize);
        assert(vbChunk.size() <= cbRemaining);
        assert(vbChunk.size() > 0);

        CHKOK(GetConnection()->EnqueueSendApplicationData(&vbChunk));

        // ensure we make progress
        assert(cbNextChunk > 0);
        iter += cbNextChunk;
        assert(iter <= pvb->end());
    }

done:
    return MR2HR(mr);

error:
    goto done;
} // end function EnqueueSendApplicationData

// called when the TLS connection has some bytes to be sent over the network
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnSend(const ByteVector* pvb)
{
    wprintf(L"queueing up %Iu bytes of data to send\n", pvb->size());
    GetPendingSends()->push_back(*pvb);
    return MT_S_OK;
} // end function OnSend

// pvb is the plaintext application data that's been received
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnReceivedApplicationData(const ByteVector* pvb)
{
    MTERR mr = MT_S_OK;
    HRESULT hr = S_OK;

    wprintf(L"got %Iu bytes of application data\n", pvb->size());

    // sometimes the other party sends us empty messages. ok. just ignore them.
    if (!pvb->empty())
    {
        // first just append the new data to the pending incoming HTTP request
        GetPendingRequest()->insert(
            GetPendingRequest()->end(),
            pvb->begin(),
            pvb->end());

        // NB: sorted by length
        static const PCSTR c_rgszHTTPHeadersTerminators[] =
        {
            "\r\n\r\n",
            "\r\r",
            "\n\n"
        };

        /*
        ** try all the terminators to see if the request is complete. this is
        ** simplistic because it doesn't handle things like content-length in
        ** the request, so the client can't send any request body
        */

        // iterator to search for end of request headers
        string::iterator itEndRequest(GetPendingRequest()->begin());

        for (ULONG i = 0; i < ARRAYSIZE(c_rgszHTTPHeadersTerminators); i++)
        {
            // find the end terminator
            string::size_type posEndRequest = GetPendingRequest()->find(c_rgszHTTPHeadersTerminators[i]);

            /*
            ** found terminator. posEndRequest is the index of the first char
            ** of the terminator string
            */
            if (posEndRequest != string::npos)
            {
                /*
                ** if it's found, set an iterator for the spot 1 past the end
                ** of the terminating string.
                */
                itEndRequest = GetPendingRequest()->begin() + posEndRequest + strlen(c_rgszHTTPHeadersTerminators[i]);
                break;
            }
        }

        /*
        ** this simple web server echoes back the request headers in the
        ** response body. if we've found a non-empty request at this point--
        ** i.e. the previous search for a terminator succeeded--construct and
        ** send the response now.
        */
        if (itEndRequest - GetPendingRequest()->begin() > 0)
        {
            ByteVector vbApplicationData;

            const CHAR szApplicationDataTemplate[] =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %d\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: Keep-Alive\r\n"
                "\r\n";

            /*
            ** reserve (more than) enough space, and trim down later. the *2
            ** is the generous part of the size, and accounts for the content
            ** length in the string above. it is really *very* generous.
            **
            ** we don't resize() at this point, because that would change
            ** begin(), end(), etc.. those will get updated as we insert/append
            */
            vbApplicationData.reserve(
                ARRAYSIZE(szApplicationDataTemplate) * 2 +
                (itEndRequest - GetPendingRequest()->begin()));

            // first get enough space for just the template part
            ResizeVector(&vbApplicationData, ARRAYSIZE(szApplicationDataTemplate) * 2);

            // substituting in the real content length
            CHKWINOKM(StringCchPrintfA(
                          reinterpret_cast<PSTR>(&vbApplicationData.front()),
                          vbApplicationData.size(),
                          szApplicationDataTemplate,
                          itEndRequest - GetPendingRequest()->begin()));

            // trim to just the part we sprintf'd. excludes null terminator
            ResizeVector(&vbApplicationData, strlen(reinterpret_cast<PSTR>(&vbApplicationData.front())));

            // append the request
            vbApplicationData.insert(
                vbApplicationData.end(),
                GetPendingRequest()->begin(),
                itEndRequest);

            // erase just the portion we inserted
            GetPendingRequest()->erase(
                GetPendingRequest()->begin(),
                itEndRequest);

            m_cRequestsReceived++;

            /*
            ** if we reach this point, we have received a request and prepared
            ** a response to send. however, since this is a test server, on the
            ** second and subsequent requests we receive, first do a
            ** renegotiation, THEN send the response. hee hee
            **
            ** the renegotiation process is not synchronous right here, so we
            ** have to save off that response and send it after it's indicated
            ** that the handshake is complete (OnHandshakeComplete).
            */
            if (m_cRequestsReceived > 1)
            {
                CHKOK(GetConnection()->EnqueueStartRenegotiation());

                CHKOK(SetPendingResponse(vbApplicationData));
            }

            // on first response, just send it now. no fancy tricks
            else
            {
                CHKWINOKM(EnqueueSendApplicationData(&vbApplicationData));
            }

            // this would send any appdata OR renegotiation request
            CHKOK(GetConnection()->SendQueuedMessages());
        }
        else
        {
            // if this ever fails, need to hoist the above SendQueuedMessages
            assert(GetConnection()->GetPendingSends()->empty());
        }

        printf("pending request is: %s\n", GetPendingRequest()->c_str());
    }

done:
    return mr;

error:
    goto done;
} // end function OnReceivedApplicationData

/*
** called during handshake to choose the protocol version to use in ServerHello
** default is to use ClientHello.version
*/
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion)
{
    UNREFERENCED_PARAMETER(pProtocolVersion);
    return MT_S_LISTENER_IGNORED;
} // end function OnSelectProtocolVersion

/*
** called during handshake to pick the cipher suite to send in the ServerHello.
** the default is to take a hard-coded server preference that the client also
** advertises.
**
** this client implementation helps testing renegotation by choosing a
** different cipher suite round-robin from a list of choices.
*/
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnSelectCipherSuite(const MT_ClientHello* pClientHello, MT_CipherSuite* pCipherSuite)
{
    // negotiations will cycle through this list. "unknown" means use default
    static const MT_CipherSuiteValue c_rgCipherSuites[] =
    {
        //MTCS_UNKNOWN,
        MTCS_TLS_RSA_WITH_AES_128_CBC_SHA
        ,MTCS_TLS_RSA_WITH_RC4_128_SHA
        //,MTCS_TLS_RSA_WITH_AES_256_CBC_SHA
        //,MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256
        //,MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256
    };

    MTERR mr = MT_S_LISTENER_IGNORED;

    UNREFERENCED_PARAMETER(pClientHello);

    MT_CipherSuiteValue csv = c_rgCipherSuites[m_iCipherSelected];

    if (csv != MTCS_UNKNOWN)
    {
        CHKOK(pCipherSuite->SetValue(csv));
        mr = MT_S_LISTENER_HANDLED;
    }

    m_iCipherSelected = (m_iCipherSelected + 1) % ARRAYSIZE(c_rgCipherSuites);

done:
    return mr;

error:
    goto done;
} // end function OnSelectCipherSuite

/*
** called when initializing the cryptographic objects needed for a new
** handshake. for this simple server, we need to fetch the certificate chain
** and configure the public key cipherer with the certificate private key. on
** other platforms they may also need to configure the symmetric cipherers or
** hasher.
**
** for now we have a hard-coded certificate name. Note that LookupCertificate
** is Windows-specific code, but that's okay, because it's contained in the
** application (rather than lib) portion.
*/
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnInitializeCrypto(
    MT_CertificateList* pCertChain,
    shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
    shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
    shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
    shared_ptr<Hasher>* pspClientHasher,
    shared_ptr<Hasher>* pspServerHasher
)
{
    MTERR mr = MT_S_OK;
    HRESULT hr = S_OK;
    PCCERT_CHAIN_CONTEXT pCertChainCtx = nullptr;
    shared_ptr<WindowsPublicKeyCipherer> spPubKeyCipherer;
    shared_ptr<WindowsSymmetricCipherer> spClientSymCipherer;
    shared_ptr<WindowsSymmetricCipherer> spServerSymCipherer;
    shared_ptr<WindowsHasher> spClientHasher;
    shared_ptr<WindowsHasher> spServerHasher;

    CHKWINOKM(LookupCertificate(
                  CERT_SYSTEM_STORE_CURRENT_USER,
                  L"my",
                  L"mtls-test",
                  &pCertChainCtx));

    spPubKeyCipherer = shared_ptr<WindowsPublicKeyCipherer>(new WindowsPublicKeyCipherer());

    /*
    ** the root cert context in the chain. it knows how to lookup the private
    ** key from this.
    */
    CHKOK(spPubKeyCipherer->Initialize(pCertChainCtx->rgpChain[0]->rgpElement[0]->pCertContext));

    spClientSymCipherer = shared_ptr<WindowsSymmetricCipherer>(new WindowsSymmetricCipherer());
    spServerSymCipherer = shared_ptr<WindowsSymmetricCipherer>(new WindowsSymmetricCipherer());

    spClientHasher = shared_ptr<WindowsHasher>(new WindowsHasher());
    spServerHasher = shared_ptr<WindowsHasher>(new WindowsHasher());

    // convert to internal MT_CertificateList
    CHKWINOKM(MTCertChainFromWinChain(pCertChainCtx, pCertChain));

    *pspPubKeyCipherer = spPubKeyCipherer;
    *pspClientSymCipherer = spClientSymCipherer;
    *pspServerSymCipherer = spServerSymCipherer;
    *pspClientHasher = spClientHasher;
    *pspServerHasher = spServerHasher;

done:
    if (pCertChainCtx)
    {
        CertFreeCertificateChain(pCertChainCtx);
        pCertChainCtx = nullptr;
    }

    return mr;

error:
    goto done;
} // end function OnInitializeCrypto

/*
** called when creating each handshake message for sending. we could package
** each message in a separate record layer message, or combine several into the
** same record layer message, since they're all of the same content type
** default is to do separate records
*/
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnCreatingHandshakeMessage(MT_Handshake* pHandshake, MT_UINT32* pfFlags)
{
    UNREFERENCED_PARAMETER(pHandshake);
    //*pfFlags |= MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE;
    *pfFlags |= MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE;
    return MT_S_LISTENER_HANDLED;
} // end function OnCreatingHandshakeMessage

/*
** called whenever the server has readied a plaintext message for the purpose
** of being sent, either in its plaintext form or after conversion to
** ciphertext. this is primarily used for logging traffic
*/
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnEnqueuePlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted)
{
    MTERR mr = MT_S_OK;
    ByteVector vb;
    wstring wsLogPrefix(L"w");

    CHKOK(pPlaintext->SerializeToVect(&vb));

    if (fActuallyEncrypted)
    {
        wsLogPrefix += L"_c";
    }

    LogTraffic(m_cMessages, &wsLogPrefix, &vb);
    m_cMessages++;

done:
    return mr;

error:
    // debugger break when I've forgotten to implement serialization for struct
    assert(mr != MT_E_NOTIMPL);
    goto done;
} // end function OnEnqueuePlaintext

// the "receiving" equivalent of OnEnqueuePlaintext. primarily used for logging
_Use_decl_annotations_
MTERR_T SimpleHTTPServer::OnReceivingPlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted)
{
    MTERR mr = MT_S_OK;
    ByteVector vb;
    wstring wsLogPrefix(L"r");

    CHKOK(pPlaintext->SerializeToVect(&vb));

    if (fActuallyEncrypted)
    {
        wsLogPrefix += L"_c";
    }

    LogTraffic(m_cMessages, &wsLogPrefix, &vb);
    m_cMessages++;

done:
    // debugger break when I've forgotten to implement serialization for struct
    assert(mr != MT_E_NOTIMPL);
    return mr;

error:
    goto done;
} // end function OnReceivingPlaintext

/*
** notifies the application that a handshake is complete, and it's safe to send
** application data. here we send the data we saved off back in
** OnReceivedApplicationData before the renegotiation.
*/
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnHandshakeComplete()
{
    MTERR mr = MT_S_OK;

    if (!GetPendingResponse()->empty())
    {
        CHKOK(EnqueueSendApplicationData(GetPendingResponse()));

        GetPendingResponse()->clear();
    }

    mr = MT_S_LISTENER_HANDLED;

done:
    return mr;

error:
    goto done;
} // end function OnHandshakeComplete

/*
** if we ever encounter a record with a different version specified than the
** currently negotiated version, the application has a chance to reconcile it
** and choose the version that's used for "security" operations like MAC
** computation.
**
** In particular, many browsers handle version negotiation differently. we
** always set to whatever higher version was previously negotiated if the
** versions differ
*/
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnReconcileSecurityVersion(
    const MT_TLSCiphertext* pCiphertext,
    MT_ProtocolVersion::MTPV_Version connVersion,
    MT_ProtocolVersion::MTPV_Version recordVersion,
    MT_ProtocolVersion::MTPV_Version* pOverrideVersion)
{
    UNREFERENCED_PARAMETER(pCiphertext);

    // detecting openssl bug and working around. could also have sniffed UA str
    if ((connVersion == MT_ProtocolVersion::MTPV_TLS11 ||
         connVersion == MT_ProtocolVersion::MTPV_TLS12) &&
        recordVersion == MT_ProtocolVersion::MTPV_TLS10)
    {
        *pOverrideVersion = connVersion;
        return MT_S_LISTENER_HANDLED;
    }

    return MT_S_LISTENER_IGNORED;
} // end function OnReconcileSecurityVersion
