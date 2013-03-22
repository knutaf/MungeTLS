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

HRESULT
LogTraffic(
    _In_ ULONG nFile,
    _In_ const wstring* pwsSuffix,
    _In_ bool fActuallyEncrypted,
    _In_ const ByteVector* pvb);

template <typename N>
_Check_return_
wstring
StringFromInt(
    _In_ N n
);

void Usage();

int
__cdecl
wmain(
    _In_ int argc,
    _In_reads_(argc) wchar_t* argv[]
)
{
    HRESULT hr = S_OK;
    WORD wPort = 0;

    SOCKET sockListen = INVALID_SOCKET;

    if (argc > 2)
    {
        if (wcscmp(argv[1], L"-p") == 0)
        {
            DWORD dwPort = _wtoi(argv[2]);
            if (dwPort > 65535)
            {
                wprintf(L"invalid port number\n");
                goto error;
            }

            wPort = static_cast<WORD>(dwPort);
        }
        else
        {
            Usage();
            goto error;
        }
    }
    else
    {
        Usage();
        goto error;
    }

    {
        // standard winsock initialization
        WSADATA wsaData = {0};
        int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
        if (iResult != NO_ERROR)
        {
            wprintf(L"Error at WSAStartup(): %d\n", iResult);
            hr = HRESULT_FROM_WIN32(iResult);
            goto error;
        }
    }

    // TCP socket
    sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockListen == INVALID_SOCKET)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"Error at socket(): %08LX\n", hr);
        goto error;
    }

    // bind to port 8879
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = 0;
    service.sin_port = htons(wPort);

    if (bind(
          sockListen,
          (SOCKADDR*) &service,
          sizeof(service)) == SOCKET_ERROR)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"bind() failed: %08LX\n", hr);
        goto error;
    }

    if (listen( sockListen, 1 ) == SOCKET_ERROR)
    {
        hr = HRESULT_FROM_WIN32(WSAGetLastError());
        wprintf(L"Error listening on socket: %08LX\n", hr);
        goto error;
    }

    // keep accepting connections one after another
    for(;;)
    {
        // blocks until an incoming connection occurs
        wprintf(L"Waiting for client to connect on port %u...\n", wPort);
        SOCKET sockAccept = accept( sockListen, NULL, NULL );

        if (sockAccept == INVALID_SOCKET)
        {
            hr = HRESULT_FROM_WIN32(WSAGetLastError());
            wprintf(L"accept failed: %08LX\n", hr);
            goto error;
        }

        {
            //
            // this simple web server is attached to the TLS connection and
            // implements all its callbacks. ProcessConnection() blocks until
            // there is no more data in the socket or the connection is
            // otherwise closed (say, forcibly closed due to an error on this
            // side).
            //
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
} // end function wmain

//
// expects a TCP connection to have already been established, and processes all
// data on it. this is the main driver of MungeTLS. we do the network receives
// and send that data in to MungeTLS, which may hand us back some data to send
// back to the client. All of the MungeTLS logic happens within a HandleMessage
// call in this function.
//
HRESULT
SimpleHTTPServer::ProcessConnection()
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

    ResizeVector(&vbData, c_cbReadBuffer);
    CHKWINOKM(SizeTToInt32(vbData.size(), &cbAvailable));

    // prime the loop that reads data from the connection
    cb = recv(
             *GetSockClient(),
             reinterpret_cast<char*>(&vbData.front()),
             cbAvailable,
             0);

    // cb < 0 means failure. cb == 0 means end of stream
    while (cb > 0)
    {
        wprintf(L"read %d bytes from the network\n", cb);

        assert(static_cast<ULONG>(cb) <= vbData.size());
        cbConsumedBuffer += cb;
        assert(cbConsumedBuffer <= vbData.size());

        //
        // HandleMessage() will consume as much data as necessary to try to
        // parse a TLS message, so we set the vector size to the amount of
        // valid data we have, so that it won't try to read invalid data off
        // the end
        //
        ResizeVector(&vbData, cbConsumedBuffer);

        //
        // keep processing messages until we can't anymore. each HandleMessage
        // call will parse and handle a maximum of one message. If it fails to
        // parse any message, it returns some error
        //
        // if HandleMessage does consume some data, it erases it from the
        // vector, so that the next unused byte is always positioned at the
        // front
        //
        mr = GetConnection()->HandleMessage(&vbData);
        while (mr == MT_S_OK)
        {
            //
            // HandleMessage reenters SimpleHTTPServer in callbacks, which can
            // result in queuing up traffic to send. check right now and
            // send any pending traffic
            //
            while (!GetPendingSends()->empty())
            {
                // pull the first message off the front of the queued list
                ByteVector vb(GetPendingSends()->front());
                GetPendingSends()->erase(GetPendingSends()->begin());

                size_t cbPayload = vb.size();
                wprintf(L"responding with %Iu bytes\n", cbPayload);

                // this loop sends the whole buffer, in pieces
                while (cbPayload != 0)
                {
                    assert(cbPayload == vb.size());

                    int cbPayloadAsInt = 0;
                    CHKWINOKM(SizeTToInt32(cbPayload, &cbPayloadAsInt));

                    cb = send(
                             *GetSockClient(),
                             reinterpret_cast<char*>(&vb.front()),
                             cbPayloadAsInt,
                             0);

                    if (cb == SOCKET_ERROR)
                    {
                        hr = HRESULT_FROM_WIN32(WSAGetLastError());
                        wprintf(L"failed in send(): %08LX\n", hr);
                        goto error;
                    }

                    wprintf(L"sent %d bytes\n", cb);

                    assert(cb >= 0);
                    assert(static_cast<ULONG>(cb) <= cbPayload);

                    cbPayload -= cb;
                    vb.erase(
                        vb.begin(),
                        vb.begin() + cb);
                }

                // must be success or we would have jumped to :error
                assert(hr == S_OK);
            }

            mr = GetConnection()->HandleMessage(&vbData);
        }

        // could fail if there's not enough data for a full message
        wprintf(L"failed HandleMessage (possibly expected): %08LX\n", mr);

        // flush logging messages
        _fflush_nolock(stdout);

        if (MT_Failed(mr))
        {
            hr = MR2HR(mr);
            goto error;
        }

        //
        // HandleMessage, if it succeeds, resizes vector, so update our
        // current knowledge of the consumed size of the vector, then
        // inflate it to the buffer size
        //
        // remember that HandleMessage also erases consumed data from the
        // front, so the first byte is the next un-consumed data
        //
        assert(vbData.size() <= c_cbReadBuffer);
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
        hr = WSAGetLastError();
        wprintf(L"failed on recv: cb=%d, err=%08LX\n", cb, hr);
        goto error;
    }
    else
    {
        assert(cb == 0);
        wprintf(L"done reading: %d\n", errno);
    }

done:
    return hr;

error:
    goto done;
} // end function ProcessConnection

//
// called when the TLS connection has some bytes to be sent over the network.
// as with all the callbacks, this is called somewhere under HandleMessage,
// which we are calling in ProcessConnection.
//
// we queue up the data, and in ProcessConnection, we will look for any pending
// data to send after every HandleMessage call
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnSend(
    const ByteVector* pvb
)
{
    wprintf(L"queueing up %Iu bytes of data to send\n", pvb->size());
    GetPendingSends()->push_back(*pvb);
    return MT_S_OK;
} // end function OnSend

//
// called by MungeTLS when initializing the cryptographic objects needed for a
// new handshake, so this is one of the first callbacks we get. for this simple
// server, we need to fetch the certificate chain and configure the public key
// cipherer with the certificate's private key. on other platforms they may
// also need to configure the symmetric cipherers or hasher.
//
// for now we have a hard-coded certificate name. Note that LookupCertificate
// is Windows-specific code, but that's okay, because it's contained in the
// platform specific lib rather than the core MungeTLS engine.
//
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

    //
    // the root cert context in the chain is element 0 in the 0th chain.
    // WindowsPublicKeyCipherer knows how to lookup the private key from this.
    //
    CHKOK(spPubKeyCipherer->Initialize(pCertChainCtx->rgpChain[0]->rgpElement[0]->pCertContext));

    //
    // MungeTLS will configure the symmetric cipherers with a cipher type and
    // key once they are known, during the TLS handshake (by calling
    // SetCipherInfo)
    //
    spClientSymCipherer = shared_ptr<WindowsSymmetricCipherer>(new WindowsSymmetricCipherer());
    spServerSymCipherer = shared_ptr<WindowsSymmetricCipherer>(new WindowsSymmetricCipherer());

    // on Windows, Hashers are stateless objects
    spClientHasher = shared_ptr<WindowsHasher>(new WindowsHasher());
    spServerHasher = shared_ptr<WindowsHasher>(new WindowsHasher());

    // convert to internal MT_CertificateList
    CHKWINOKM(MTCertChainFromWinCertChain(pCertChainCtx, pCertChain));

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

//
// MungeTLS calls this during handshake to choose the protocol version to use
// in ServerHello. returning MT_S_LISTENER_IGNORED defaults to using
// ClientHello.version
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnSelectProtocolVersion(
    MT_ProtocolVersion* pProtocolVersion
)
{
    UNREFERENCED_PARAMETER(pProtocolVersion);
    return MT_S_LISTENER_IGNORED;
} // end function OnSelectProtocolVersion

//
// MungeTLS calls this during the handshake to let the application pick the
// cipher suite to send in the ServerHello. the default is to take a hard-coded
// server preference that the client also advertises.
//
// this client implementation helps testing renegotation by choosing a
// different cipher suite round-robin from a list of choices every time
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnSelectCipherSuite(
    const MT_ClientHello* pClientHello,
    MT_CipherSuite* pCipherSuite
)
{
    //
    // negotiations will cycle through this list. "unknown" means use default
    // only TLS 1.2, which not all browsers support, supports AES-256 or
    // SHA-256, so those are omitted from the list for now
    //
    // instead, we have AES-128 and RC4, a block cipher and a stream cipher,
    // respectively, which are two significantly different codepaths
    //
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
        // our selection is set by calling SetValue
        CHKOK(pCipherSuite->SetValue(csv));
        mr = MT_S_LISTENER_HANDLED;
    }

    // cycle through the list
    m_iCipherSelected = (m_iCipherSelected + 1) % ARRAYSIZE(c_rgCipherSuites);

done:
    return mr;

error:
    goto done;
} // end function OnSelectCipherSuite

//
// MungeTLS calls this when creating each handshake message. we could package
// each message in a separate record layer message, or combine several into the
// same record layer message, since they're all of the same content type If we
// return MT_S_LISTENER_IGNORED, pfFlags are ignored and a safe default is
// used.
//
// we can also modify the contents of the Handshake message
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnCreatingHandshakeMessage(
    MT_Handshake* pHandshake,
    MT_UINT32* pfFlags
)
{
    UNREFERENCED_PARAMETER(pHandshake);

    // examples of the flags available to be set
    *pfFlags |= MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE;
    //*pfFlags |= MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE;

    return MT_S_LISTENER_HANDLED;
} // end function OnCreatingHandshakeMessage

//
// MungeTLS calls this to notify the application that a handshake is complete,
// and it is now safe to send application data.
//
// in the case of completing a handshake resulting from a renegotiation, we
// use this function to send the data we saved off back in
// OnReceivedApplicationData, before the renegotiation began
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnHandshakeComplete()
{
    MTERR mr = MT_S_OK;

    // send any saved response we were holding until after handshake completes
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

//
// This function is called by the server (not MungeTLS) when there is new
// application data (e.g. a HTTP response) to send to the client
//
_Use_decl_annotations_
HRESULT
SimpleHTTPServer::EnqueueSendApplicationData(
    const ByteVector* pvb
)
{
    static const size_t c_cbChunkSize = 50;
    MTERR mr = MT_S_OK;

    //
    // send payloads of size c_cbChunkSize to MungeTLS to encrypt. MungeTLS
    // will call back into us with OnSend when it has the final bytes of the
    // payload
    //
    auto iter = pvb->begin();
    while (iter < pvb->end())
    {
        ByteVector vbChunk;

        size_t cbRemaining = pvb->end() - iter;
        size_t cbNextChunk;
        if (cbRemaining > c_cbChunkSize)
        {
            cbNextChunk = c_cbChunkSize;
        }
        else
        {
            cbNextChunk = cbRemaining;
        }

        vbChunk.assign(iter, iter + cbNextChunk);
        assert(vbChunk.size() <= c_cbChunkSize);
        assert(vbChunk.size() <= cbRemaining);
        assert(vbChunk.size() > 0);

        // call into MungeTLS to prepare this data to be encrypted and sent
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

//
// MungeTLS calls this when it has parsed an application data message, and it
// is passing up the decrypted contents to us, the application. pvb is the
// plaintext application data payload that's been received
//
// since this is an HTTP server implementation, we try to parse this
// application data as a HTTP request, and if successful, respond with a
// HTTP response that echoes back the request. Since this is a *minimal* HTTP
// server, we do practically no validation on the request
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnReceivedApplicationData(
    const ByteVector* pvb
)
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

        //
        // try all the terminators to see if the request is complete. this is
        // simplistic because it doesn't handle things like content-length in
        // the request, so the client can't send any request body
        //

        // iterator to search for end of HTTP request headers
        string::iterator itEndRequest(GetPendingRequest()->begin());

        for (ULONG i = 0; i < ARRAYSIZE(c_rgszHTTPHeadersTerminators); i++)
        {
            // find the end terminator
            string::size_type posEndRequest = GetPendingRequest()->find(c_rgszHTTPHeadersTerminators[i]);

            //
            // found terminator. posEndRequest is the index of the first char
            // of the terminator string
            //
            if (posEndRequest != string::npos)
            {
                //
                // if it's found, set an iterator for the spot 1 past the end
                // of the terminating string.
                //
                itEndRequest = GetPendingRequest()->begin() + posEndRequest + strlen(c_rgszHTTPHeadersTerminators[i]);
                break;
            }
        }

        //
        // this simple web server echoes back the request headers in the
        // response body. if we've found a non-empty request at this point--
        // i.e. the previous search for a terminator succeeded--construct and
        // send the response now.
        //
        if (itEndRequest > GetPendingRequest()->begin())
        {
            ByteVector vbApplicationData;

            const CHAR szApplicationDataTemplate[] =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %d\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: Keep-Alive\r\n"
                "\r\n";

            //
            // reserve some space, and trim down later. the +10 accounts for
            // the varying number of digits in Content-Length.
            //
            // we don't resize() at this point, because that would change
            // begin(), end(), etc.. those will get updated as we insert/append
            //
            vbApplicationData.reserve(
                ARRAYSIZE(szApplicationDataTemplate) + 10 +
                (itEndRequest - GetPendingRequest()->begin()));

            // first get enough space for just the template part
            ResizeVector(&vbApplicationData, ARRAYSIZE(szApplicationDataTemplate) + 10);

            // substituting in the real content length
            CHKWINOKM(StringCchPrintfA(
                          reinterpret_cast<PSTR>(&vbApplicationData.front()),
                          vbApplicationData.size(),
                          szApplicationDataTemplate,
                          itEndRequest - GetPendingRequest()->begin()));

            // trim to just the part we sprintf'd. excludes null terminator
            ResizeVector(&vbApplicationData, strlen(reinterpret_cast<PSTR>(&vbApplicationData.front())));

            // append the request headers, which are now the response body
            vbApplicationData.insert(
                vbApplicationData.end(),
                GetPendingRequest()->begin(),
                itEndRequest);

            // erase just the portion we consumed just now
            GetPendingRequest()->erase(
                GetPendingRequest()->begin(),
                itEndRequest);

            m_cRequestsReceived++;

            //
            // if we reach this point, we have received a request and prepared
            // a response to send. however, since this is a test server, on the
            // second and subsequent requests we receive, first do a
            // renegotiation, THEN send the response. hee hee
            //
            // the renegotiation process is not synchronous right here--
            // MungeTLS will send and receive several messages through that
            // handshake, so we have to save off that response and send it only
            // after it's indicated that the handshake is complete
            // (OnHandshakeComplete).
            //
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

            // this would flush/send any appdata OR renegotiation request
            CHKOK(GetConnection()->SendQueuedMessages());
        }
        else
        {
            //
            // we didn't parse a new HTTP request, and after any successful
            // HTTP request we send all of our pending sends, so there should
            // never be pending sends at this point
            //
            assert(GetConnection()->GetPendingSends()->empty());
        }

        printf("pending request is: %s\n", GetPendingRequest()->c_str());
    }

done:
    return mr;

error:
    goto done;
} // end function OnReceivedApplicationData

//
// MungeTLS calls this when it has readied a message about to be sent. The
// plaintext version of the message is passed in here, and fActuallyEncrypted
// tells whether the message is actually going to be encrypted before sending,
// as opposed to being sent in the clear (like some Handshake messages).
//
// the application has a last chance to modify the message prior to it being
// sealed for encryption. it is also a useful place to log the message
//
// for this server, we actually log the raw bytes of the message in a special
// format. see the notes for LogTraffic
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnEnqueuePlaintext(
    MT_TLSPlaintext* pPlaintext,
    bool fActuallyEncrypted
)
{
    MTERR mr = MT_S_OK;
    ByteVector vb;

    //
    // "w" means "write", as in, from the server's point of view, we are
    // writing data back to the client
    //
    wstring wsLogPrefix(L"w");

    CHKOK(pPlaintext->SerializeToVect(&vb));

    LogTraffic(m_cMessages, &wsLogPrefix, fActuallyEncrypted, &vb);
    m_cMessages++;

done:
    //
    // if this assert hits, it means we've probably tried to serialize a
    // structure that I forgot to implement SerializePriv() for
    //
    assert(mr != MT_E_NOTIMPL);

    return mr;

error:
    goto done;
} // end function OnEnqueuePlaintext

//
// MungeTLS calls this when it has just decrypted a message, before doing any
// other processing on it. The application can modify the message (though
// doing so indiscriminately can cause the TLS protocol to fail), but here we
// just log the traffic. See notes for LogTraffic on the special format we log
// it in
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnReceivingPlaintext(
    MT_TLSPlaintext* pPlaintext,
    bool fActuallyEncrypted
)
{
    MTERR mr = MT_S_OK;
    ByteVector vb;
    wstring wsLogPrefix(L"r");

    CHKOK(pPlaintext->SerializeToVect(&vb));

    LogTraffic(m_cMessages, &wsLogPrefix, fActuallyEncrypted, &vb);
    m_cMessages++;

done:
    // debugger break when I've forgotten to implement serialization for struct
    assert(mr != MT_E_NOTIMPL);
    return mr;

error:
    goto done;
} // end function OnReceivingPlaintext

//
// MungeTLS calls this if it is about to check the security of a record it has
// received, but that record has a different version specified than the
// currently negotiated version for the connection. It gives the application
// a chance to reconcile it and choose the version that should be used for
// "security" operations like integrity checks
//
// if we return MT_S_LISTENER_IGNORED here, MTLS will use the record's version,
// not the currently negotiated connection's version
//
// In particular, many browsers handle version negotiation differently. we
// always set to whatever higher version was previously negotiated if the
// versions differ
//
_Use_decl_annotations_
MTERR_T
SimpleHTTPServer::OnReconcileSecurityVersion(
    const MT_TLSCiphertext* pCiphertext,
    MT_ProtocolVersion::MTPV_Version connVersion,
    MT_ProtocolVersion::MTPV_Version recordVersion,
    MT_ProtocolVersion::MTPV_Version* pOverrideVersion
)
{
    UNREFERENCED_PARAMETER(pCiphertext);

    //
    // if the incoming record is stepping down from a previously negotiated
    // TLS 1.1 or 1.2 to 1.0, then continue using the more secure 1.1 or 1.2.
    // this is actually experienced with openssl clients
    //
    if ((connVersion == MT_ProtocolVersion::MTPV_TLS11 ||
         connVersion == MT_ProtocolVersion::MTPV_TLS12) &&
        recordVersion == MT_ProtocolVersion::MTPV_TLS10)
    {
        *pOverrideVersion = connVersion;
        return MT_S_LISTENER_HANDLED;
    }

    return MT_S_LISTENER_IGNORED;
} // end function OnReconcileSecurityVersion

//
// The server calls this function to log the raw bytes of inbound and outbound
// traffic. We log it with a specific format that makes it suitable for
// parsing by the "munge2netmon" companion tool, which can take the raw traffic
// and turn it into a Netmon capture, which can be viewed for easy traffic
// parsing and inspection
//
_Use_decl_annotations_
HRESULT
LogTraffic(
    ULONG nFile,
    const wstring* pwsSuffix,
    bool fActuallyEncrypted,
    const ByteVector* pvb
)
{
    HRESULT hr = S_OK;

    // dump log file in the "out" subdirectory
    wstring wsFilename(L"out\\");
    HANDLE hOutfile = INVALID_HANDLE_VALUE;

    // supports up to 1000 messages
    for (ULONG i = nFile; i < 1000; i *= 10)
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

    if (fActuallyEncrypted)
    {
        wsFilename += L"_c";
    }

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
        // lazy code - fail if we can't write the whole message at once
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

    // most common cause of failing is the "out" directory not existing
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

template <typename N>
_Check_return_
wstring
StringFromInt(
    _In_ N n
)
{
    wstringstream s;
    s << n;
    return s.str();
} // end function StringFromInt

void Usage()
{
    wprintf(L"Usage: MungeTLS.exe -p port_number\n"
            L"    starts the web server listening on the specified port\n");
}
