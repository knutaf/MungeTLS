#include "precomp.h"

#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>
#include <functional>

#include "mtls_defs.h"
#include "MungeTLS.h"
#include "mtls_helper.h"

#define SAFE_SUB(h, l, r)              \
{                                      \
    (h) = SizeTSub((l), (r), &(l));    \
    if ((h) != S_OK) { goto error; }   \
}                                      \

#define ADVANCE_PARSE()                \
{                                      \
    pv += cbField;                     \
    SAFE_SUB(hr, cb, cbField);         \
}                                      \

namespace MungeTLS
{

using namespace std;

HRESULT
ComputePRF_TLS12(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF);

HRESULT
ComputePRF_TLS10(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF);

// same PRF used for both 1.0 and 1.1
auto ComputePRF_TLS11 = ComputePRF_TLS10;

HRESULT
PRF_P_hash(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    size_t cbMinimumLengthDesired,
    ByteVector* pvbResult);

HRESULT
PRF_A(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    UINT i,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    ByteVector* pvbResult);

/*********** TLSConnection *****************/

TLSConnection::TLSConnection(ITLSListener* pListener)
    : m_currentConnection(),
      m_nextConnection(),
      m_pendingSends(),
      m_pListener(pListener)
{
} // end ctor TLSConnection

HRESULT
TLSConnection::Initialize()
{
    HRESULT hr = S_OK;

    MT_CertificateList certChain;
    shared_ptr<PublicKeyCipherer> spPubKeyCipherer;
    shared_ptr<SymmetricCipherer> spClientSymCipherer;
    shared_ptr<SymmetricCipherer> spServerSymCipherer;
    shared_ptr<Hasher> spHasher;

    hr = Listener()->OnInitializeCrypto(
             &certChain,
             &spPubKeyCipherer,
             &spClientSymCipherer,
             &spServerSymCipherer,
             &spHasher);

    if (hr != S_OK)
    {
        goto error;
    }

    hr = CurrConn()->Initialize(
             &certChain,
             spPubKeyCipherer,
             spClientSymCipherer,
             spServerSymCipherer,
             spHasher);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Initialize

HRESULT
TLSConnection::StartNextHandshake(const MT_ClientHello* pClientHello)
{
    HRESULT hr = S_OK;

    // could pass this to OnInitializeCrypto
    UNREFERENCED_PARAMETER(pClientHello);

    MT_CertificateList certChain;
    shared_ptr<PublicKeyCipherer> spPubKeyCipherer;
    shared_ptr<SymmetricCipherer> spClientSymCipherer;
    shared_ptr<SymmetricCipherer> spServerSymCipherer;
    shared_ptr<Hasher> spHasher;

    if (NextConn()->IsHandshakeInProgress())
    {
        // TODO: may lift this restriction if okay...
        assert(false);
    }

    hr = Listener()->OnInitializeCrypto(
             &certChain,
             &spPubKeyCipherer,
             &spClientSymCipherer,
             &spServerSymCipherer,
             &spHasher);

    if (hr != S_OK)
    {
        goto error;
    }

    hr = NextConn()->Initialize(
             &certChain,
             spPubKeyCipherer,
             spClientSymCipherer,
             spServerSymCipherer,
             spHasher);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function StartNextHandshake

HRESULT
TLSConnection::FinishNextHandshake()
{
    HRESULT hr = S_OK;

    *NextConn() = ConnectionParameters();

    hr = Listener()->OnHandshakeComplete();
    if (FAILED(hr))
    {
        goto error;
    }
    else
    {
        hr = S_OK;
    }

done:
    return hr;

error:
    goto done;
} // end function FinishNextHandshake

HRESULT
TLSConnection::HandleMessage(
    ByteVector* pvb
)
{
    HRESULT hr = S_OK;

    MT_TLSCiphertext message;
    MT_TLSPlaintext record;
    size_t cbConsumed = 0;

    if (pvb->empty())
    {
        hr = S_FALSE;
        goto done;
    }

    *message.Conn() = this;

    hr = message.ParseFromVect(pvb);
    if (hr != S_OK)
    {
        wprintf(L"failed to parse ciphered message: %08LX\n", hr);
        goto error;
    }

    wprintf(L"successfully parsed TLSCiphertext. CT=%d\n", *message.ContentType()->Type());

    hr = message.SetSecurityParameters(CurrConn()->ReadParams());
    if (hr != S_OK)
    {
        goto error;
    }

    hr = message.Decrypt();
    if (hr != S_OK)
    {
        wprintf(L"failed to decrypt ciphertext: %08LX\n", hr);
        goto error;
    }

    {
        ByteVector vbDecryptedFragment;
        wprintf(L"decrypted fragment:\n");
        PrintByteVector(message.CipherFragment()->Content());
    }

    hr = message.CheckSecurity();
    if (hr != S_OK)
    {
        wprintf(L"tlsciphertext failed security check: %08LX\n", hr);
        goto error;
    }

    hr = message.ToTLSPlaintext(&record);
    if (hr != S_OK)
    {
        wprintf(L"failed to assign ciphertext to plaintext: %08LX\n", hr);
        goto error;
    }

    hr = Listener()->OnReceivingPlaintext(
             &record,
             message.EndParams()->IsEncrypted());

    if (hr != S_OK)
    {
        goto error;
    }

    if (CurrConn()->ReadParams()->Cipher()->type == CipherType_Block)
    {
        if (*CurrConn()->ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS10)
        {
            MT_GenericBlockCipher_TLS10* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS10*>(message.CipherFragment());
            CurrConn()->ReadParams()->IV()->assign(pBlockCipher->RawContent()->end() - CurrConn()->ReadParams()->Cipher()->cbIVSize, pBlockCipher->RawContent()->end());
        }
        else if (*CurrConn()->ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
        {
            MT_GenericBlockCipher_TLS11* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS11*>(message.CipherFragment());
            *CurrConn()->ReadParams()->IV() = *pBlockCipher->IVNext();
        }
        else if (*CurrConn()->ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
        {
            MT_GenericBlockCipher_TLS12* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS12*>(message.CipherFragment());
            *CurrConn()->ReadParams()->IV() = *pBlockCipher->IVNext();
        }
        else
        {
            assert(false);
        }
    }

    assert(CurrConn()->ReadParams()->IV()->size() == CurrConn()->ReadParams()->Cipher()->cbIVSize);

    cbConsumed = message.Length();

    if (*record.ContentType()->Type() == MT_ContentType::MTCT_Type_Handshake)
    {
        vector<MT_Handshake> vStructures;
        hr = ParseStructures(record.Fragment(), &vStructures);
        if (hr != S_OK)
        {
            goto error;
        }

        for (auto it = vStructures.begin(); it != vStructures.end(); it++)
        {
            shared_ptr<MT_Handshake> spHandshakeMessage(new MT_Handshake());
            *spHandshakeMessage = *it;

            wprintf(L"successfully parsed Handshake. type=%d\n", *spHandshakeMessage->Type());

            if (*spHandshakeMessage->Type() == MT_Handshake::MTH_ClientHello)
            {
                MT_ClientHello clientHello;

                hr = clientHello.ParseFromVect(spHandshakeMessage->Body());
                if (hr != S_OK)
                {
                    wprintf(L"failed to parse client hello: %08LX\n", hr);
                    goto error;
                }

                wprintf(L"parsed client hello message:\n");
                wprintf(L"version %04LX\n", *clientHello.ProtocolVersion()->Version());
                if (clientHello.SessionID()->Count() > 0)
                {
                    wprintf(L"session ID %d (%d)\n", clientHello.SessionID()->Data()[0]);
                }
                else
                {
                    wprintf(L"no session ID specified\n");
                }

                wprintf(L"%d crypto suites\n", clientHello.CipherSuites()->Count());

                wprintf(L"crypto suite 0: %02X %02X\n",
                       *clientHello.CipherSuites()->at(0)->at(0),
                       *clientHello.CipherSuites()->at(0)->at(1));

                wprintf(L"%d compression methods: %d\n",
                       clientHello.CompressionMethods()->Count(),
                       *clientHello.CompressionMethods()->at(0)->Method());

                wprintf(L"%d extensions, taking %d bytes\n", clientHello.Extensions()->Count(), clientHello.Extensions()->Length());

                {
                    for (auto it = clientHello.Extensions()->Data()->begin(); it != clientHello.Extensions()->Data()->end(); it++)
                    {
                        if (*it->ExtensionType() == MT_Extension::MTEE_RenegotiationInfo)
                        {
                            wprintf(L"found renegotiation info:\n");
                            PrintByteVector(it->ExtensionData());
                        }
                    }
                }

                hr = StartNextHandshake(&clientHello);
                if (hr != S_OK)
                {
                    goto error;
                }

                NextConn()->HandshakeMessages()->push_back(spHandshakeMessage);

                *NextConn()->ClientHello() = clientHello;

                {
                    MT_ProtocolVersion protocolVersion = *clientHello.ProtocolVersion();

                    HRESULT hrL = Listener()->OnSelectProtocolVersion(&protocolVersion);
                    if (FAILED(hrL))
                    {
                        hr = hrL;
                        goto error;
                    }

                    *NextConn()->ReadParams()->Version() = *protocolVersion.Version();
                    *NextConn()->WriteParams()->Version() = *protocolVersion.Version();
                }

                *NextConn()->ClientRandom() = *(clientHello.Random());

                {
                    MT_CipherSuite cipherSuite;

                    HRESULT hrL = Listener()->OnSelectCipherSuite(&cipherSuite);
                    if (FAILED(hrL))
                    {
                        hr = hrL;
                        goto error;
                    }

                    if (hrL == MT_S_LISTENER_IGNORED)
                    {
                        MT_CipherSuiteValue ePreferred;
                        vector<MT_CipherSuiteValue> vValues(NextConn()->ClientHello()->CipherSuites()->Count());

                        transform(
                            NextConn()->ClientHello()->CipherSuites()->Data()->begin(),
                            NextConn()->ClientHello()->CipherSuites()->Data()->end(),
                            vValues.begin(),
                            [&hr](const MT_CipherSuite& rSuite)
                            {
                                if (hr == S_OK)
                                {
                                    MT_CipherSuiteValue eValue;
                                    hr = rSuite.Value(&eValue);
                                    return eValue;
                                }
                                else
                                {
                                    return MTCS_UNKNOWN;
                                }
                            }
                        );

                        if (hr != S_OK)
                        {
                            goto error;
                        }

                        hr = ChooseBestCipherSuite(
                                 &vValues,
                                 GetCipherSuitePreference(),
                                 &ePreferred);

                        if (hr != S_OK)
                        {
                            goto error;
                        }

                        hr = cipherSuite.SetValue(ePreferred);
                        if (hr != S_OK)
                        {
                            goto error;
                        }
                    }

                    *NextConn()->ReadParams()->CipherSuite() = cipherSuite;
                    *NextConn()->WriteParams()->CipherSuite() = cipherSuite;

                    {
                        MT_CipherSuiteValue eValue;
                        HRESULT hrTemp = cipherSuite.Value(&eValue);
                        assert(hrTemp == S_OK);

                        wprintf(L"chosen cipher suite %04LX\n", eValue);
                    }
                }

                hr = RespondToClientHello();
                if (hr != S_OK)
                {
                    wprintf(L"failed RespondToClientHello: %08LX\n", hr);
                    goto error;

                }
            }
            else if (*spHandshakeMessage->Type() == MT_Handshake::MTH_ClientKeyExchange)
            {
                MT_KeyExchangeAlgorithm keyExchangeAlg;
                MT_ClientKeyExchange<MT_EncryptedPreMasterSecret> keyExchange;
                MT_EncryptedPreMasterSecret* pExchangeKeys = nullptr;
                MT_PreMasterSecret* pSecret = nullptr;

                /*
                ** at this point we should have exchanged hellos and therefore
                ** agreed on a single cipher suite
                */
                assert(*NextConn()->ReadParams()->CipherSuite() == *NextConn()->WriteParams()->CipherSuite());

                hr = NextConn()->ReadParams()->CipherSuite()->KeyExchangeAlgorithm(&keyExchangeAlg);
                if (hr != S_OK)
                {
                    wprintf(L"failed to get key exchange algorithm: %08LX\n", hr);
                    goto error;
                }

                if (keyExchangeAlg != MTKEA_rsa)
                {
                    wprintf(L"unsupported key exchange type: %d\n", keyExchangeAlg);
                    hr = MT_E_UNSUPPORTED_KEY_EXCHANGE;
                    goto error;
                }

                hr = keyExchange.ParseFromVect(spHandshakeMessage->Body());

                if (hr != S_OK)
                {
                    wprintf(L"failed to parse key exchange message from handshake body: %08LX\n", hr);
                    goto error;
                }

                pExchangeKeys = keyExchange.ExchangeKeys();
                pExchangeKeys->SetCipherer(NextConn()->PubKeyCipherer()->get());
                hr = pExchangeKeys->DecryptStructure();
                if (hr != S_OK)
                {
                    wprintf(L"failed to decrypt structure: %08LX\n", hr);
                    goto error;
                }

                NextConn()->HandshakeMessages()->push_back(spHandshakeMessage);

                pSecret = pExchangeKeys->Structure();
                wprintf(L"version %04LX\n", *pSecret->ClientVersion()->Version());

                hr = NextConn()->ComputeMasterSecret(pSecret);
                if (hr != S_OK)
                {
                    wprintf(L"failed to compute master secret: %08LX\n", hr);
                    goto error;
                }

                wprintf(L"computed master secret:\n");
                PrintByteVector(NextConn()->MasterSecret());

                hr = NextConn()->GenerateKeyMaterial();
                if (hr != S_OK)
                {
                    wprintf(L"failed to compute key material: %08LX\n", hr);
                    goto error;
                }

                wprintf(L"computed key material\n");
            }
            else if (*spHandshakeMessage->Type() == MT_Handshake::MTH_Finished)
            {
                MT_Finished finishedMessage;
                hr = finishedMessage.ParseFromVect(spHandshakeMessage->Body());
                if (hr != S_OK)
                {
                    wprintf(L"failed to parse finished message: %08LX\n", hr);
                    goto error;
                }

                hr = finishedMessage.SetConnectionParameters(NextConn());
                if (hr != S_OK)
                {
                    goto error;
                }

                hr = finishedMessage.SetSecurityParameters(NextConn()->ReadParams());
                if (hr != S_OK)
                {
                    goto error;
                }

                hr = finishedMessage.CheckSecurity();
                if (hr != S_OK)
                {
                    wprintf(L"security failed on finished message: %08LX\n", hr);
                    goto error;
                }

                *NextConn()->ClientVerifyData() = *finishedMessage.VerifyData();

                NextConn()->HandshakeMessages()->push_back(spHandshakeMessage);

                hr = RespondToFinished();
                if (hr != S_OK)
                {
                    wprintf(L"failed RespondToFinished: %08LX\n", hr);
                    goto error;

                }
            }
            else
            {
                wprintf(L"not yet supporting handshake type %d\n", *spHandshakeMessage->Type());
                hr = MT_E_UNSUPPORTED_HANDSHAKE_TYPE;
                goto error;
            }
        }

        (*CurrConn()->ReadParams()->SequenceNumber())++;
    }
    else if (*record.ContentType()->Type() == MT_ContentType::MTCT_Type_ChangeCipherSpec)
    {
        vector<MT_ChangeCipherSpec> vStructures;
        hr = ParseStructures(record.Fragment(), &vStructures);
        if (hr != S_OK)
        {
            goto error;
        }

        for (auto it = vStructures.begin(); it != vStructures.end(); it++)
        {
            wprintf(L"change cipher spec found: %d\n", *it->Type());
            *CurrConn()->ReadParams() = *NextConn()->ReadParams();
        }

        /*
        ** after copying the next endpoint state, which has not been touched,
        ** its sequence number should already be 0 without having to reset it
        */
        assert(*CurrConn()->ReadParams()->SequenceNumber() == 0);
    }
    else if (*record.ContentType()->Type() == MT_ContentType::MTCT_Type_Alert)
    {
        vector<MT_Alert> vStructures;
        hr = ParseStructures(record.Fragment(), &vStructures);
        if (hr != S_OK)
        {
            goto error;
        }

        for (auto it = vStructures.begin(); it != vStructures.end(); it++)
        {
            wprintf(L"got alert: %s\n", it->ToString().c_str());
        }

        (*CurrConn()->ReadParams()->SequenceNumber())++;
    }
    else if (*record.ContentType()->Type() == MT_ContentType::MTCT_Type_ApplicationData)
    {
        wprintf(L"application data:\n");
        PrintByteVector(record.Fragment());

        hr = Listener()->OnApplicationData(record.Fragment());
        if (hr != S_OK)
        {
            wprintf(L"warning: error in OnApplicationData with listener: %08LX\n", hr);
        }

        (*CurrConn()->ReadParams()->SequenceNumber())++;
    }
    else
    {
        // TLSPlaintext.ParseFrom should filter out unknown content types
        assert(false);
    }

    hr = SendQueuedMessages();
    if (hr != S_OK)
    {
        wprintf(L"failed sending pending messages: %08LX\n", hr);
        goto error;
    }

    assert(cbConsumed <= pvb->size());
    pvb->erase(pvb->begin(), pvb->begin() + cbConsumed);

done:
    return hr;

error:
    goto done;
} // end function ParseMessage

HRESULT
TLSConnection::EnqueueMessage(
    shared_ptr<MT_TLSPlaintext> spPlaintext
)
{
    HRESULT hr = S_OK;

    shared_ptr<MT_TLSCiphertext> spCiphertext;

    hr = MT_TLSCiphertext::FromTLSPlaintext(
             spPlaintext.get(),
             CurrConn()->WriteParams(),
             &spCiphertext);

    if (hr != S_OK)
    {
        goto error;
    }

    CurrConn()->WriteParams()->IV()->assign(spCiphertext->Fragment()->end() - CurrConn()->WriteParams()->Cipher()->cbIVSize, spCiphertext->Fragment()->end());
    assert(CurrConn()->WriteParams()->IV()->size() == CurrConn()->WriteParams()->Cipher()->cbIVSize);

    PendingSends()->push_back(spCiphertext);
    (*CurrConn()->WriteParams()->SequenceNumber())++;

    wprintf(L"write seq num is now %d\n", *CurrConn()->WriteParams()->SequenceNumber());


    hr = Listener()->OnEnqueuePlaintext(
             spPlaintext.get(),
             spCiphertext->EndParams()->IsEncrypted());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EnqueueMessage

HRESULT
TLSConnection::SendQueuedMessages()
{
    HRESULT hr = S_OK;

    if (!PendingSends()->empty())
    {
        wprintf(L"sending %u messages\n", PendingSends()->size());

        {
            for_each(PendingSends()->begin(), PendingSends()->end(),
            [](const shared_ptr<MT_RecordLayerMessage>& rspStructure)
            {
                wprintf(L"    %s\n", rspStructure->ContentType()->ToString().c_str());
            });
        }

        for_each(PendingSends()->begin(), PendingSends()->end(),
        [&hr, this](const shared_ptr<MT_RecordLayerMessage>& rspStructure)
        {
            if (hr == S_OK)
            {
                ByteVector vbResponse;

                hr = rspStructure->SerializeToVect(&vbResponse);
                if (hr == S_OK)
                {
                    hr = Listener()->OnSend(&vbResponse);
                    if (hr != S_OK)
                    {
                        wprintf(L"warning: error in OnSend with listener: %08LX\n", hr);
                    }
                }
                else
                {
                    wprintf(L"failed to serialize message: %08LX\n", hr);
                }
            }
        });

        if (hr != S_OK)
        {
            goto error;
        }

        PendingSends()->clear();
    }

done:
    return hr;

error:
    goto done;
} // end function SendQueuedMessages

HRESULT
TLSConnection::RespondToClientHello()
{
    HRESULT hr = S_OK;
    MT_ClientHello* pClientHello = NextConn()->ClientHello();
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    // Server Hello
    {
        MT_ProtocolVersion protocolVersion;
        MT_Random random;
        MT_SessionID sessionID;
        MT_CompressionMethod compressionMethod;
        MT_HelloExtensions extensions;
        MT_ServerHello serverHello;
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());

        // could call back to caller for this
        *protocolVersion.Version() = *NextConn()->ReadParams()->Version();

        hr = random.PopulateNow();
        if (hr != S_OK)
        {
            goto error;
        }

        *compressionMethod.Method() = MT_CompressionMethod::MTCM_Null;

        {
            MT_RenegotiationInfoExtension renegotiationExtension;
            *renegotiationExtension.ExtensionType() = MT_Extension::MTEE_RenegotiationInfo;

            // no previous verify data to use, i.e. not renegotiating
            if (!CurrConn()->ServerVerifyData()->Data()->empty())
            {
                // also need client verify data
                assert(!CurrConn()->ClientVerifyData()->Data()->empty());

                renegotiationExtension.RenegotiatedConnection()->Data()->insert(
                    renegotiationExtension.RenegotiatedConnection()->Data()->end(),
                    CurrConn()->ClientVerifyData()->Data()->begin(),
                    CurrConn()->ClientVerifyData()->Data()->end());

                renegotiationExtension.RenegotiatedConnection()->Data()->insert(
                    renegotiationExtension.RenegotiatedConnection()->Data()->end(),
                    CurrConn()->ServerVerifyData()->Data()->begin(),
                    CurrConn()->ServerVerifyData()->Data()->end());

                if (renegotiationExtension.RenegotiatedConnection()->Data()->size() != c_cbFinishedVerifyData_Length * 2)
                {
                    wprintf(L"warning: renegotiation verify data is odd length. expected: %u, actual: %u\n", c_cbFinishedVerifyData_Length * 2, renegotiationExtension.RenegotiatedConnection()->Data()->size());
                }

                wprintf(L"adding renegotation binding information:\n");
                PrintByteVector(renegotiationExtension.RenegotiatedConnection()->Data());
            }
            // else, empty renegotiated info

            hr = renegotiationExtension.UpdateDerivedFields();
            if (hr != S_OK)
            {
                goto error;
            }

            extensions.Data()->push_back(renegotiationExtension);
        }

        *(serverHello.ProtocolVersion()) = protocolVersion;
        *(serverHello.Random()) = random;
        *(serverHello.SessionID()) = sessionID;

        assert(*NextConn()->ReadParams()->CipherSuite() == *NextConn()->WriteParams()->CipherSuite());
        *(serverHello.CipherSuite()) = *NextConn()->ReadParams()->CipherSuite();

        *(serverHello.CompressionMethod()) = compressionMethod;
        *(serverHello.Extensions()) = extensions;

        *NextConn()->ServerRandom() = *(serverHello.Random());

        *spHandshake->Type() = MT_Handshake::MTH_ServerHello;
        hr = serverHello.SerializeToVect(spHandshake->Body());
        if (hr != S_OK)
        {
            goto error;
        }

        hr = CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 *protocolVersion.Version(),
                 spHandshake.get(),
                 spPlaintext.get());

        if (hr != S_OK)
        {
            goto error;
        }

        NextConn()->HandshakeMessages()->push_back(spHandshake);

        /*
        ** don't enqueue or increment sequence number just yet. we may choose
        ** as part of the next handshake message below to tack on another
        ** handshake message to this single record layer message
        */
    }

    assert(hr == S_OK);

    // Certificate
    {
        MT_Certificate certificate;
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_TLSPlaintext* pPlaintextPass = spPlaintext.get();

        *certificate.CertificateList() = *NextConn()->CertChain();
        *spHandshake->Type() = MT_Handshake::MTH_Certificate;

        hr = certificate.SerializeToVect(spHandshake->Body());
        if (hr != S_OK)
        {
            goto error;
        }

        hr = AddHandshakeMessage(
                 spHandshake.get(),
                 *pClientHello->ProtocolVersion()->Version(),
                 &pPlaintextPass);

        if (hr == S_OK)
        {
            /*
            ** send the previous record layer message. The caller chose to put
            ** this handshake message in a new record layer message, passed
            ** back in pPlaintextPass
            */
            hr = EnqueueMessage(spPlaintext);
            if (hr != S_OK)
            {
                goto error;
            }

            // take ownership of memory allocated in AddHandshakeMessage
            spPlaintext.reset(pPlaintextPass);
        }
        else if (hr != S_FALSE)
        {
            goto error;
        }

        NextConn()->HandshakeMessages()->push_back(spHandshake);

        hr = S_OK;
    }

    assert(hr == S_OK);

    // Server Hello Done
    {
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_TLSPlaintext* pPlaintextPass = spPlaintext.get();

        *spHandshake->Type() = MT_Handshake::MTH_ServerHelloDone;

        hr = AddHandshakeMessage(
                 spHandshake.get(),
                 *pClientHello->ProtocolVersion()->Version(),
                 &pPlaintextPass);

        if (hr == S_OK)
        {
            /*
            ** send the previous record layer message. The caller chose to put
            ** this handshake message in a new record layer message, passed
            ** back in pPlaintextPass
            */
            hr = EnqueueMessage(spPlaintext);
            if (hr != S_OK)
            {
                goto error;
            }

            // take ownership of memory allocated in AddHandshakeMessage
            spPlaintext.reset(pPlaintextPass);
        }
        else if (hr != S_FALSE)
        {
            goto error;
        }

        hr = EnqueueMessage(spPlaintext);
        if (hr != S_OK)
        {
            goto error;
        }

        NextConn()->HandshakeMessages()->push_back(spHandshake);
    }

    assert(hr == S_OK);

done:
    return hr;

error:
    goto done;
} // end function RespondToClientHello

HRESULT
TLSConnection::RespondToFinished()
{
    HRESULT hr = S_OK;

    // ChangeCipherSpec
    {
        MT_ChangeCipherSpec changeCipherSpec;
        shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

        *(changeCipherSpec.Type()) = MT_ChangeCipherSpec::MTCCS_ChangeCipherSpec;

        assert(*NextConn()->ReadParams()->Version() == *NextConn()->WriteParams()->Version());

        hr = CreatePlaintext(
                 MT_ContentType::MTCT_Type_ChangeCipherSpec,
                 *NextConn()->ReadParams()->Version(),
                 &changeCipherSpec,
                 spPlaintext.get());

        if (hr != S_OK)
        {
            goto error;
        }

        // ChangeCipherSpec resets sequence number
        hr = EnqueueMessage(spPlaintext);
        if (hr != S_OK)
        {
            goto error;
        }

        *CurrConn()->WriteParams() = *NextConn()->WriteParams();

        hr = NextConn()->CopyCommonParamsTo(CurrConn());
        if (hr != S_OK)
        {
            goto error;
        }

        /*
        ** newly copied new connection state should have its initial value of
        ** 0 for sequence number, since it hasn't been touched yet
        */
        assert(*CurrConn()->WriteParams()->SequenceNumber() == 0);
    }

    // Finished
    {
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_Finished finished;
        shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

        hr = finished.SetConnectionParameters(CurrConn());
        if (hr != S_OK)
        {
            goto error;
        }

        hr = finished.SetSecurityParameters(CurrConn()->WriteParams());
        if (hr != S_OK)
        {
            goto error;
        }

        hr = finished.ComputeVerifyData(c_szServerFinished_PRFLabel, finished.VerifyData()->Data());
        if (hr != S_OK)
        {
            goto error;
        }

        *spHandshake->Type() = MT_Handshake::MTH_Finished;
        hr = finished.SerializeToVect(spHandshake->Body());
        if (hr != S_OK)
        {
            goto error;
        }

        assert(*CurrConn()->ReadParams()->Version() == *CurrConn()->WriteParams()->Version());

        hr = CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 *CurrConn()->WriteParams()->Version(),
                 spHandshake.get(),
                 spPlaintext.get());

        if (hr != S_OK)
        {
            goto error;
        }

        hr = EnqueueMessage(spPlaintext);
        if (hr != S_OK)
        {
            goto error;
        }

        CurrConn()->HandshakeMessages()->push_back(spHandshake);

        *CurrConn()->ServerVerifyData() = *finished.VerifyData();
    }

    hr = FinishNextHandshake();
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function RespondToFinished

HRESULT
TLSConnection::AddHandshakeMessage(
    MT_Handshake* pHandshake,
    MT_ProtocolVersion::MTPV_Version version,
    MT_TLSPlaintext** ppPlaintext
)
{
    HRESULT hr = S_OK;
    DWORD fCreateFlags = 0;

    hr = Listener()->OnCreatingHandshakeMessage(pHandshake, &fCreateFlags);
    if (hr == MT_S_LISTENER_IGNORED)
    {
        fCreateFlags = MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE;
    }
    else if (hr != MT_S_LISTENER_HANDLED)
    {
        goto error;
    }

    if (fCreateFlags & MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE)
    {
        pHandshake->SerializeAppendToVect((*ppPlaintext)->Fragment());
        hr = S_FALSE;
    }
    else
    {
        *ppPlaintext = new MT_TLSPlaintext();

        hr = CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 version,
                 pHandshake,
                 *ppPlaintext);

        if (hr != S_OK)
        {
            goto error;
        }

        // hr = S_OK; implied
    }

done:
    return hr;

error:
    goto done;
} // end function AddHandshakeMessage

HRESULT
TLSConnection::EnqueueSendApplicationData(
    const ByteVector* pvb
)
{
    HRESULT hr = S_OK;
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    assert(*CurrConn()->ReadParams()->Version() == *CurrConn()->WriteParams()->Version());

    hr = CreatePlaintext(
             MT_ContentType::MTCT_Type_ApplicationData,
             *CurrConn()->WriteParams()->Version(),
             pvb,
             spPlaintext.get());

    if (hr != S_OK)
    {
        goto error;
    }

    hr = EnqueueMessage(spPlaintext);
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EnqueueSendApplicationData

HRESULT
TLSConnection::EnqueueStartRenegotiation()
{
    HRESULT hr = S_OK;
    MT_HelloRequest helloRequest;
    MT_Handshake handshake;
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    wprintf(L"starting renegotiation\n");

    *handshake.Type() = MT_Handshake::MTH_HelloRequest;
    hr = helloRequest.SerializeToVect(handshake.Body());
    if (hr != S_OK)
    {
        goto error;
    }

    assert(*CurrConn()->ReadParams()->Version() == *CurrConn()->WriteParams()->Version());

    hr = CreatePlaintext(
             MT_ContentType::MTCT_Type_Handshake,
             *CurrConn()->WriteParams()->Version(),
             &handshake,
             spPlaintext.get());

    if (hr != S_OK)
    {
        goto error;
    }

    hr = EnqueueMessage(spPlaintext);
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EnqueueStartRenegotiation

HRESULT
TLSConnection::CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    MT_TLSPlaintext* pPlaintext)
{
    HRESULT hr = S_OK;

    ByteVector vbFragment;
    hr = pFragment->SerializeToVect(&vbFragment);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = CreatePlaintext(
             eContentType,
             eProtocolVersion,
             &vbFragment,
             pPlaintext);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CreatePlaintext

HRESULT
TLSConnection::CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    MT_TLSPlaintext* pPlaintext)
{
    MT_ContentType contentType;
    MT_ProtocolVersion protocolVersion;

    *contentType.Type() = eContentType;
    *pPlaintext->ContentType() = contentType;

    *protocolVersion.Version() = eProtocolVersion;
    *pPlaintext->ProtocolVersion() = protocolVersion;

    *pPlaintext->Fragment() = *pvbFragment;

    assert(*pPlaintext->Conn() == nullptr);
    *pPlaintext->Conn() = this;

    return S_OK;
} // end function CreatePlaintext

HRESULT
TLSConnection::CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext)
{
    HRESULT hr = S_OK;
    ByteVector vbFragment;

    hr = pFragment->SerializeToVect(&vbFragment);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = CreateCiphertext(
             eContentType,
             eProtocolVersion,
             &vbFragment,
             pEndParams,
             pCiphertext);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CreateCiphertext

HRESULT
TLSConnection::CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext)
{
    HRESULT hr = S_OK;

    MT_ContentType contentType;
    MT_ProtocolVersion protocolVersion;

    assert(*pCiphertext->Conn() == nullptr);
    *pCiphertext->Conn() = this;

    hr = pCiphertext->SetSecurityParameters(pEndParams);
    if (hr != S_OK)
    {
        goto error;
    }

    *contentType.Type() = eContentType;
    *pCiphertext->ContentType() = contentType;

    *protocolVersion.Version() = eProtocolVersion;
    *pCiphertext->ProtocolVersion() = protocolVersion;
    *pCiphertext->CipherFragment()->Content() = *pvbFragment;

    hr = pCiphertext->UpdateFragmentSecurity();
    if (hr != S_OK)
    {
        goto error;
    }

    hr = pCiphertext->Encrypt();
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CreateCiphertext


/*********** Utility functions *****************/

template <typename N>
HRESULT
ReadNetworkLong(
    const BYTE* pv,
    size_t cb,
    size_t cbToRead,
    N* pResult
)
{
    assert(pResult != nullptr);
    assert(cbToRead <= sizeof(size_t));

    HRESULT hr = S_OK;

    *pResult = 0;

    while (cbToRead > 0)
    {
        if (cb <= 0)
        {
            hr = MT_E_INCOMPLETE_MESSAGE;
            goto error;
        }

        (*pResult) <<= 8;
        *pResult |= *pv;

        pv++;
        cb--;
        cbToRead--;
    }

done:
    return hr;

error:
    goto done;
} // end function ReadNetworkLong

template <typename I>
HRESULT
WriteNetworkLong(
    I toWrite,
    size_t cbToWrite,
    BYTE* pv,
    size_t cb
)
{
    assert(pv != nullptr);
    assert(cbToWrite <= sizeof(I));

    HRESULT hr = S_OK;

    if (cbToWrite > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    while (cbToWrite > 0)
    {
        pv[cbToWrite - 1] = (toWrite & 0xFF);

        toWrite >>= 8;
        cbToWrite--;
    }

done:
    return hr;

error:
    goto done;
} // end function WriteNetworkLong

HRESULT
WriteRandomBytes(
    BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_FALSE;
    int r = 0;
    size_t cbR = 0;

    while (cb > 0)
    {
        hr = S_OK;

        if (cbR == 0)
        {
            r = rand();
            cbR = sizeof(r);
        }

        pv[0] = r & 0xFF;

        pv++;
        cb--;
        cbR--;
        r >>= 8;
    }

    return hr;
} // end function WriteRandomBytes

HRESULT
EpochTimeFromSystemTime(
    const SYSTEMTIME* pST,
    ULARGE_INTEGER* pLI
)
{
    assert(pLI != nullptr);
    assert(pST != nullptr);

    HRESULT hr = S_OK;

    const SYSTEMTIME st1Jan1970 =
    {
        1970, // year
        1,    // month
        0,    // day of week
        1,    // day
        0,    // hour
        0,    // min
        0,    // sec
        0     // ms
    };

    FILETIME ft = {0};
    FILETIME ft1Jan1970 = {0};
    ULARGE_INTEGER li1Jan1970 = {0};

    if (!SystemTimeToFileTime(pST, &ft))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    pLI->LowPart = ft.dwLowDateTime;
    pLI->HighPart = ft.dwHighDateTime;

    if (!SystemTimeToFileTime(&st1Jan1970, &ft1Jan1970))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    li1Jan1970.LowPart = ft1Jan1970.dwLowDateTime;
    li1Jan1970.HighPart = ft1Jan1970.dwHighDateTime;

    hr = ULongLongSub(pLI->QuadPart, li1Jan1970.QuadPart, &pLI->QuadPart);

    if (hr != S_OK)
    {
        goto error;
    }

    // convert from 100 ns to ms
    pLI->QuadPart /= 10000000ULL;

done:
    return hr;

error:
    goto done;
} // end function EpochTimeFromSystemTime

template <typename T>
HRESULT
SerializeMessagesToVector(
    typename vector<T>::const_iterator itBegin,
    typename vector<T>::const_iterator itEnd,
    ByteVector* pvb
)
{
    HRESULT hr = S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(itBegin, itEnd,
        [&hr, &cbTotal, pvb](const T& rStructure)
        {
            if (hr == S_OK)
            {
                cbTotal += rStructure.Length();
                hr = rStructure.SerializeAppendToVect(pvb);
            }
        }
    );

    if (hr == S_OK)
    {
        assert(cbTotal == pvb->size());
    }

    return hr;
} // end function SerializeMessagesToVector

template <typename T>
HRESULT
SerializeMessagesToVector(
    typename vector<shared_ptr<T>>::const_iterator itBegin,
    typename vector<shared_ptr<T>>::const_iterator itEnd,
    ByteVector* pvb
)
{
    HRESULT hr = S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(itBegin, itEnd,
        [&hr, &cbTotal, pvb](const shared_ptr<T>& rspStructure)
        {
            if (hr == S_OK)
            {
                cbTotal += rspStructure->Length();
                hr = rspStructure->SerializeAppendToVect(pvb);
            }
        }
    );

    if (hr == S_OK)
    {
        assert(cbTotal == pvb->size());
    }

    return hr;
} // end function SerializeMessagesToVector

template <typename T>
void
ResizeVector<T>(
    vector<T>* pv,
    typename vector<T>::size_type siz
)
{
    pv->resize(siz);
} // end function ResizeVector<T>

template <>
void
ResizeVector<BYTE>(
    ByteVector* pv,
    typename ByteVector::size_type siz
)
{
    // arbitrary filler value
    pv->resize(siz, 0x23);
} // end function ResizeVector<BYTE>

template <typename T>
void
EnsureVectorSize<T>(
    vector<T>* pVect,
    typename vector<T>::size_type siz
)
{
    if (siz > pVect->size())
    {
        pVect->resize(siz);
    }
} // end function EnsureVectorSize

HRESULT PrintByteVector(const ByteVector* pvb)
{
     for_each(pvb->begin(), pvb->end(),
     [](BYTE b)
     {
         wprintf(L"%02X ", b);
     });

     wprintf(L"\n");

     return S_OK;
} // end function PrintByteVector

template <typename T>
HRESULT
ParseStructures(
    const ByteVector* pvb,
    vector<T>* pvStructures
)
{
    HRESULT hr = S_OK;
    vector<T> vStructures;

    const BYTE* pv = &pvb->front();
    size_t cb = pvb->size();

    assert(cb > 0);

    while (cb > 0)
    {
        vStructures.emplace_back();
        hr = vStructures.back().ParseFrom(pv, cb);
        if (hr != S_OK)
        {
            vStructures.pop_back();
            break;
        }

        assert(vStructures.back().Length() <= cb);
        pv += vStructures.back().Length();
        cb -= vStructures.back().Length();
    }

    if (vStructures.empty())
    {
        assert(hr != S_OK);
        goto error;
    }

    pvStructures->insert(pvStructures->end(), vStructures.begin(), vStructures.end());

done:
    return hr;

error:
    goto done;
} // end function ParseStructures



/*********** EndpointParameters *****************/

EndpointParameters::EndpointParameters()
    : m_cipherSuite(MTCS_TLS_RSA_WITH_NULL_NULL),
      m_spHasher(),
      m_eVersion(MT_ProtocolVersion::MTPV_Unknown),
      m_vbKey(),
      m_vbMACKey(),
      m_vbIV(),
      m_seqNum(0)
{
} // end ctor EndpointParameters

HRESULT
EndpointParameters::Initialize(
    shared_ptr<SymmetricCipherer> spSymCipherer,
    shared_ptr<Hasher> spHasher
)
{
    m_spSymCipherer = spSymCipherer;
    m_spHasher = spHasher;
    return S_OK;
} // end function Initialize

const CipherInfo*
EndpointParameters::Cipher() const
{
    static CipherInfo cipherInfo =
    {
        CipherAlg_Unknown,
        CipherType_Stream,
        0,
        0,
        0
    };

    HRESULT hr = CryptoInfoFromCipherSuite(CipherSuite(), &cipherInfo, nullptr);
    assert(hr == S_OK);

    return &cipherInfo;
} // end function Cipher

const HashInfo*
EndpointParameters::Hash() const
{
    static HashInfo hashInfo =
    {
        HashAlg_Unknown,
        0,
        0
    };

    HRESULT hr = CryptoInfoFromCipherSuite(CipherSuite(), nullptr, &hashInfo);
    assert(hr == S_OK);

    return &hashInfo;
} // end function Hash

bool
EndpointParameters::IsEncrypted() const
{
    return (Cipher()->alg != CipherAlg_NULL);
} // end function IsEncrypted

/*********** ConnectionParameters *****************/

ConnectionParameters::ConnectionParameters()
    : m_certChain(),
      m_spPubKeyCipherer(nullptr),
      m_vbMasterSecret(),
      m_clientHello(),
      m_clientRandom(),
      m_serverRandom(),
      m_clientVerifyData(),
      m_serverVerifyData(),
      m_vHandshakeMessages()
{
} // end ctor ConnectionParameters

HRESULT
ConnectionParameters::Initialize(
    const MT_CertificateList* pCertChain,
    shared_ptr<PublicKeyCipherer> spPubKeyCipherer,
    shared_ptr<SymmetricCipherer> spClientSymCipherer,
    shared_ptr<SymmetricCipherer> spServerSymCipherer,
    shared_ptr<Hasher> spHasher
)
{
    HRESULT hr = S_OK;

    assert(CertChain()->Data()->empty());

    *CertChain() = *pCertChain;
    m_spPubKeyCipherer = spPubKeyCipherer;

    hr = spClientSymCipherer->Initialize(
             ReadParams()->Key(),
             ReadParams()->Cipher());

    if (hr != S_OK)
    {
        goto error;
    }

    hr = spServerSymCipherer->Initialize(
             WriteParams()->Key(),
             WriteParams()->Cipher());

    if (hr != S_OK)
    {
        goto error;
    }

    // for now passing same hasher into both endpoints. could split up
    hr = ReadParams()->Initialize(spClientSymCipherer, spHasher);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = WriteParams()->Initialize(spServerSymCipherer, spHasher);
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Initialize

HRESULT
ConnectionParameters::ComputePRF(
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    HRESULT hr = S_OK;

    assert(*ReadParams()->Version() == *WriteParams()->Version());
    assert(*ReadParams()->Hash() == *WriteParams()->Hash());

    wprintf(L"protocol version for PRF algorithm: %04LX\n", *ReadParams()->Version());

    if (*ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS10)
    {
        hr = ComputePRF_TLS10(
                 ReadParams()->HashInst()->get(),
                 pvbSecret,
                 szLabel,
                 pvbSeed,
                 cbLengthDesired,
                 pvbPRF);
    }
    else if (*ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
    {
        hr = ComputePRF_TLS11(
                 ReadParams()->HashInst()->get(),
                 pvbSecret,
                 szLabel,
                 pvbSeed,
                 cbLengthDesired,
                 pvbPRF);
    }
    else if (*ReadParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
    {
        hr = ComputePRF_TLS12(
                 ReadParams()->HashInst()->get(),
                 pvbSecret,
                 szLabel,
                 pvbSeed,
                 cbLengthDesired,
                 pvbPRF);
    }
    else
    {
        assert(false);
    }

    if (hr != S_OK)
    {
        goto error;
    }

    assert(pvbPRF->size() == cbLengthDesired);

done:
    return hr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF

HRESULT
ConnectionParameters::ComputeMasterSecret(
    const MT_PreMasterSecret* pPreMasterSecret
)
{
    HRESULT hr = S_OK;

    ByteVector vbPreMasterSecret;
    ByteVector vbRandoms;

    hr = pPreMasterSecret->SerializeToVect(&vbPreMasterSecret);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"premaster secret:\n");
    PrintByteVector(&vbPreMasterSecret);

    hr = ClientRandom()->SerializeToVect(&vbRandoms);
    if (hr != S_OK)
    {
        goto error;
    }

    assert(vbRandoms.size() == ClientRandom()->Length());

    hr = ServerRandom()->SerializeAppendToVect(&vbRandoms);
    if (hr != S_OK)
    {
        goto error;
    }

    assert(vbRandoms.size() == ClientRandom()->Length() + ServerRandom()->Length());

    hr = ComputePRF(
             &vbPreMasterSecret,
             c_szMasterSecret_PRFLabel,
             &vbRandoms,
             c_cbMasterSecret_Length,
             MasterSecret());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(MasterSecret()->size() == c_cbMasterSecret_Length);

done:
    return hr;

error:
    goto done;
} // end function ComputeMasterSecret

HRESULT
ConnectionParameters::GenerateKeyMaterial()
{
    HRESULT hr = S_OK;

    size_t cbKeyBlock;
    ByteVector vbRandoms;
    ByteVector vbKeyBlock;

    wprintf(L"gen key material\n");

    assert(!MasterSecret()->empty());
    assert(*ReadParams()->Cipher() == *WriteParams()->Cipher());
    assert(*ReadParams()->Hash() == *WriteParams()->Hash());

    /*
    ** client and server hash keys
    ** client and server keys
    ** client and server IVs
    */
    cbKeyBlock = (ReadParams()->Hash()->cbHashKeySize * 2) +
                 (ReadParams()->Cipher()->cbKeyMaterialSize * 2) +
                 (ReadParams()->Cipher()->cbIVSize * 2);

    wprintf(L"need %d bytes for key block (%d * 2) + (%d * 2) + (%d * 2)\n",
        cbKeyBlock,
        ReadParams()->Hash()->cbHashKeySize,
        ReadParams()->Cipher()->cbKeyMaterialSize,
        ReadParams()->Cipher()->cbIVSize);

    hr = ServerRandom()->SerializeToVect(&vbRandoms);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = ClientRandom()->SerializeAppendToVect(&vbRandoms);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"randoms: (%d bytes)\n", vbRandoms.size());
    PrintByteVector(&vbRandoms);

    hr = ComputePRF(
             MasterSecret(),
             c_szKeyExpansion_PRFLabel,
             &vbRandoms,
             cbKeyBlock,
             &vbKeyBlock);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"key block:\n");
    PrintByteVector(&vbKeyBlock);

    {
        auto itKeyBlock = vbKeyBlock.begin();

        size_t cbField = ReadParams()->Hash()->cbHashKeySize;
        ReadParams()->MACKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"ReadParams()->MACKey\n");
        PrintByteVector(ReadParams()->MACKey());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = WriteParams()->Hash()->cbHashKeySize;
        WriteParams()->MACKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"WriteParams()->MACKey\n");
        PrintByteVector(WriteParams()->MACKey());



        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = ReadParams()->Cipher()->cbKeyMaterialSize;
        ReadParams()->Key()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"ReadParams()->Key\n");
        PrintByteVector(ReadParams()->Key());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = WriteParams()->Cipher()->cbKeyMaterialSize;
        WriteParams()->Key()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"WriteParams()->Key\n");
        PrintByteVector(WriteParams()->Key());



        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = ReadParams()->Cipher()->cbIVSize;
        ReadParams()->IV()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"ReadParams()->IV\n");
        PrintByteVector(ReadParams()->IV());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = WriteParams()->Cipher()->cbIVSize;
        WriteParams()->IV()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        wprintf(L"WriteParams()->IV\n");
        PrintByteVector(WriteParams()->IV());

        assert(itKeyBlock == vbKeyBlock.end());


        hr = (*ReadParams()->SymCipherer())->Initialize(
                 ReadParams()->Key(),
                 ReadParams()->Cipher());

        if (hr != S_OK)
        {
            goto error;
        }

        hr = (*WriteParams()->SymCipherer())->Initialize(
                 WriteParams()->Key(),
                 WriteParams()->Cipher());

        if (hr != S_OK)
        {
            goto error;
        }
    }

done:
    return hr;

error:
    ReadParams()->MACKey()->clear();
    WriteParams()->MACKey()->clear();
    ReadParams()->Key()->clear();
    WriteParams()->Key()->clear();
    ReadParams()->IV()->clear();
    WriteParams()->IV()->clear();
    goto done;
} // end function GenerateKeyMaterial

HRESULT
ConnectionParameters::CopyCommonParamsTo(
    ConnectionParameters* pDest
)
{
    *pDest->CertChain() = *CertChain();
    *pDest->PubKeyCipherer() = *PubKeyCipherer();
    *pDest->ClientHello() = *ClientHello();
    *pDest->ClientRandom() = *ClientRandom();
    *pDest->ServerRandom() = *ServerRandom();
    *pDest->ClientVerifyData() = *ClientVerifyData();
    *pDest->ServerVerifyData() = *ServerVerifyData();
    *pDest->HandshakeMessages() = *HandshakeMessages();
    *pDest->MasterSecret() = *MasterSecret();
    return S_OK;
} // end function CopyCommonParamsTo

/*********** crypto stuff *****************/

HRESULT
ComputePRF_TLS12(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    HRESULT hr = S_OK;

    ByteVector vbLabelAndSeed;
    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(vbLabelAndSeed.end(), pvbSeed->begin(), pvbSeed->end());

    hr = PRF_P_hash(
             pHasher,
             &c_HashInfo_SHA256,
             pvbSecret,
             &vbLabelAndSeed,
             cbLengthDesired,
             pvbPRF);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(pvbPRF->size() >= cbLengthDesired);
    ResizeVector(pvbPRF, cbLengthDesired);

done:
    return hr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF_TLS12

HRESULT
ComputePRF_TLS10(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    HRESULT hr = S_OK;
    wprintf(L"PRF 1.0\n");

    ByteVector vbLabelAndSeed;
    ByteVector vbS1;
    ByteVector vbS2;
    ByteVector vbS1_Expanded;
    ByteVector vbS2_Expanded;

    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(vbLabelAndSeed.end(), pvbSeed->begin(), pvbSeed->end());

    wprintf(L"label + seed = (%d)\n", vbLabelAndSeed.size());
    PrintByteVector(&vbLabelAndSeed);

    // ceil(size / 2)
    size_t cbL_S1 = (pvbSecret->size() + 1) / 2;

    wprintf(L"L_S = %d, L_S1 = L_S2 = %d\n", pvbSecret->size(), cbL_S1);

    auto itSecretMidpoint = pvbSecret->begin() + cbL_S1;

    vbS1.assign(pvbSecret->begin(), itSecretMidpoint);

    wprintf(L"S1:\n");
    PrintByteVector(&vbS1);

    // makes the two halves overlap by one byte, as required in RFC
    if ((pvbSecret->size() % 2) != 0)
    {
        itSecretMidpoint--;
    }

    vbS2.assign(itSecretMidpoint, pvbSecret->end());

    wprintf(L"S2:\n");
    PrintByteVector(&vbS2);

    assert(vbS1.size() == vbS2.size());

    hr = PRF_P_hash(
             pHasher,
             &c_HashInfo_MD5,
             &vbS1,
             &vbLabelAndSeed,
             cbLengthDesired,
             &vbS1_Expanded);

    if (hr != S_OK)
    {
        goto error;
    }

    hr = PRF_P_hash(
             pHasher,
             &c_HashInfo_SHA1,
             &vbS2,
             &vbLabelAndSeed,
             cbLengthDesired,
             &vbS2_Expanded);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(vbS1_Expanded.size() >= cbLengthDesired);
    assert(vbS2_Expanded.size() >= cbLengthDesired);
    ResizeVector(pvbPRF, cbLengthDesired);

    transform(
        vbS1_Expanded.begin(),
        vbS1_Expanded.begin() + cbLengthDesired,
        vbS2_Expanded.begin(),
        pvbPRF->begin(),
        bit_xor<BYTE>());

done:
    return hr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF_TLS10

HRESULT
PRF_A(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    UINT i,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    ByteVector* pvbResult
)
{
    HRESULT hr = S_OK;
    ByteVector vbTemp;

    // A(0) = seed
    *pvbResult = *pvbSeed;

    while (i > 0)
    {
        vbTemp = *pvbResult;

        hr = pHasher->HMAC(
                          pHashInfo,
                          pvbSecret,
                          &vbTemp,
                          pvbResult);

        if (hr != S_OK)
        {
            goto error;
        }

        i--;
    }

done:
    return hr;

error:
    pvbResult->clear();
    goto done;
} // end function PRF_A

HRESULT
PRF_P_hash(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    size_t cbMinimumLengthDesired,
    ByteVector* pvbResult
)
{
    HRESULT hr = S_OK;

    assert(pvbResult->empty());

    // starts from A(1), not A(0)
    for (UINT i = 1; pvbResult->size() < cbMinimumLengthDesired; i++)
    {
        wprintf(L"PRF_P generated %d out of %d bytes\n", pvbResult->size(), cbMinimumLengthDesired);

        ByteVector vbIteration;
        ByteVector vbInnerSeed;

        hr = PRF_A(
                 pHasher,
                 pHashInfo,
                 i,
                 pvbSecret,
                 pvbSeed,
                 &vbInnerSeed);

        if (hr != S_OK)
        {
            goto error;
        }

        vbInnerSeed.insert(vbInnerSeed.end(), pvbSeed->begin(), pvbSeed->end());

        hr = pHasher->HMAC(
                          pHashInfo,
                          pvbSecret,
                          &vbInnerSeed,
                          &vbIteration);

        if (hr != S_OK)
        {
            goto error;
        }

        pvbResult->insert(pvbResult->end(), vbIteration.begin(), vbIteration.end());
    }

done:
    return hr;

error:
    pvbResult->clear();
    goto done;
} // end function PRF_P_hash

HRESULT
CryptoInfoFromCipherSuite(
    const MT_CipherSuite* pCipherSuite,
    CipherInfo* pCipherInfo,
    HashInfo* pHashInfo
)
{
    HRESULT hr = S_OK;
    MT_CipherSuiteValue eCSV;

    if (pHashInfo == NULL && pCipherInfo == NULL)
    {
        hr = E_INVALIDARG;
        goto error;
    }

    hr = pCipherSuite->Value(&eCSV);
    if (hr != S_OK)
    {
        goto error;
    }

    if (pHashInfo)
    {
        if (eCSV == MTCS_TLS_RSA_WITH_NULL_NULL)
        {
            *pHashInfo = c_HashInfo_NULL;
        }
        else if (eCSV == MTCS_TLS_RSA_WITH_NULL_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_RC4_128_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_3DES_EDE_CBC_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA)
        {
            *pHashInfo = c_HashInfo_SHA1;
        }
        else if (eCSV == MTCS_TLS_RSA_WITH_NULL_SHA256 ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256 ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256)
        {
            *pHashInfo = c_HashInfo_SHA256;
        }
        else
        {
            hr = MT_E_UNSUPPORTED_HASH;
            goto error;
        }
    }

    if (pCipherInfo)
    {
        if (eCSV == MTCS_TLS_RSA_WITH_NULL_NULL ||
            eCSV == MTCS_TLS_RSA_WITH_NULL_MD5 ||
            eCSV == MTCS_TLS_RSA_WITH_NULL_SHA ||
            eCSV == MTCS_TLS_RSA_WITH_NULL_SHA256)
        {
            *pCipherInfo = c_CipherInfo_NULL;
        }
        else if (eCSV == MTCS_TLS_RSA_WITH_RC4_128_MD5 ||
                 eCSV ==  MTCS_TLS_RSA_WITH_RC4_128_SHA)
        {
            *pCipherInfo = c_CipherInfo_RC4_128;
        }
        else if (eCSV == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256)
        {
            *pCipherInfo = c_CipherInfo_AES_128;
        }
        else if (eCSV == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA ||
                 eCSV == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256)
        {
            *pCipherInfo = c_CipherInfo_AES_256;
        }
        else
        {
            hr = MT_E_UNSUPPORTED_CIPHER;
            goto error;
        }
    }

done:
    return hr;

error:
    goto done;
} // end function CryptoInfoFromCipherSuite

/*********** MT_Structure *****************/

HRESULT
MT_Structure::ParseFrom(
    const BYTE* pv,
    size_t cb
)
{
    return ParseFromPriv(pv, cb);
} // end function ParseFrom

HRESULT
MT_Structure::ParseFromVect(
    const ByteVector* pvb
)
{
    return ParseFrom(&(pvb->front()), pvb->size());
} // end function ParseFromVect

HRESULT
MT_Structure::Serialize(
    BYTE* pv,
    size_t cb
) const
{
    return SerializePriv(pv, cb);
} // end function Serialize

HRESULT
MT_Structure::SerializeToVect(
    ByteVector* pvb
) const
{
    pvb->clear();
    return SerializeAppendToVect(pvb);
} // end function SerializeToVect

HRESULT
MT_Structure::SerializeAppendToVect(
    ByteVector* pvb
) const
{
    size_t cSize = pvb->size();
    ResizeVector(pvb, cSize + Length());

    ByteVector::iterator end = pvb->begin() + cSize;

    assert(pvb->end() - (end + Length()) >= 0);
    return Serialize(&(*end), Length());
} // end function SerializeAppendToVect


/*********** MT_Securable *****************/

MT_Securable::MT_Securable()
    : m_pEndParams(nullptr)
{
} // end ctor MT_Securable

HRESULT
MT_Securable::CheckSecurity()
{
    assert(EndParams() != nullptr);
    return CheckSecurityPriv();
} // end function CheckSecurity

/*********** MT_VariableLengthFieldBase *****************/

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::MT_VariableLengthFieldBase()
    : MT_Structure()
{
    assert(LengthFieldSize <= sizeof(size_t));
    assert(MAXFORBYTES(LengthFieldSize) >= MaxSize);
}

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::Length() const
{
    return LengthFieldSize + DataLength();
} // end function Length

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
F*
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::at(
    typename vector<F>::size_type pos
)
{
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
}

/*********** MT_VariableLengthField *****************/

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbTotalElementsSize = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbTotalElementsSize);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    if (cbTotalElementsSize < MinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > MaxSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    while (cbTotalElementsSize > 0)
    {
        F elem;
        hr = elem.ParseFrom(pv, cbTotalElementsSize);
        if (hr != S_OK)
        {
            goto error;
        }

        Data()->push_back(elem);

        cbField = elem.Length();
        ADVANCE_PARSE();
        SAFE_SUB(hr, cbTotalElementsSize, cbField);
    }

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv


template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::DataLength() const
{
    assert(MAXFORBYTES(LengthFieldSize) >= MaxSize);

    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(cbTotalDataLength <= MaxSize);
    assert(cbTotalDataLength >= MinSize);

    return cbTotalDataLength;
} // end function DataLength

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = LengthFieldSize;

    hr = WriteNetworkLong(DataLength(), cbField, pv, cb);
    assert(hr == S_OK);

    ADVANCE_PARSE();

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        ADVANCE_PARSE();
    }

done:
    return hr;

error:
    goto done;
} // end function SerializePriv



/*********** MT_VariableLengthByteField *****************/

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbDataLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbDataLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    if (cbDataLength < MinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbDataLength > MaxSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    cbField = cbDataLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Data()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::DataLength() const
{
    size_t cbTotalDataLength = Count();
    assert(cbTotalDataLength <= MaxSize);
    assert(cbTotalDataLength >= MinSize);

    return cbTotalDataLength;
} // end function DataLength

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = LengthFieldSize;

    hr = WriteNetworkLong(DataLength(), cbField, pv, cb);
    assert(hr == S_OK);

    ADVANCE_PARSE();

    cbField = DataLength();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_FixedLengthStructureBase *****************/

template <typename F, size_t Size>
MT_FixedLengthStructureBase<F, Size>::MT_FixedLengthStructureBase()
    : MT_Structure(),
      m_vData()
{
    assert(Size > 0);
}

template <typename F,
          size_t Size>
F*
MT_FixedLengthStructureBase<F, Size>::at(
    typename vector<F>::size_type pos
)
{
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
}

/*********** MT_FixedLengthStructure *****************/

template <typename F, size_t Size>
HRESULT
MT_FixedLengthStructure<F, Size>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbTotalElementsSize = Size;

    if (cbTotalElementsSize > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    while (cbTotalElementsSize > 0)
    {
        F elem;
        hr = elem.ParseFrom(pv, cbTotalElementsSize);
        if (hr != S_OK)
        {
            goto error;
        }

        Data()->push_back(elem);

        size_t cbField = elem.Length();
        ADVANCE_PARSE();
        SAFE_SUB(hr, cbTotalElementsSize, cbField);
    }

    assert(Length() == Size);

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

template <typename F, size_t Size>
HRESULT
MT_FixedLengthStructure<F, Size>::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        size_t cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        ADVANCE_PARSE();
    }

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

template <typename F, size_t Size>
size_t
MT_FixedLengthStructure<F, Size>::Length() const
{
    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(Size == cbTotalDataLength);

    return cbTotalDataLength;
} // end function Length

/*********** MT_FixedLengthByteStructure *****************/

template <size_t Size>
HRESULT
MT_FixedLengthByteStructure<Size>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Size;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Data()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

template <size_t Size>
HRESULT
MT_FixedLengthByteStructure<Size>::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = Data()->size();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

template <size_t Size>
size_t
MT_FixedLengthByteStructure<Size>::Length() const
{
    assert(Size == Data()->size());
    return Size;
} // end function Length

/*********** MT_PublicKeyEncryptedStructure *****************/

template <typename T>
MT_PublicKeyEncryptedStructure<T>::MT_PublicKeyEncryptedStructure()
    : MT_Structure(),
      m_structure(),
      m_vbEncryptedStructure(),
      m_vbPlaintextStructure(),
      m_pCipherer(nullptr)
{
} // end ctor MT_PublicKeyEncryptedStructure

template <typename T>
HRESULT
MT_PublicKeyEncryptedStructure<T>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbPublicKeyEncrypted_LFL;
    size_t cbStructureLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbStructureLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbStructureLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    EncryptedStructure()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

template <typename T>
size_t
MT_PublicKeyEncryptedStructure<T>::Length() const
{
    size_t cbLength = EncryptedStructure()->size();
    return cbLength;
} // end function Length

template <typename T>
HRESULT
MT_PublicKeyEncryptedStructure<T>::DecryptStructure()
{
    HRESULT hr = S_OK;
    PlaintextStructure()->clear();

    hr = GetCipherer()->DecryptBufferWithPrivateKey(
             EncryptedStructure(),
             PlaintextStructure());

    if (hr != S_OK)
    {
        goto error;
    }

    hr = Structure()->ParseFromVect(PlaintextStructure());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function DecryptStructure


/*********** MT_RecordLayerMessage *****************/

MT_RecordLayerMessage::MT_RecordLayerMessage()
    : MT_Structure(),
      MT_ConnectionAware(),
      m_contentType(),
      m_protocolVersion(),
      m_vbFragment()
{
} // end ctor MT_RecordLayerMessage

HRESULT
MT_RecordLayerMessage::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;
    size_t cbFragmentLength = 0;

    hr = ContentType()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ContentType()->Length();
    ADVANCE_PARSE();

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    ADVANCE_PARSE();


    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    hr = ReadNetworkLong(pv, cb, cbField, &cbFragmentLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbFragmentLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Fragment()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

MT_UINT16
MT_RecordLayerMessage::PayloadLength() const
{
    size_t cbLength = Fragment()->size();
    assert(cbLength <= UINT16_MAX);
    return static_cast<MT_UINT16>(cbLength);
} // end function PayloadLength

size_t
MT_RecordLayerMessage::Length() const
{
    size_t cbLength = ContentType()->Length() +
                      ProtocolVersion()->Length() +
                      c_cbRecordLayerMessage_Fragment_LFL +
                      PayloadLength();

    return cbLength;
} // end function Length

HRESULT
MT_RecordLayerMessage::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = ContentType()->Length();

    hr = ContentType()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = ProtocolVersion()->Length();
    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = PayloadLength();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(Fragment()->begin(), Fragment()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_TLSCiphertext *****************/

MT_TLSCiphertext::MT_TLSCiphertext()
    : MT_RecordLayerMessage(),
      MT_Securable(),
      m_spCipherFragment()
{
} // end ctor MT_TLSCiphertext

HRESULT
MT_TLSCiphertext::SetSecurityParameters(
    EndpointParameters* pEndParams
)
{
    HRESULT hr = S_OK;

    hr = MT_Securable::SetSecurityParameters(pEndParams);
    if (hr != S_OK)
    {
        goto error;
    }

    if (EndParams()->Cipher()->type == CipherType_Stream)
    {
        m_spCipherFragment = shared_ptr<MT_CipherFragment>(new MT_GenericStreamCipher());
    }
    else if (EndParams()->Cipher()->type == CipherType_Block)
    {
        if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS10)
        {
            m_spCipherFragment = shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS10());
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
        {
            m_spCipherFragment = shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS11());
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
        {
            m_spCipherFragment = shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS12());
        }
        else
        {
            assert(false);
        }
    }
    else
    {
        assert(false);
    }

    hr = CipherFragment()->SetSecurityParameters(EndParams());
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function SetSecurityParameters

HRESULT
MT_TLSCiphertext::Decrypt()
{
    HRESULT hr = S_OK;

    hr = CipherFragment()->SetSecurityParameters(EndParams());
    if (hr != S_OK)
    {
        goto error;
    }

    /*
    ** it is crucial that this pass in exactly the fragment assigned to this
    ** TLSCiphertext--no more, no less--because CipherFragment itself has no
    ** way to validate the length. it just accepts everything it's given
    */
    hr = CipherFragment()->ParseFromVect(Fragment());
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Decrypt

HRESULT
MT_TLSCiphertext::Encrypt()
{
    HRESULT hr = S_OK;

    hr = CipherFragment()->SerializeToVect(Fragment());
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Encrypt

HRESULT
MT_TLSCiphertext::ToTLSPlaintext(
    MT_TLSPlaintext* pPlaintext
)
{
    assert(*pPlaintext->Conn() == nullptr);
    *pPlaintext->Conn() = *Conn();

    *(pPlaintext->ContentType()) = *ContentType();
    *(pPlaintext->ProtocolVersion()) = *ProtocolVersion();

    // assumes it has already been decrypted
    *(pPlaintext->Fragment()) = *(CipherFragment()->Content());

    return S_OK;
} // end function ToTLSPlaintext

HRESULT
MT_TLSCiphertext::FromTLSPlaintext(
    MT_TLSPlaintext* pPlaintext,
    EndpointParameters* pEndParams,
    shared_ptr<MT_TLSCiphertext>* pspCiphertext
)
{
    HRESULT hr = S_OK;

    pspCiphertext->reset(new MT_TLSCiphertext());

    hr = (*pPlaintext->Conn())->CreateCiphertext(
             *pPlaintext->ContentType()->Type(),
             *pPlaintext->ProtocolVersion()->Version(),
             pPlaintext->Fragment(),
             pEndParams,
             pspCiphertext->get());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function FromTLSPlaintext

HRESULT
MT_TLSCiphertext::UpdateFragmentSecurity()
{
    HRESULT hr = S_OK;

    if (EndParams()->Cipher()->type == CipherType_Stream)
    {
        MT_GenericStreamCipher* pStreamCipher = static_cast<MT_GenericStreamCipher*>(CipherFragment());

        hr = pStreamCipher->UpdateWriteSecurity(
                  ContentType(),
                  ProtocolVersion());

        if (hr != S_OK)
        {
            goto error;
        }
    }
    else if (EndParams()->Cipher()->type == CipherType_Block)
    {
        if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS10)
        {
            MT_GenericBlockCipher_TLS10* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS10*>(CipherFragment());

            hr = pBlockCipher->UpdateWriteSecurity(
                      ContentType(),
                      ProtocolVersion());

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
        {
            MT_GenericBlockCipher_TLS11* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS11*>(CipherFragment());

            *pBlockCipher->IVNext() = *EndParams()->IV();

            hr = pBlockCipher->UpdateWriteSecurity(
                      ContentType(),
                      ProtocolVersion());

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
        {
            MT_GenericBlockCipher_TLS12* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS12*>(CipherFragment());

            *pBlockCipher->IVNext() = *EndParams()->IV();

            hr = pBlockCipher->UpdateWriteSecurity(
                      ContentType(),
                      ProtocolVersion());

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else
        {
            assert(false);
        }
    }
    else
    {
        assert(false);
    }

done:
    return hr;

error:
    goto done;
} // end function UpdateFragmentSecurity

HRESULT
MT_TLSCiphertext::CheckSecurityPriv()
{
    HRESULT hr = S_OK;
    MT_ProtocolVersion hashVersion(*ProtocolVersion());

    /*
    ** there is a bug in chrome in which the clienthello sometimes has a
    ** different version specified in its record layer than in its handshake
    ** layer. normally we could handle this, but it also incorrectly passes the
    ** handshake layer's version to the MAC function.
    **
    ** if we detect such a mismatch here, we ask the app if it wants to
    ** reconcile it. the default behavior is to strictly follow the RFC and use
    ** the record layer version
    */
    if (*EndParams()->Version() != *hashVersion.Version())
    {
        MT_ProtocolVersion::MTPV_Version ver;

        wprintf(L"reconciling version mismatch between conn:%04LX and record:%04LX\n", *EndParams()->Version(), *hashVersion.Version());

        hr = (*Conn())->Listener()->OnReconcileSecurityVersion(
                 this,
                 *EndParams()->Version(),
                 *hashVersion.Version(),
                 &ver);

        if (hr == MT_S_LISTENER_HANDLED)
        {
            *hashVersion.Version() = ver;
        }
        else if (hr != MT_S_LISTENER_IGNORED)
        {
            goto error;
        }
        // else retain current record's protocol version
    }

    if (EndParams()->Cipher()->type == CipherType_Stream)
    {
        MT_GenericStreamCipher* pStreamCipher = static_cast<MT_GenericStreamCipher*>(CipherFragment());
        hr = pStreamCipher->CheckSecurity(
                 ContentType(),
                 &hashVersion);

        if (hr != S_OK)
        {
            goto error;
        }
    }
    else if (EndParams()->Cipher()->type == CipherType_Block)
    {
        if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS10)
        {
            MT_GenericBlockCipher_TLS10* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS10*>(CipherFragment());
            hr = pBlockCipher->CheckSecurity(
                     ContentType(),
                     &hashVersion);

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
        {
            MT_GenericBlockCipher_TLS11* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS11*>(CipherFragment());
            hr = pBlockCipher->CheckSecurity(
                     ContentType(),
                     &hashVersion);

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
        {
            MT_GenericBlockCipher_TLS12* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS12*>(CipherFragment());
            hr = pBlockCipher->CheckSecurity(
                     ContentType(),
                     &hashVersion);

            if (hr != S_OK)
            {
                goto error;
            }
        }
        else
        {
            assert(false);
        }
    }
    else
    {
        assert(false);
    }

done:
    return hr;

error:
    goto done;
} // end function CheckSecurityPriv

/*********** MT_ContentType *****************/

MT_ContentType::MT_ContentType()
    : MT_Structure(),
      m_eType(MTCT_Type_Unknown)
{
}

const MT_ContentType::MTCT_Type MT_ContentType::c_rgeValidTypes[] =
{
    MTCT_Type_ChangeCipherSpec,
    MTCT_Type_Alert,
    MTCT_Type_Handshake,
    MTCT_Type_ApplicationData,
    MTCT_Type_Unknown,
};

const ULONG MT_ContentType::c_cValidTypes = ARRAYSIZE(c_rgeValidTypes);


HRESULT
MT_ContentType::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbContentType_Length);

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<BYTE*>(Type()));
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_ContentType::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    size_t cbField = Length();
    assert(Length() == c_cbContentType_Length);

    hr = WriteNetworkLong(static_cast<ULONG>(*Type()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

bool
MT_ContentType::IsValidContentType(
    MTCT_Type eType
)
{
    return (find(c_rgeValidTypes, c_rgeValidTypes+c_cValidTypes, eType) != c_rgeValidTypes+c_cValidTypes);
} // end function IsValidContentType

wstring
MT_ContentType::ToString() const
{
    switch (*Type())
    {
        case MTCT_Type_ChangeCipherSpec:
            return wstring(L"ChangeCipherSpec");
        break;

        case MTCT_Type_Alert:
            return wstring(L"Alert");
        break;

        case MTCT_Type_Handshake:
            return wstring(L"Handshake");
        break;

        case MTCT_Type_ApplicationData:
            return wstring(L"ApplicationData");
        break;

        default:
            return wstring(L"UnknownContentType");
        break;
    }
} // end function ToString


/*********** MT_ProtocolVersion *****************/

MT_ProtocolVersion::MT_ProtocolVersion()
    : MT_Structure(),
      m_eVersion(MTPV_Unknown)
{
} // end ctor MT_ProtocolVersion

HRESULT
MT_ProtocolVersion::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbProtocolVersion_Length);

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Version()));
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    if (!IsKnownVersion(*Version()))
    {
        wprintf(L"warning: unknown protocol version: %02X\n", *Version());
    }

done:
    return hr;

error:
    *Version() = MTPV_Unknown;
    goto done;
} // end function ParseFromPriv

HRESULT
MT_ProtocolVersion::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbProtocolVersion_Length);

    hr = WriteNetworkLong(static_cast<ULONG>(*Version()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

bool
MT_ProtocolVersion::IsKnownVersion(
    MTPV_Version eVersion
)
{
    return (eVersion == MTPV_TLS10 ||
            eVersion == MTPV_TLS11 ||
            eVersion == MTPV_TLS12);
} // end function IsKnownVersion


/*********** MT_Handshake *****************/

const MT_Handshake::MTH_HandshakeType MT_Handshake::c_rgeKnownTypes[] =
{
    MTH_HelloRequest,
    MTH_ClientHello,
    MTH_ServerHello,
    MTH_Certificate,
    MTH_ServerKeyExchange,
    MTH_CertificateRequest,
    MTH_ServerHelloDone,
    MTH_CertificateVerify,
    MTH_ClientKeyExchange,
    MTH_Finished,
    MTH_Unknown,
};

const ULONG MT_Handshake::c_cKnownTypes = ARRAYSIZE(c_rgeKnownTypes);

const MT_Handshake::MTH_HandshakeType MT_Handshake::c_rgeSupportedTypes[] =
{
    MTH_ClientHello,
    MTH_ServerHello,
    MTH_Certificate,
    MTH_ServerKeyExchange,
    MTH_ServerHelloDone,
    MTH_CertificateVerify,
    MTH_ClientKeyExchange,
    MTH_Finished,
};

const ULONG MT_Handshake::c_cSupportedTypes = ARRAYSIZE(c_rgeSupportedTypes);

MT_Handshake::MT_Handshake()
    : MT_Structure(),
      m_eType(MTH_Unknown),
      m_vbBody()
{
} // end ctor MT_Handshake

HRESULT
MT_Handshake::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbHandshakeType_Length;
    size_t cbPayloadLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Type()));
    if (hr != S_OK)
    {
        goto error;
    }

    if (!IsKnownType(*Type()))
    {
        wprintf(L"warning: unknown handshake type: %d\n", *Type());
    }

    if (!IsSupportedType(*Type()))
    {
        hr = MT_E_UNSUPPORTED_HANDSHAKE_TYPE;
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbHandshake_LFL;
    hr = ReadNetworkLong(pv, cb, cbField, &cbPayloadLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbPayloadLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Body()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

size_t
MT_Handshake::Length() const
{
    return c_cbHandshakeType_Length +
           c_cbHandshake_LFL +
           PayloadLength();
} // end function Length

bool
MT_Handshake::IsKnownType(
    MTH_HandshakeType eType
)
{
    return (find(c_rgeKnownTypes, c_rgeKnownTypes+c_cKnownTypes, eType) != c_rgeKnownTypes+c_cKnownTypes);
} // end function IsKnownType

bool
MT_Handshake::IsSupportedType(
    MTH_HandshakeType eType
)
{
    return (find(c_rgeSupportedTypes, c_rgeSupportedTypes+c_cSupportedTypes, eType) != c_rgeSupportedTypes+c_cSupportedTypes);
} // end function IsSupportedType

HRESULT
MT_Handshake::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbHandshakeType_Length;

    hr = WriteNetworkLong(static_cast<ULONG>(*Type()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbHandshake_LFL;
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = PayloadLength();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(Body()->begin(), Body()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

wstring MT_Handshake::HandshakeTypeString() const
{
    PCWSTR wszType = nullptr;

    switch (*Type())
    {
        case MTH_HelloRequest:
        wszType = L"HelloRequest";
        break;

        case MTH_ClientHello:
        wszType = L"ClientHello";
        break;

        case MTH_ServerHello:
        wszType = L"ServerHello";
        break;

        case MTH_Certificate:
        wszType = L"Certificate";
        break;

        case MTH_ServerKeyExchange:
        wszType = L"ServerKeyExchange";
        break;

        case MTH_CertificateRequest:
        wszType = L"CertificateRequest";
        break;

        case MTH_ServerHelloDone:
        wszType = L"ServerHelloDone";
        break;

        case MTH_CertificateVerify:
        wszType = L"CertificateVerify";
        break;

        case MTH_ClientKeyExchange:
        wszType = L"ClientKeyExchange";
        break;

        case MTH_Finished:
        wszType = L"Finished";
        break;

        default:
        wszType = L"Unknown";
        break;
    }

    return wstring(wszType);
} // end function HandshakeTypeString

/*********** MT_Random *****************/

MT_Random::MT_Random()
    : MT_Structure(),
      m_timestamp(0),
      m_vbRandomBytes()
{
} // end ctor MT_Random

HRESULT
MT_Random::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;

    size_t cbField = c_cbRandomTime_Length;
    hr = ReadNetworkLong(pv, cb, cbField, &m_timestamp);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbRandomBytes_Length;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    RandomBytes()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_Random::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbRandomTime_Length;

    hr = WriteNetworkLong(GMTUnixTime(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    assert(RandomBytes()->size() == c_cbRandomBytes_Length);
    cbField = RandomBytes()->size();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(RandomBytes()->begin(), RandomBytes()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

HRESULT
MT_Random::PopulateNow()
{
    HRESULT hr = S_OK;

    SYSTEMTIME st = {0};
    GetSystemTime(&st);

    ULARGE_INTEGER li = {0};
    hr = EpochTimeFromSystemTime(&st, &li);

    if (hr != S_OK)
    {
        goto error;
    }

    MT_UINT32 t = 0;
    hr = ULongLongToULong(li.QuadPart, &t);

    if (hr != S_OK)
    {
        goto error;
    }

    SetGMTUnixTime(t);

    ResizeVector(RandomBytes(), c_cbRandomBytes_Length);
    /*
    hr = WriteRandomBytes(&RandomBytes()->front(), RandomBytes()->size());

    if (hr != S_OK)
    {
        goto error;
    }
    */

done:
    return hr;

error:
    goto done;
} // end function PopulateNow


/*********** MT_ClientHello *****************/

MT_ClientHello::MT_ClientHello()
    : MT_Structure(),
      m_protocolVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuites(),
      m_compressionMethods(),
      m_extensions()
{
}

HRESULT
MT_ClientHello::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    ADVANCE_PARSE();

    hr = Random()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Random()->Length();
    ADVANCE_PARSE();

    hr = SessionID()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = SessionID()->Length();
    ADVANCE_PARSE();

    hr = CipherSuites()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CipherSuites()->Length();
    ADVANCE_PARSE();

    hr = CompressionMethods()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CompressionMethods()->Length();
    ADVANCE_PARSE();

    hr = Extensions()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Extensions()->Length();
    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
}

size_t
MT_ClientHello::Length() const
{
    size_t cbLength = ProtocolVersion()->Length() +
                      Random()->Length() +
                      SessionID()->Length() +
                      CipherSuites()->Length() +
                      CompressionMethods()->Length() +
                      Extensions()->Length();

    return cbLength;
} // end function Length

/*********** MT_CompressionMethod *****************/

MT_CompressionMethod::MT_CompressionMethod()
    : MT_Structure(),
      m_eMethod(MTCM_Unknown)
{
}

HRESULT
MT_CompressionMethod::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbCompressionMethod_Length);

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Method()));
    if (hr != S_OK)
    {
        goto error;
    }

    if (*Method() != MTCM_Null)
    {
        wprintf(L"unknown compression method: %d\n", *Method());
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_CompressionMethod::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbCompressionMethod_Length);

    hr = WriteNetworkLong(static_cast<ULONG>(*Method()), cbField, pv, cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_ServerHello *****************/

MT_ServerHello::MT_ServerHello()
    : MT_Structure(),
      m_protocolVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuite(),
      m_compressionMethod(),
      m_extensions()
{
} // end ctor MT_ServerHello

size_t
MT_ServerHello::Length() const
{
    size_t cbLength = ProtocolVersion()->Length() +
                      Random()->Length() +
                      SessionID()->Length() +
                      CipherSuite()->Length() +
                      CompressionMethod()->Length();

    if (Extensions()->Count() > 0)
    {
        cbLength += Extensions()->Length();
    }

    return cbLength;
} // end function Length

HRESULT
MT_ServerHello::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = ProtocolVersion()->Length();

    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = Random()->Length();
    hr = Random()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = SessionID()->Length();
    hr = SessionID()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = CipherSuite()->Length();
    hr = CipherSuite()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = CompressionMethod()->Length();
    hr = CompressionMethod()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    if (Extensions()->Count() > 0)
    {
        cbField = Extensions()->Length();
        hr = Extensions()->Serialize(pv, cb);
        if (hr != S_OK)
        {
            goto error;
        }

        ADVANCE_PARSE();
    }

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_Certificate *****************/

MT_Certificate::MT_Certificate()
    : MT_Structure(),
      m_certificateList()
{
} // end ctor MT_Certificate

HRESULT
MT_Certificate::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    hr = CertificateList()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

HRESULT
MT_Certificate::AddCertificateFromMemory(
    const BYTE* pvCert,
    size_t cbCert
)
{
    MT_ASN1Cert cert;
    cert.Data()->assign(pvCert, pvCert + cbCert);
    CertificateList()->Data()->push_back(cert);
    return S_OK;
} // end function AddCertificateFromMemory

/*********** MT_SessionID *****************/

HRESULT
MT_SessionID::PopulateWithRandom()
{
    HRESULT hr = S_OK;

    ResizeVector(Data(), MaxLength());
    hr = WriteRandomBytes(&Data()->front(), Data()->size());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function PopulateWithRandom

/*********** MT_PreMasterSecret *****************/

MT_PreMasterSecret::MT_PreMasterSecret()
    : MT_Structure(),
      m_clientVersion(),
      m_random()
{
} // end ctor MT_PreMasterSecret

HRESULT
MT_PreMasterSecret::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    hr = ClientVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ClientVersion()->Length();
    ADVANCE_PARSE();

    hr = Random()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Random()->Length();
    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_PreMasterSecret::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    hr = ClientVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ClientVersion()->Length();
    ADVANCE_PARSE();

    hr = Random()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Random()->Length();
    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

size_t
MT_PreMasterSecret::Length() const
{
    size_t cbLength = ClientVersion()->Length() +
                      Random()->Length();

    return cbLength;
} // end function Length


/*********** MT_CipherSuite *****************/

const MT_CipherSuiteValue c_rgeCipherSuitePreference[] =
{
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256,
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA,
      MTCS_TLS_RSA_WITH_RC4_128_SHA,
      MTCS_TLS_RSA_WITH_RC4_128_MD5
};

const vector<MT_CipherSuiteValue>* GetCipherSuitePreference()
{
    static vector<MT_CipherSuiteValue> s_veCipherSuiteValues;

    // first time initialization
    if (s_veCipherSuiteValues.empty())
    {
        s_veCipherSuiteValues.assign(
            c_rgeCipherSuitePreference,
            c_rgeCipherSuitePreference + ARRAYSIZE(c_rgeCipherSuitePreference));
    }

    return &s_veCipherSuiteValues;
} // end function GetCipherSuitePreference

bool
IsKnownCipherSuite(
    MT_CipherSuiteValue eSuite
)
{
    const vector<MT_CipherSuiteValue>* pveCipherSuites = GetCipherSuitePreference();

    return (find(
                pveCipherSuites->begin(),
                pveCipherSuites->end(),
                eSuite)
                != pveCipherSuites->end());
} // end function IsKnownCipherSuite

HRESULT
ChooseBestCipherSuite(
    const vector<MT_CipherSuiteValue>* pveClientPreference,
    const vector<MT_CipherSuiteValue>* pveServerPreference,
    MT_CipherSuiteValue* pePreferredCipherSuite
)
{
    HRESULT hr = S_OK;

    for (auto itServer = pveServerPreference->begin(); itServer != pveServerPreference->end(); itServer++)
    {
        for (auto itClient = pveClientPreference->begin(); itClient != pveClientPreference->end(); itClient++)
        {
            if (*itClient == *itServer)
            {
                *pePreferredCipherSuite = *itServer;
                goto done;
            }
        }
    }

    hr = MT_E_NO_PREFERRED_CIPHER_SUITE;
    goto error;

done:
    return hr;

error:
    goto done;
} // end function ChooseBestCipherSuite

MT_CipherSuite::MT_CipherSuite()
    : MT_FixedLengthByteStructure()
{
} // end ctor MT_CipherSuite

MT_CipherSuite::MT_CipherSuite(MT_CipherSuiteValue eValue)
    : MT_FixedLengthByteStructure()
{
    HRESULT hr = SetValue(eValue);
    assert(hr == S_OK);
} // end ctor MT_CipherSuite

HRESULT
MT_CipherSuite::KeyExchangeAlgorithm(
    MT_KeyExchangeAlgorithm* pAlg
) const
{
    HRESULT hr = S_OK;
    MT_CipherSuiteValue eCSV;

    hr = Value(&eCSV);
    if (hr != S_OK)
    {
        goto error;
    }

    if (IsKnownCipherSuite(eCSV))
    {
        *pAlg = MTKEA_rsa;
    }
    else
    {
        hr = MT_E_UNKNOWN_CIPHER_SUITE;
    }

done:
    return hr;

error:
    goto done;
} // end function KeyExchangeAlgorithm

HRESULT
MT_CipherSuite::Value(
    MT_CipherSuiteValue* peValue
) const
{
    MT_CipherSuiteValue cs;

    assert(Data()->size() <= sizeof(cs));
    assert(Data()->size() == c_cbCipherSuite_Length);

    HRESULT hr = ReadNetworkLong(
                     &Data()->front(),
                     Data()->size(),
                     Data()->size(),
                     reinterpret_cast<ULONG*>(&cs));

    if (hr == S_OK)
    {
        *peValue = cs;
    }

    return hr;
} // end function Value

HRESULT
MT_CipherSuite::SetValue(
    MT_CipherSuiteValue eValue
)
{
    HRESULT hr = S_OK;

    ResizeVector(Data(), c_cbCipherSuite_Length);

    hr = WriteNetworkLong(
             static_cast<ULONG>(eValue),
             Data()->size(),
             &Data()->front(),
             Data()->size());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function SetValue

bool
MT_CipherSuite::operator==(
    const MT_CipherSuite& rOther
) const
{
    HRESULT hr = S_OK;
    MT_CipherSuiteValue eValue;
    MT_CipherSuiteValue eOtherValue;
    hr = Value(&eValue);
    if (hr != S_OK)
    {
        return false;
    }

    hr = rOther.Value(&eOtherValue);
    if (hr != S_OK)
    {
        return false;
    }

    return eValue == eOtherValue;
} // end operator==

/*********** MT_ClientKeyExchange *****************/

template <typename KeyType>
MT_ClientKeyExchange<KeyType>::MT_ClientKeyExchange()
    : m_spExchangeKeys()
{
} // end ctor MT_ClientKeyExchange

template <typename KeyType>
HRESULT
MT_ClientKeyExchange<KeyType>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    assert(ExchangeKeys() == nullptr);

    m_spExchangeKeys = shared_ptr<KeyType>(new KeyType());

    hr = ExchangeKeys()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ExchangeKeys()->Length();
    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

/*********** MT_ChangeCipherSpec *****************/

MT_ChangeCipherSpec::MT_ChangeCipherSpec()
    : MT_Structure(),
      m_eType(MTCCS_Unknown)
{
} // end ctor MT_ChangeCipherSpec

HRESULT
MT_ChangeCipherSpec::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbChangeCipherSpec_Length);

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Type()));
    if (hr != S_OK)
    {
        goto error;
    }

    if (*Type() != MTCCS_ChangeCipherSpec)
    {
        wprintf(L"unrecognized change cipher spec type: %d\n", *Type());
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_ChangeCipherSpec::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbChangeCipherSpec_Length);

    hr = WriteNetworkLong(static_cast<BYTE>(*Type()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_Extension *****************/

MT_Extension::MT_Extension()
    : MT_Structure(),
      m_extensionType(MTEE_Unknown),
      m_vbExtensionData()
{
} // end ctor MT_Extension

HRESULT
MT_Extension::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbExtensionType_Length;
    size_t cbExtensionLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(ExtensionType()));
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbExtensionData_LFL;
    hr = ReadNetworkLong(pv, cb, cbField, &cbExtensionLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbExtensionLength;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    ExtensionData()->assign(pv, pv + cbField);
    assert(ExtensionData()->size() == cbExtensionLength);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

size_t
MT_Extension::Length() const
{
    size_t cbLength = c_cbExtensionType_Length +
                      c_cbExtensionData_LFL +
                      ExtensionData()->size();
    return cbLength;
} // end function Length

HRESULT
MT_Extension::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    cbField = c_cbExtensionType_Length;
    hr = WriteNetworkLong(static_cast<ULONG>(*ExtensionType()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbExtensionData_LFL;
    hr = WriteNetworkLong(ExtensionData()->size(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = ExtensionData()->size();
    if (cbField > cb)
    {
        goto error;
    }

    std::copy(ExtensionData()->begin(), ExtensionData()->end(), pv);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_Finished *****************/

MT_Finished::MT_Finished()
    : MT_Structure(),
      MT_Securable(),
      m_verifyData()
{
} // end ctor MT_Finished

HRESULT
MT_Finished::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    return VerifyData()->ParseFrom(pv, cb);
} // end function ParseFromPriv

HRESULT
MT_Finished::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    return VerifyData()->Serialize(pv, cb);
} // end function SerializePriv

HRESULT
MT_Finished::CheckSecurityPriv()
{
    HRESULT hr = S_OK;

    ByteVector vbComputedVerifyData;

    hr = ComputeVerifyData(
             c_szClientFinished_PRFLabel,
             &vbComputedVerifyData);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"Received Finished hash:\n");
    PrintByteVector(VerifyData()->Data());

    if (vbComputedVerifyData != *VerifyData()->Data())
    {
        hr = MT_E_BAD_FINISHED_HASH;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CheckSecurityPriv

HRESULT
MT_Finished::ComputeVerifyData(
    PCSTR szLabel,
    ByteVector* pvbVerifyData
)
{
    HRESULT hr = S_OK;

    ByteVector vbHandshakeMessages;
    ByteVector vbHashedHandshakeMessages;

    {
        wprintf(L"working on the following handshake messages:\n");
        for_each(
            ConnParams()->HandshakeMessages()->begin(),
            ConnParams()->HandshakeMessages()->end(),
            [] (const shared_ptr<MT_Structure> spStructure)
            {
                MT_Handshake* pHandshakeMessage = static_cast<MT_Handshake*>(spStructure.get());
                wprintf(L"    %s\n", pHandshakeMessage->HandshakeTypeString().c_str());
            }
        );
    }

    hr = SerializeMessagesToVector<MT_Structure>(
             ConnParams()->HandshakeMessages()->begin(),
             ConnParams()->HandshakeMessages()->end(),
             &vbHandshakeMessages);

    if (hr != S_OK)
    {
        goto error;
    }

    if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS10 ||
        *EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS11)
    {
        ByteVector vbMD5HandshakeHash;
        ByteVector vbSHA1HandshakeHash;
        ByteVector vbHandshakeHash;

        hr = (*EndParams()->HashInst())->Hash(
                 &c_HashInfo_MD5,
                 &vbHandshakeMessages,
                 &vbMD5HandshakeHash);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = (*EndParams()->HashInst())->Hash(
                 &c_HashInfo_SHA1,
                 &vbHandshakeMessages,
                 &vbSHA1HandshakeHash);

        if (hr != S_OK)
        {
            goto error;
        }

        vbHashedHandshakeMessages = vbMD5HandshakeHash;
        vbHashedHandshakeMessages.insert(
            vbHashedHandshakeMessages.end(),
            vbSHA1HandshakeHash.begin(),
            vbSHA1HandshakeHash.end());
    }
    else if (*EndParams()->Version() == MT_ProtocolVersion::MTPV_TLS12)
    {
        hr = (*EndParams()->HashInst())->Hash(
                 &c_HashInfo_SHA256,
                 &vbHandshakeMessages,
                 &vbHashedHandshakeMessages);

        if (hr != S_OK)
        {
            goto error;
        }
    }
    else
    {
        wprintf(L"unrecognized version: %04LX\n", *EndParams()->Version());
        hr = MT_E_UNKNOWN_PROTOCOL_VERSION;
        goto error;
    }

    hr = ConnParams()->ComputePRF(
             ConnParams()->MasterSecret(),
             szLabel,
             &vbHashedHandshakeMessages,
             c_cbFinishedVerifyData_Length,
             pvbVerifyData);

    if (hr != S_OK)
    {
        goto error;
    }

    printf("Computed Finished hash with label \"%s\":\n", szLabel);
    PrintByteVector(pvbVerifyData);

done:
    return hr;

error:
    goto done;
} // end function ComputeVerifyData

/*********** MT_CipherFragment *****************/

MT_CipherFragment::MT_CipherFragment()
    : MT_Structure(),
      MT_Securable(),
      m_vbContent(),
      m_vbRawContent()
{
} // end ctor MT_CipherFragment

HRESULT
MT_CipherFragment::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = cb;

    RawContent()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    assert(cb == 0);

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_CipherFragment::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(RawContent()->begin(), RawContent()->end(), pv);

    ADVANCE_PARSE();

    assert(cb == 0);

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

size_t
MT_CipherFragment::Length() const
{
    size_t cbLength = RawContent()->size();

    return cbLength;
} // end function Length

/*********** MT_GenericStreamCipher *****************/

MT_GenericStreamCipher::MT_GenericStreamCipher()
    : MT_CipherFragment(),
      m_vbMAC()
{
} // end ctor MT_GenericStreamCipher

HRESULT
MT_GenericStreamCipher::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    const HashInfo* pHashInfo = EndParams()->Hash();
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = MT_CipherFragment::ParseFromPriv(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    /*
    ** we have to be careful only to call this when we mean it, or else it
    ** changes the internal state of the cipherer down in cryptapi
    */
    hr = (*EndParams()->SymCipherer())->DecryptBuffer(
             RawContent(),
             nullptr,
             &vbDecryptedStruct);

    if (hr != S_OK)
    {
        goto error;
    }

    pv = &vbDecryptedStruct.front();
    cb = vbDecryptedStruct.size();

    // allows for 0-length content
    assert(cb >= pHashInfo->cbHashSize);

    cbField = cb - pHashInfo->cbHashSize;
    Content()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    assert(cb == pHashInfo->cbHashSize);
    cbField = pHashInfo->cbHashSize;
    MAC()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_GenericStreamCipher::UpdateWriteSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion)
{
    HRESULT hr = S_OK;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = ComputeSecurityInfo(
              *EndParams()->SequenceNumber(),
              EndParams()->MACKey(),
              pContentType,
              pProtocolVersion,
              MAC());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(MAC()->size() == EndParams()->Hash()->cbHashSize);

    cb = Content()->size() +
         MAC()->size();
    ResizeVector(&vbDecryptedStruct, cb);
    pv = &vbDecryptedStruct.front();

    cbField = Content()->size();
    assert(cbField <= cb);
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();

    cbField = MAC()->size();
    assert(cbField <= cb);
    std::copy(MAC()->begin(), MAC()->end(), pv);

    ADVANCE_PARSE();

    assert(cb == 0);

    hr = (*EndParams()->SymCipherer())->EncryptBuffer(
             &vbDecryptedStruct,
             EndParams()->IV(),
             RawContent());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(!RawContent()->empty());

done:
    return hr;

error:
    goto done;
} // end function UpdateWriteSecurity

HRESULT
MT_GenericStreamCipher::ComputeSecurityInfo(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC
)
{
    HRESULT hr = S_OK;

    ByteVector vbHashText;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;

    const HashInfo* pHashInfo = EndParams()->Hash();

    cb = c_cbSequenceNumber_Length +
         c_cbContentType_Length +
         c_cbProtocolVersion_Length +
         c_cbRecordLayerMessage_Fragment_LFL +
         Content()->size();

    wprintf(L"MAC text is %d bytes\n", cb);

    ResizeVector(&vbHashText, cb);
    pv = &vbHashText.front();

    wprintf(L"sequence number: %d\n", sequenceNumber);

    cbField = c_cbSequenceNumber_Length;
    hr = WriteNetworkLong(
             sequenceNumber,
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbContentType_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pContentType->Type()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbProtocolVersion_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pProtocolVersion->Version()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    hr = WriteNetworkLong(
             Content()->size(),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = Content()->size();
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();
    assert(cb == 0);

    wprintf(L"MAC hash text:\n");
    PrintByteVector(&vbHashText);

    hr = (*EndParams()->HashInst())->HMAC(
             pHashInfo,
             pvbMACKey,
             &vbHashText,
             pvbMAC);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(pvbMAC->size() == pHashInfo->cbHashSize);

done:
    return hr;

error:
    goto done;
} // end function ComputeSecurityInfo

HRESULT
MT_GenericStreamCipher::CheckSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion
)
{
    HRESULT hr = S_OK;
    ByteVector vbMAC;

    hr = ComputeSecurityInfo(
              *EndParams()->SequenceNumber(),
              EndParams()->MACKey(),
              pContentType,
              pProtocolVersion,
              &vbMAC);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"received MAC:\n");
    PrintByteVector(MAC());

    wprintf(L"computed MAC:\n");
    PrintByteVector(&vbMAC);

    if (*MAC() != vbMAC)
    {
        hr = MT_E_BAD_RECORD_MAC;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CheckSecurity

/*********** MT_GenericBlockCipher_TLS10 *****************/

MT_GenericBlockCipher_TLS10::MT_GenericBlockCipher_TLS10()
    : MT_CipherFragment(),
      m_vbMAC(),
      m_vbPadding()
{
} // end ctor MT_GenericBlockCipher_TLS10

HRESULT
MT_GenericBlockCipher_TLS10::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    const HashInfo* pHashInfo = EndParams()->Hash();
    const BYTE* pvEnd = nullptr;
    MT_UINT8 cbPaddingLength = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = MT_CipherFragment::ParseFromPriv(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    /*
    ** we have to be careful only to call this when we mean it, or else it
    ** changes the internal state of the cipherer
    */
    hr = (*EndParams()->SymCipherer())->DecryptBuffer(
             RawContent(),
             EndParams()->IV(),
             &vbDecryptedStruct);

    if (hr != S_OK)
    {
        goto error;
    }

    pv = &vbDecryptedStruct.front();
    cb = vbDecryptedStruct.size();

    pvEnd = &pv[cb - c_cbGenericBlockCipher_Padding_LFL];

    cbField = c_cbGenericBlockCipher_Padding_LFL;
    if (cb < cbField)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    hr = ReadNetworkLong(pvEnd, cbField, cbField, &cbPaddingLength);
    if (hr != S_OK)
    {
        goto error;
    }

    cb -= cbField;
    pvEnd -= cbField;

    cbField = cbPaddingLength;
    if (cb < cbField)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    /*
    ** cbPaddingLength = cbField = 5
    **
    ** yy yy yy 05 05 05 05 05 05
    **          ^           ^  ^
    **          |           |  padding length
    **          |           |
    **          |           pvEnd
    **          pvEnd -
    **          cbField + 1
    */
    Padding()->assign(pvEnd - cbField + 1, pvEnd + 1);

    {
        ByteVector vbFakePadding(cbPaddingLength, static_cast<BYTE>(cbPaddingLength));
        assert(*Padding() == vbFakePadding);
    }

    pvEnd -= cbField;
    cb -= cbField;

    assert(cb >= pHashInfo->cbHashSize);

    cbField = cb - pHashInfo->cbHashSize;
    Content()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    assert(cb == pHashInfo->cbHashSize);
    cbField = pHashInfo->cbHashSize;
    MAC()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_GenericBlockCipher_TLS10::UpdateWriteSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion)
{
    HRESULT hr = S_OK;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = ComputeSecurityInfo(
             *EndParams()->SequenceNumber(),
             EndParams()->MACKey(),
             pContentType,
             pProtocolVersion,
             MAC(),
             Padding());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(MAC()->size() == EndParams()->Hash()->cbHashSize);

    cb = Content()->size() +
         MAC()->size() +
         Padding()->size() +
         c_cbGenericBlockCipher_Padding_LFL;

    {
        const CipherInfo* pCipherInfo = EndParams()->Cipher();
        assert(pCipherInfo->type == CipherType_Block);
        assert((cb % pCipherInfo->cbBlockSize) == 0);
    }

    ResizeVector(&vbDecryptedStruct, cb);
    pv = &vbDecryptedStruct.front();

    cbField = Content()->size();
    assert(cbField <= cb);
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();

    cbField = MAC()->size();
    assert(cbField <= cb);
    std::copy(MAC()->begin(), MAC()->end(), pv);

    ADVANCE_PARSE();

    cbField = Padding()->size();
    assert(cbField <= cb);
    std::copy(Padding()->begin(), Padding()->end(), pv);

    ADVANCE_PARSE();

    cbField = c_cbGenericBlockCipher_Padding_LFL;
    hr = WriteNetworkLong(PaddingLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    assert(cb == 0);

    hr = (*EndParams()->SymCipherer())->EncryptBuffer(
             &vbDecryptedStruct,
             EndParams()->IV(),
             RawContent());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(!RawContent()->empty());

done:
    return hr;

error:
    goto done;
} // end function UpdateWriteSecurity

MT_UINT8
MT_GenericBlockCipher_TLS10::PaddingLength() const
{
    HRESULT hr = S_OK;
    BYTE b = 0;
    hr = SizeTToByte(Padding()->size(), &b);
    assert(hr == S_OK);
    return b;
} // end function PaddingLength

HRESULT
MT_GenericBlockCipher_TLS10::ComputeSecurityInfo(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC,
    ByteVector* pvbPadding
)
{
    HRESULT hr = S_OK;

    ByteVector vbHashText;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;

    const HashInfo* pHashInfo = EndParams()->Hash();
    const CipherInfo* pCipherInfo = EndParams()->Cipher();

    cb = c_cbSequenceNumber_Length +
         c_cbContentType_Length +
         c_cbProtocolVersion_Length +
         c_cbRecordLayerMessage_Fragment_LFL +
         Content()->size();

    wprintf(L"MAC text is %d bytes\n", cb);

    ResizeVector(&vbHashText, cb);
    pv = &vbHashText.front();

    wprintf(L"sequence number: %d\n", sequenceNumber);

    cbField = c_cbSequenceNumber_Length;
    hr = WriteNetworkLong(
             sequenceNumber,
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbContentType_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pContentType->Type()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbProtocolVersion_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pProtocolVersion->Version()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    hr = WriteNetworkLong(
             Content()->size(),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = Content()->size();
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();
    assert(cb == 0);

    wprintf(L"MAC hash text:\n");
    PrintByteVector(&vbHashText);


    hr = (*EndParams()->HashInst())->HMAC(
             pHashInfo,
             pvbMACKey,
             &vbHashText,
             pvbMAC);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(pvbMAC->size() == pHashInfo->cbHashSize);

    {
        assert(pCipherInfo->cbBlockSize != 0);
        size_t cbUnpaddedBlockLength = Content()->size() + MAC()->size();
        size_t cbPaddedBlockLength = 0;
        while (cbPaddedBlockLength <= cbUnpaddedBlockLength)
        {
            cbPaddedBlockLength += pCipherInfo->cbBlockSize;
        }

        assert(cbPaddedBlockLength >= cbUnpaddedBlockLength);
        assert((cbPaddedBlockLength % pCipherInfo->cbBlockSize) == 0);
        assert(cbPaddedBlockLength > 0);

        size_t cbPaddingLength = cbPaddedBlockLength -
                                 Content()->size() -
                                 MAC()->size() -
                                 c_cbGenericBlockCipher_Padding_LFL;
        BYTE b = 0;

        hr = SizeTToByte(cbPaddingLength, &b);
        if (hr != S_OK)
        {
            goto error;
        }

        assert(b == cbPaddingLength);

        pvbPadding->assign(cbPaddingLength, b);
    }

    assert(
    (
      (Content()->size() +
       MAC()->size() +
       pvbPadding->size() +
       c_cbGenericBlockCipher_Padding_LFL)
       %
       pCipherInfo->cbBlockSize
    ) == 0);

done:
    return hr;

error:
    goto done;
} // end function ComputeSecurityInfo

HRESULT
MT_GenericBlockCipher_TLS10::CheckSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion
)
{
    HRESULT hr = S_OK;

    ByteVector vbMAC;
    ByteVector vbPadding;

    hr = ComputeSecurityInfo(
              *EndParams()->SequenceNumber(),
              EndParams()->MACKey(),
              pContentType,
              pProtocolVersion,
              &vbMAC,
              &vbPadding);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"received MAC:\n");
    PrintByteVector(MAC());

    wprintf(L"computed MAC:\n");
    PrintByteVector(&vbMAC);

    if (*MAC() != vbMAC)
    {
        hr = MT_E_BAD_RECORD_MAC;
        goto error;
    }

    wprintf(L"received padding:\n");
    PrintByteVector(Padding());

    wprintf(L"computed padding:\n");
    PrintByteVector(&vbPadding);

    if (*Padding() != vbPadding)
    {
        hr = MT_E_BAD_RECORD_PADDING;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CheckSecurity

/*********** MT_GenericBlockCipher_TLS11 *****************/

MT_GenericBlockCipher_TLS11::MT_GenericBlockCipher_TLS11()
    : MT_CipherFragment(),
      m_vbIVNext(),
      m_vbMAC(),
      m_vbPadding()
{
} // end ctor MT_GenericBlockCipher_TLS11

HRESULT
MT_GenericBlockCipher_TLS11::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    const HashInfo* pHashInfo = EndParams()->Hash();
    const BYTE* pvEnd = nullptr;
    MT_UINT8 cbPaddingLength = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = MT_CipherFragment::ParseFromPriv(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    /*
    ** we have to be careful only to call this when we mean it, or else it
    ** changes the internal state of the cipherer down in cryptapi
    */
    hr = (*EndParams()->SymCipherer())->DecryptBuffer(
             RawContent(),
             EndParams()->IV(),
             &vbDecryptedStruct);

    if (hr != S_OK)
    {
        goto error;
    }

    pv = &vbDecryptedStruct.front();
    cb = vbDecryptedStruct.size();

    cbField = EndParams()->Cipher()->cbIVSize;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    IVNext()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    pvEnd = &pv[cb - c_cbGenericBlockCipher_Padding_LFL];

    cbField = c_cbGenericBlockCipher_Padding_LFL;
    if (cb < cbField)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    hr = ReadNetworkLong(pvEnd, cbField, cbField, &cbPaddingLength);
    if (hr != S_OK)
    {
        goto error;
    }

    cb -= cbField;
    pvEnd -= cbField;

    cbField = cbPaddingLength;
    if (cb < cbField)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    // see TLS1.0 implementation for more comments
    Padding()->assign(pvEnd - cbPaddingLength + 1, pvEnd + 1);

    {
        ByteVector vbFakePadding(cbPaddingLength, static_cast<BYTE>(cbPaddingLength));
        assert(*Padding() == vbFakePadding);
    }

    pvEnd -= cbField;
    cb -= cbField;

    // allows for 0-length content
    assert(cb >= pHashInfo->cbHashSize);

    cbField = cb - pHashInfo->cbHashSize;
    Content()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    assert(cb == pHashInfo->cbHashSize);
    cbField = pHashInfo->cbHashSize;
    MAC()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

    assert(cb == 0);

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_GenericBlockCipher_TLS11::UpdateWriteSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion)
{
    HRESULT hr = S_OK;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    hr = ComputeSecurityInfo(
              *EndParams()->SequenceNumber(),
              EndParams()->MACKey(),
              pContentType,
              pProtocolVersion,
              MAC(),
              Padding());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(MAC()->size() == EndParams()->Hash()->cbHashSize);

    cb = IVNext()->size() +
         Content()->size() +
         MAC()->size() +
         Padding()->size() +
         c_cbGenericBlockCipher_Padding_LFL; // padding length

    {
        const CipherInfo* pCipherInfo = EndParams()->Cipher();
        assert(pCipherInfo->type == CipherType_Block);
        assert((cb % pCipherInfo->cbBlockSize) == 0);
    }

    ResizeVector(&vbDecryptedStruct, cb);
    pv = &vbDecryptedStruct.front();

    cbField = IVNext()->size();
    assert(IVNext()->size() == EndParams()->Cipher()->cbIVSize);
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(IVNext()->begin(), IVNext()->end(), pv);

    ADVANCE_PARSE();

    cbField = Content()->size();
    assert(cbField <= cb);
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();

    cbField = MAC()->size();
    assert(cbField <= cb);
    std::copy(MAC()->begin(), MAC()->end(), pv);

    ADVANCE_PARSE();

    cbField = Padding()->size();
    assert(cbField <= cb);
    std::copy(Padding()->begin(), Padding()->end(), pv);

    ADVANCE_PARSE();

    cbField = c_cbGenericBlockCipher_Padding_LFL;
    hr = WriteNetworkLong(PaddingLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    assert(cb == 0);

    hr = (*EndParams()->SymCipherer())->EncryptBuffer(
             &vbDecryptedStruct,
             EndParams()->IV(),
             RawContent());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(!RawContent()->empty());

done:
    return hr;

error:
    goto done;
} // end function UpdateWriteSecurity

MT_UINT8
MT_GenericBlockCipher_TLS11::PaddingLength() const
{
    HRESULT hr = S_OK;
    BYTE b = 0;
    hr = SizeTToByte(Padding()->size(), &b);
    assert(hr == S_OK);
    return b;
} // end function PaddingLength

HRESULT
MT_GenericBlockCipher_TLS11::ComputeSecurityInfo(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC,
    ByteVector* pvbPadding
)
{
    HRESULT hr = S_OK;

    ByteVector vbHashText;
    BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;

    const HashInfo* pHashInfo = EndParams()->Hash();
    const CipherInfo* pCipherInfo = EndParams()->Cipher();

    cb = c_cbSequenceNumber_Length +
         c_cbContentType_Length +
         c_cbProtocolVersion_Length +
         c_cbRecordLayerMessage_Fragment_LFL +
         Content()->size();

    wprintf(L"MAC text is %d bytes\n", cb);

    ResizeVector(&vbHashText, cb);
    pv = &vbHashText.front();

    wprintf(L"sequence number: %d\n", sequenceNumber);

    cbField = c_cbSequenceNumber_Length;
    hr = WriteNetworkLong(
             sequenceNumber,
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbContentType_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pContentType->Type()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbProtocolVersion_Length;
    hr = WriteNetworkLong(
             static_cast<ULONG>(*pProtocolVersion->Version()),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    hr = WriteNetworkLong(
             Content()->size(),
             cbField,
             pv,
             cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = Content()->size();
    std::copy(Content()->begin(), Content()->end(), pv);

    ADVANCE_PARSE();
    assert(cb == 0);

    wprintf(L"MAC hash text:\n");
    PrintByteVector(&vbHashText);


    hr = (*EndParams()->HashInst())->HMAC(
             pHashInfo,
             pvbMACKey,
             &vbHashText,
             pvbMAC);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(pvbMAC->size() == pHashInfo->cbHashSize);

    {
        assert(pCipherInfo->cbBlockSize != 0);
        size_t cbUnpaddedBlockLength = Content()->size() + MAC()->size();
        size_t cbPaddedBlockLength = 0;
        while (cbPaddedBlockLength <= cbUnpaddedBlockLength)
        {
            cbPaddedBlockLength += pCipherInfo->cbBlockSize;
        }

        assert(cbPaddedBlockLength >= cbUnpaddedBlockLength);
        assert((cbPaddedBlockLength % pCipherInfo->cbBlockSize) == 0);
        assert(cbPaddedBlockLength > 0);

        // minus one for the padding length value itself
        size_t cbPaddingLength = cbPaddedBlockLength -
                                 Content()->size() -
                                 MAC()->size() -
                                 c_cbGenericBlockCipher_Padding_LFL;
        BYTE b = 0;

        hr = SizeTToByte(cbPaddingLength, &b);
        if (hr != S_OK)
        {
            goto error;
        }

        assert(b == cbPaddingLength);

        pvbPadding->assign(cbPaddingLength, b);
    }

    assert(
    (
      (Content()->size() +
      MAC()->size() +
      pvbPadding->size() +
      c_cbGenericBlockCipher_Padding_LFL)
      %
      pCipherInfo->cbBlockSize
    ) == 0);

done:
    return hr;

error:
    goto done;
} // end function ComputeSecurityInfo

HRESULT
MT_GenericBlockCipher_TLS11::CheckSecurity(
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion
)
{
    HRESULT hr = S_OK;

    ByteVector vbMAC;
    ByteVector vbPadding;

    hr = ComputeSecurityInfo(
              *EndParams()->SequenceNumber(),
              EndParams()->MACKey(),
              pContentType,
              pProtocolVersion,
              &vbMAC,
              &vbPadding);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"received MAC:\n");
    PrintByteVector(MAC());

    wprintf(L"computed MAC:\n");
    PrintByteVector(&vbMAC);

    if (*MAC() != vbMAC)
    {
        hr = MT_E_BAD_RECORD_MAC;
        goto error;
    }

    wprintf(L"received padding:\n");
    PrintByteVector(Padding());

    wprintf(L"computed padding:\n");
    PrintByteVector(&vbPadding);

    if (*Padding() != vbPadding)
    {
        hr = MT_E_BAD_RECORD_PADDING;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function CheckSecurity

/*********** MT_Alert *****************/

MT_Alert::MT_Alert()
    : MT_Structure(),
      m_eLevel(MTAL_Unknown),
      m_eDescription(MTAD_Unknown)
{
} // end ctor MT_Alert

HRESULT
MT_Alert::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbAlertLevel_Length;

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Level()));
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbAlertDescription_Length;
    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<ULONG*>(Description()));
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_Alert::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = c_cbAlertLevel_Length;

    hr = WriteNetworkLong(static_cast<BYTE>(*Level()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = c_cbAlertDescription_Length;
    hr = WriteNetworkLong(static_cast<BYTE>(*Description()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

wstring
MT_Alert::ToString() const
{
    PCWSTR wszLevel = nullptr;
    PCWSTR wszDescription = nullptr;

    switch (*Level())
    {
        case MTAL_Warning:
        wszLevel = L"warning";
        break;

        case MTAL_Fatal:
        wszLevel = L"fatal";
        break;

        default:
        wszLevel = L"unknown";
        break;
    }

    switch (*Description())
    {
        case MTAD_CloseNotify:
        wszDescription = L"CloseNotify";
        break;

        case MTAD_UnexpectedMessage:
        wszDescription = L"UnexpectedMessage";
        break;

        case MTAD_BadRecordMAC:
        wszDescription = L"BadRecordMAC";
        break;

        case MTAD_DecryptionFailed_RESERVED:
        wszDescription = L"DecryptionFailed_RESERVED";
        break;

        case MTAD_RecordOverflow:
        wszDescription = L"RecordOverflow";
        break;

        case MTAD_DecompressionFailure:
        wszDescription = L"DecompressionFailure";
        break;

        case MTAD_HandshakeFailure:
        wszDescription = L"HandshakeFailure";
        break;

        case MTAD_NoCertificate_RESERVED:
        wszDescription = L"NoCertificate_RESERVED";
        break;

        case MTAD_BadCertificate:
        wszDescription = L"BadCertificate";
        break;

        case MTAD_UnsupportedCertificate:
        wszDescription = L"UnsupportedCertificate";
        break;

        case MTAD_CertificateRevoked:
        wszDescription = L"CertificateRevoked";
        break;

        case MTAD_CertificateExpired:
        wszDescription = L"CertificateExpired";
        break;

        case MTAD_CertificateUnknown:
        wszDescription = L"CertificateUnknown";
        break;

        case MTAD_IllegalParameter:
        wszDescription = L"IllegalParameter";
        break;

        case MTAD_UnknownCA:
        wszDescription = L"UnknownCA";
        break;

        case MTAD_AccessDenied:
        wszDescription = L"AccessDenied";
        break;

        case MTAD_DecodeError:
        wszDescription = L"DecodeError";
        break;

        case MTAD_DecryptError:
        wszDescription = L"DecryptError";
        break;

        case MTAD_ExportRestriction_RESERVED:
        wszDescription = L"ExportRestriction_RESERVED";
        break;

        case MTAD_ProtocolVersion:
        wszDescription = L"ProtocolVersion";
        break;

        case MTAD_InsufficientSecurity:
        wszDescription = L"InsufficientSecurity";
        break;

        case MTAD_InternalError:
        wszDescription = L"InternalError";
        break;

        case MTAD_UserCanceled:
        wszDescription = L"UserCanceled";
        break;

        case MTAD_NoRenegotiation:
        wszDescription = L"NoRenegotiation";
        break;

        case MTAD_UnsupportedExtension:
        wszDescription = L"UnsupportedExtension";
        break;

        default:
        wszDescription = L"Unknown";
        break;
    }

    wstring wsAlert(wszLevel);
    wsAlert += L" ";
    wsAlert += wszDescription;
    return wsAlert;
} // end function ToString


/*********** SymmetricCipherer *****************/

SymmetricCipherer::SymmetricCipherer()
    : m_cipherInfo()
{
} // end ctor SymmetricCipherer

HRESULT
SymmetricCipherer::Initialize(
    const ByteVector* pvbKey,
    const CipherInfo* pCipherInfo
)
{
    UNREFERENCED_PARAMETER(pvbKey);

    *Cipher() = *pCipherInfo;
    return S_OK;
} // end function Initialize

HRESULT
SymmetricCipherer::EncryptBuffer(
    const ByteVector* pvbCleartext,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted
)
{
    UNREFERENCED_PARAMETER(pvbIV);

    if (Cipher()->alg == CipherAlg_NULL)
    {
        *pvbEncrypted = *pvbCleartext;
        return S_OK;
    }

    return E_NOTIMPL;
} // end function EncryptBuffer

HRESULT
SymmetricCipherer::DecryptBuffer(
    const ByteVector* pvbEncrypted,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted
)
{
    UNREFERENCED_PARAMETER(pvbIV);

    if (Cipher()->alg == CipherAlg_NULL)
    {
        *pvbDecrypted = *pvbEncrypted;
        return S_OK;
    }

    return E_NOTIMPL;
} // end function DecryptBuffer

/*********** Hasher *****************/

HRESULT
Hasher::Hash(
    const HashInfo* pHashInfo,
    const ByteVector* pvbText,
    ByteVector* pvbHash)
{
    UNREFERENCED_PARAMETER(pvbText);

    if (pHashInfo->alg == HashAlg_NULL)
    {
        // 0 byte hash
        pvbHash->clear();
        return S_OK;
    }

    return E_NOTIMPL;
} // end function Hash

HRESULT
Hasher::HMAC(
    const HashInfo* pHashInfo,
    const ByteVector* pvbKey,
    const ByteVector* pvbText,
    ByteVector* pvbHMAC)
{
    UNREFERENCED_PARAMETER(pvbKey);
    UNREFERENCED_PARAMETER(pvbText);

    if (pHashInfo->alg == HashAlg_NULL)
    {
        // 0 byte hash
        pvbHMAC->clear();
        return S_OK;
    }

    return E_NOTIMPL;
} // end function HMAC

/*********** MT_HelloRequest *****************/

MT_HelloRequest::MT_HelloRequest()
    : MT_Structure()
{
} // end ctor MT_HelloRequest

HRESULT
MT_HelloRequest::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    UNREFERENCED_PARAMETER(pv);
    UNREFERENCED_PARAMETER(cb);

    // 0-byte structure
    return S_OK;
} // end function SerializePriv

/*********** MT_RenegotiationInfoExtension *****************/

MT_RenegotiationInfoExtension::MT_RenegotiationInfoExtension()
    : MT_Extension(),
      m_renegotiatedConnection()
{
} // end ctor MT_RenegotiationInfoExtension

HRESULT
MT_RenegotiationInfoExtension::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;

    hr = MT_Extension::ParseFromPriv(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = RenegotiatedConnection()->ParseFromVect(ExtensionData());
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

HRESULT
MT_RenegotiationInfoExtension::UpdateDerivedFields()
{
    HRESULT hr = S_OK;
    hr = RenegotiatedConnection()->SerializeToVect(ExtensionData());
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function SerializePriv

/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : MT_Structure(),
      m_thingy()
{
} // end ctor MT_Thingy

HRESULT
MT_Thingy::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    hr = Thingy()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Thingy()->Length();
    ADVANCE_PARSE();

done:
    return hr;

error:
    goto done;
} // end function ParseFromPriv

size_t
MT_Thingy::Length() const
{
    size_t cbLength = Thingy()->Length();
    return cbLength;
} // end function Length

HRESULT
MT_Thingy::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    return E_NOTIMPL;
} // end function SerializePriv
*/

}
