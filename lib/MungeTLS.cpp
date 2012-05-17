#include "precomp.h"

#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>
#include <functional>

#include "MungeTLS.h"
#include "mtls_helper.h"

namespace MungeTLS
{

using namespace std;

HRESULT
ComputePRF_TLS12(
    Hasher* pHasher,
    const std::vector<BYTE>* pvbSecret,
    PCSTR szLabel,
    const std::vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    std::vector<BYTE>* pvbPRF);

HRESULT
ComputePRF_TLS10(
    Hasher* pHasher,
    const std::vector<BYTE>* pvbSecret,
    PCSTR szLabel,
    const std::vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    std::vector<BYTE>* pvbPRF);

HRESULT
PRF_P_hash(
    Hasher* pHasher,
    Hasher::HashAlg alg,
    const std::vector<BYTE>* pvbSecret,
    const std::vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    std::vector<BYTE>* pvbResult);

HRESULT
PRF_A(
    Hasher* pHasher,
    Hasher::HashAlg alg,
    UINT i,
    const std::vector<BYTE>* pvbSecret,
    const std::vector<BYTE>* pvbSeed,
    std::vector<BYTE>* pvbResult);

/*********** TLSConnection *****************/

TLSConnection::TLSConnection()
    : m_cipherSuite(),
      m_pCertContext(nullptr),
      m_spPubKeyCipherer(nullptr),
      m_spHasher(nullptr),
      m_vbMasterSecret(),
      m_clientRandom(),
      m_serverRandom(),
      m_negotiatedVersion(),
      m_vbClientWriteMACKey(),
      m_vbServerWriteMACKey(),
      m_vbClientWriteKey(),
      m_vbServerWriteKey(),
      m_vbClientWriteIV(),
      m_vbServerWriteIV(),
      m_fSecureMode(false)
{
} // end ctor TLSConnection

HRESULT
TLSConnection::Initialize()
{
    HRESULT hr = S_OK;
    shared_ptr<WindowsPublicKeyCipherer> spPubKeyCipherer;

    assert(*CertContext() == nullptr);

    hr = LookupCertificate(
             CERT_SYSTEM_STORE_CURRENT_USER,
             L"root",
             L"mtls-test",
             CertContext());

    if (hr != S_OK)
    {
        goto error;
    }

    spPubKeyCipherer.reset(new WindowsPublicKeyCipherer());
    hr = spPubKeyCipherer->Initialize(*CertContext());
    if (hr != S_OK)
    {
        goto error;
    }

    m_spPubKeyCipherer = spPubKeyCipherer;

    m_spClientSymCipherer.reset(new WindowsSymmetricCipherer());
    m_spServerSymCipherer.reset(new WindowsSymmetricCipherer());

    m_spHasher.reset(new WindowsHasher());

done:
    return hr;

error:
    goto done;
} // end function Initialize

HRESULT
TLSConnection::HandleMessage(
    const BYTE* pv,
    size_t cb,
    vector<BYTE>* pvbResponse
)
{
    HRESULT hr = S_OK;

    if (cb < 0)
    {
        return E_UNEXPECTED;
    }

    if (m_fSecureMode)
    {
        MT_TLSCiphertext message;
        hr = message.ParseFrom(pv, cb);

        if (hr == S_OK)
        {
            printf("successfully parsed TLSCiphertext. CT=%d\n", message.ContentType()->Type());

            message.SetSecurityParameters(this);

            hr = message.Decrypt();

            if (hr == S_OK)
            {
                printf("decrypted fragment:\n");
                PrintByteVector(message.DecryptedFragment());
            }
            else
            {
                printf("failed to decrypt ciphertext: %08LX\n", hr);
            }
        }
        else
        {
            printf("failed to parse ciphered message: %08LX\n", hr);
        }
    }
    else
    {
        MT_TLSPlaintext message;
        hr = message.ParseFrom(pv, cb);

        if (hr == S_OK)
        {
            printf("successfully parsed TLSPlaintext. CT=%d\n", message.ContentType()->Type());

            if (message.ContentType()->Type() == MT_ContentType::MTCT_Type_Handshake)
            {
                MT_Handshake handshakeMessage;
                hr = handshakeMessage.ParseFromVect(message.Fragment());

                if (hr == S_OK)
                {
                    printf("successfully parsed Handshake. type=%d\n", handshakeMessage.HandshakeType());

                    if (handshakeMessage.HandshakeType() == MT_Handshake::MTH_ClientHello)
                    {
                        MT_ClientHello clientHello;
                        hr = clientHello.ParseFromVect(handshakeMessage.Body());

                        if (hr == S_OK)
                        {
                            printf("parsed client hello message:\n");
                            printf("version %04LX\n", clientHello.ProtocolVersion()->Version());
                            printf("session ID %d\n", clientHello.SessionID()->Data()[0]);
                            printf("%d crypto suites\n", clientHello.CipherSuites()->Count());

                            printf("crypto suite 0: %02X %02X\n",
                                   *(clientHello.CipherSuites()->at(0)->at(0)),
                                   *(clientHello.CipherSuites()->at(0)->at(1)));

                            printf("%d compression methods: %d\n",
                                   clientHello.CompressionMethods()->Count(),
                                   clientHello.CompressionMethods()->at(0)->Method());

                            printf("%d bytes of extensions\n", clientHello.Extensions()->Length());


                            *NegotiatedVersion() = *(clientHello.ProtocolVersion());
                            *ClientRandom() = *(clientHello.Random());

                            vector<MT_TLSPlaintext> responseMessages;
                            hr = RespondTo(&clientHello, &responseMessages);

                            if (hr == S_OK)
                            {
                                printf("got %u messages to respond with\n", responseMessages.size());
                                hr = SerializeMessagesToVector(&responseMessages, pvbResponse);
                                //hr = responseMessages[0].SerializeToVect(pvbResponse);
                            }
                            else
                            {
                                printf("failed RespondTo: %08LX\n", hr);
                            }
                        }
                        else
                        {
                            printf("failed to parse client hello: %08LX\n", hr);
                        }
                    }
                    else if (handshakeMessage.HandshakeType() == MT_Handshake::MTH_ClientKeyExchange)
                    {
                        MT_KeyExchangeAlgorithm keyExchangeAlg;
                        hr = CipherSuite()->KeyExchangeAlgorithm(&keyExchangeAlg);

                        if (hr == S_OK)
                        {
                            if (keyExchangeAlg == MTKEA_rsa)
                            {
                                MT_ClientKeyExchange<MT_EncryptedPreMasterSecret> keyExchange;
                                hr = keyExchange.ParseFromVect(handshakeMessage.Body());

                                if (hr == S_OK)
                                {
                                    MT_EncryptedPreMasterSecret* pExchangeKeys = keyExchange.ExchangeKeys();
                                    pExchangeKeys->SetCipherer(PubKeyCipherer());
                                    hr = pExchangeKeys->DecryptStructure();

                                    if (hr == S_OK)
                                    {
                                        MT_PreMasterSecret* pSecret = pExchangeKeys->Structure();
                                        printf("version %04LX\n", pSecret->ClientVersion()->Version());

                                        hr = ComputeMasterSecret(pSecret);

                                        if (hr == S_OK)
                                        {
                                            printf("computed master secret:\n");
                                            PrintByteVector(MasterSecret());

                                            hr = GenerateKeyMaterial();
                                            if (hr == S_OK)
                                            {
                                                printf("computed key material\n");
                                            }
                                            else
                                            {
                                                printf("failed to compute key material: %08LX\n", hr);
                                            }
                                        }
                                        else
                                        {
                                            printf("failed to compute master secret: %08LX\n", hr);
                                        }
                                    }
                                    else
                                    {
                                        printf("failed to decrypt structure: %08LX\n", hr);
                                    }
                                }
                                else
                                {
                                    printf("failed to parse key exchange message from handshake body: %08LX\n", hr);
                                }
                            }
                            else
                            {
                                printf("unsupported key exchange type: %d\n", keyExchangeAlg);
                                hr = MT_E_UNSUPPORTED_KEY_EXCHANGE;
                            }
                        }
                        else
                        {
                            printf("failed to get key exchange algorithm: %08LX\n", hr);
                        }
                    }
                    else
                    {
                        printf("not yet supporting handshake type %d\n", handshakeMessage.HandshakeType());
                    }
                }
                else
                {
                    printf("failed to parse handshake: %08LX\n", hr);
                }
            }
            else if (message.ContentType()->Type() == MT_ContentType::MTCT_Type_ChangeCipherSpec)
            {
                MT_ChangeCipherSpec changeCipherSpec;

                hr = changeCipherSpec.ParseFromVect(message.Fragment());
                if (hr == S_OK)
                {
                    printf("change cipher spec found: %d\n", *(changeCipherSpec.Type()));
                    m_fSecureMode = true;
                }
                else
                {
                    printf("failed to parse change cipher spec: %08LX\n", hr);
                }
            }
        }
        else
        {
            printf("failed to parse message: %08LX\n", hr);
        }
    }

    return hr;
} // end function ParseMessage

HRESULT
TLSConnection::RespondTo(
    const MT_ClientHello* pClientHello,
    vector<MT_TLSPlaintext>* pResponses
)
{
    HRESULT hr = S_OK;
    UNREFERENCED_PARAMETER(pClientHello);

    // Server Hello
    {
        MT_ProtocolVersion protocolVersion;
        MT_Random random;
        MT_SessionID sessionID;
        MT_CompressionMethod compressionMethod;
        MT_HelloExtensions extensions;
        MT_ServerHello serverHello;
        MT_Handshake handshake;
        MT_ContentType contentType;
        MT_TLSPlaintext plaintext;

        protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);

        hr = random.PopulateNow();
        if (hr != S_OK)
        {
            goto error;
        }

        // TODO: setting this on the connection object. feels unclean
        // rsa + sha256 cbc
        //*(CipherSuite()->at(0)) = 0x00;
        //*(CipherSuite()->at(1)) = 0x35;

        // rsa + rc4_128 + sha
        *(CipherSuite()->at(0)) = 0x00;
        *(CipherSuite()->at(1)) = 0x05;

        compressionMethod.SetMethod(MT_CompressionMethod::MTCM_Null);

        /* renegotation info
        *(extensions.at(0)) = 0xff;
        *(extensions.at(1)) = 0x01;
        *(extensions.at(2)) = 0x00;
        *(extensions.at(3)) = 0x01;
        *(extensions.at(4)) = 0x00;
        */

        *(serverHello.ProtocolVersion()) = protocolVersion;
        *(serverHello.Random()) = random;
        *(serverHello.SessionID()) = sessionID;
        *(serverHello.CipherSuite()) = *CipherSuite();
        *(serverHello.CompressionMethod()) = compressionMethod;
        *(serverHello.Extensions()) = extensions;

        *ServerRandom() = *(serverHello.Random());

        handshake.SetType(MT_Handshake::MTH_ServerHello);
        hr = serverHello.SerializeToVect(handshake.Body());
        if (hr != S_OK)
        {
            goto error;
        }

        contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

        *(plaintext.ContentType()) = contentType;
        *(plaintext.ProtocolVersion()) = protocolVersion;

        hr = handshake.SerializeToVect(plaintext.Fragment());
        if (hr != S_OK)
        {
            goto error;
        }

        pResponses->push_back(plaintext);
    }

    assert(hr == S_OK);

    // Certificate
    {
        MT_Certificate certificate;
        MT_Handshake handshake;
        MT_ContentType contentType;
        MT_TLSPlaintext plaintext;
        MT_ProtocolVersion protocolVersion;

        if (hr != S_OK)
        {
            goto error;
        }


        hr = certificate.PopulateFromMemory(
                 (*CertContext())->pbCertEncoded,
                 (*CertContext())->cbCertEncoded);

        if (hr != S_OK)
        {
            goto error;
        }

        handshake.SetType(MT_Handshake::MTH_Certificate);
        hr = certificate.SerializeToVect(handshake.Body());

        protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);
        contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

        *(plaintext.ContentType()) = contentType;
        *(plaintext.ProtocolVersion()) = protocolVersion;

        hr = handshake.SerializeToVect(plaintext.Fragment());
        if (hr != S_OK)
        {
            goto error;
        }

        pResponses->push_back(plaintext);
    }

    assert(hr == S_OK);

    // Server Hello Done
    {
        MT_Handshake handshake;
        MT_ContentType contentType;
        MT_TLSPlaintext plaintext;
        MT_ProtocolVersion protocolVersion;

        protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);
        handshake.SetType(MT_Handshake::MTH_ServerHelloDone);
        contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

        *(plaintext.ContentType()) = contentType;
        *(plaintext.ProtocolVersion()) = protocolVersion;

        hr = handshake.SerializeToVect(plaintext.Fragment());
        if (hr != S_OK)
        {
            goto error;
        }

        pResponses->push_back(plaintext);
    }

    assert(hr == S_OK);

error:
    return hr;
} // end function RespondTo

HRESULT
TLSConnection::ComputeMasterSecret(
    const MT_PreMasterSecret* pPreMasterSecret
)
{
    HRESULT hr = S_OK;

    vector<BYTE> vbPreMasterSecret;
    vector<BYTE> vbRandoms;

    hr = pPreMasterSecret->SerializeToVect(&vbPreMasterSecret);
    if (hr != S_OK)
    {
        goto error;
    }

    printf("premaster secret:\n");
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
             "master secret",
             &vbRandoms,
             48,
             MasterSecret());

    if (hr != S_OK)
    {
        goto error;
    }

    assert(MasterSecret()->size() == 48);

done:
    return hr;

error:
    goto done;
} // end function ComputeMasterSecret

HRESULT
TLSConnection::ComputePRF(
    const vector<BYTE>* pvbSecret,
    PCSTR szLabel,
    const vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    vector<BYTE>* pvbPRF
)
{
    HRESULT hr = S_OK;

    printf("protocol version for PRF algorithm: %04LX\n", NegotiatedVersion()->Version());

    if (NegotiatedVersion()->Version() == MT_ProtocolVersion::MTPV_TLS10)
    {
        hr = ComputePRF_TLS10(
                 HashInst(),
                 pvbSecret,
                 szLabel,
                 pvbSeed,
                 cbMinimumLengthDesired,
                 pvbPRF);
    }
    else if (NegotiatedVersion()->Version() == MT_ProtocolVersion::MTPV_TLS12)
    {
        hr = ComputePRF_TLS12(
                 HashInst(),
                 pvbSecret,
                 szLabel,
                 pvbSeed,
                 cbMinimumLengthDesired,
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

done:
    return hr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF

HRESULT
TLSConnection::GenerateKeyMaterial()
{
    HRESULT hr = S_OK;

    SymmetricCipherer::CipherInfo cipherInfo;
    Hasher::HashInfo hashInfo;
    size_t cbKeyBlock;
    vector<BYTE> vbRandoms;
    vector<BYTE> vbKeyBlock;

    printf("gen key material\n");

    assert(!MasterSecret()->empty());

    hr = CryptoInfoFromCipherSuite(CipherSuite(), &cipherInfo, &hashInfo);
    if (hr != S_OK)
    {
        goto error;
    }

    cbKeyBlock = (hashInfo.cbHashKeySize * 2) +
                 (cipherInfo.cbKeyMaterialSize * 2) +
                 (cipherInfo.cbIVSize * 2);

    printf("need %d bytes for key block (%d * 2) + (%d * 2) + (%d * 2)\n", cbKeyBlock, hashInfo.cbHashKeySize, cipherInfo.cbKeyMaterialSize, cipherInfo.cbIVSize);

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

    printf("randoms: (%d bytes)\n", vbRandoms.size());
    PrintByteVector(&vbRandoms);

    hr = ComputePRF(
             MasterSecret(),
             "key expansion",
             &vbRandoms,
             cbKeyBlock,
             &vbKeyBlock);

    if (hr != S_OK)
    {
        goto error;
    }

    printf("key block:\n");
    PrintByteVector(&vbKeyBlock);

    {
        auto itKeyBlock = vbKeyBlock.begin();

        size_t cbField = hashInfo.cbHashKeySize;
        ClientWriteMACKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ClientWriteMACKey\n");
        PrintByteVector(ClientWriteMACKey());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = hashInfo.cbHashKeySize;
        ServerWriteMACKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ServerWriteMACKey\n");
        PrintByteVector(ServerWriteMACKey());



        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = cipherInfo.cbKeyMaterialSize;
        ClientWriteKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ClientWriteKey\n");
        PrintByteVector(ClientWriteKey());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = cipherInfo.cbKeyMaterialSize;
        ServerWriteKey()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ServerWriteKey\n");
        PrintByteVector(ServerWriteKey());



        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = cipherInfo.cbIVSize;
        ClientWriteIV()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ClientWriteIV\n");
        PrintByteVector(ClientWriteIV());

        assert(itKeyBlock <= vbKeyBlock.end());
        cbField = cipherInfo.cbIVSize;
        ServerWriteIV()->assign(itKeyBlock, itKeyBlock + cbField);
        itKeyBlock += cbField;

        printf("ServerWriteIV\n");
        PrintByteVector(ServerWriteIV());

        assert(itKeyBlock == vbKeyBlock.end());



        // TODO: incorporate IV
        hr = ClientSymCipherer()->Initialize(
                 ClientWriteKey(),
                 cipherInfo.alg);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = ServerSymCipherer()->Initialize(
                 ServerWriteKey(),
                 cipherInfo.alg);

        if (hr != S_OK)
        {
            goto error;
        }
    }

done:
    return hr;

error:
    ClientWriteMACKey()->clear();
    ServerWriteMACKey()->clear();
    ClientWriteKey()->clear();
    ServerWriteKey()->clear();
    ClientWriteIV()->clear();
    ServerWriteIV()->clear();
    goto done;
} // end function GenerateKeyMaterial




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

error:
    return hr;
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

error:
    return hr;
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

error:
    return hr;
} // end function EpochTimeFromSystemTime

template <typename T>
HRESULT
SerializeMessagesToVector(
    const std::vector<T>* pvMessages,
    std::vector<BYTE>* pvb
)
{
    HRESULT hr = S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(pvMessages->begin(), pvMessages->end(),
        [&hr, &cbTotal, pvb](const T& pStructure)
        {
            if (hr == S_OK)
            {
                cbTotal += pStructure.Length();
                hr = pStructure.SerializeAppendToVect(pvb);
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
    std::vector<T>* pv,
    typename std::vector<T>::size_type siz
)
{
    pv->resize(siz);
} // end function ResizeVector<T>

template <>
void
ResizeVector<BYTE>(
    std::vector<BYTE>* pv,
    typename std::vector<BYTE>::size_type siz
)
{
    pv->resize(siz, 0x23);
} // end function ResizeVector<BYTE>

template <typename T>
void
EnsureVectorSize<T>(
    std::vector<T>* pVect,
    typename std::vector<T>::size_type siz
)
{
    if (siz > pVect->size())
    {
        pVect->resize(siz);
    }
} // end function EnsureVectorSize

vector<BYTE>
ReverseByteOrder(
    const vector<BYTE>* pvb
)
{
    return vector<BYTE>(pvb->rbegin(), pvb->rend());
} // end function ReverseByteOrder

HRESULT PrintByteVector(const vector<BYTE>* pvb)
{
     HRESULT hr = S_OK;

     for_each(pvb->begin(), pvb->end(),
     [](BYTE b)
     {
         wprintf(L"%02X ", b);
     });

     wprintf(L"\n");

     return hr;
} // end function PrintByteVector

/*********** crypto stuff *****************/

HRESULT
ComputePRF_TLS12(
    Hasher* pHasher,
    const vector<BYTE>* pvbSecret,
    PCSTR szLabel,
    const vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    vector<BYTE>* pvbPRF
)
{
    HRESULT hr = S_OK;

    vector<BYTE> vbLabelAndSeed;
    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(vbLabelAndSeed.end(), pvbSeed->begin(), pvbSeed->end());

    hr = PRF_P_hash(
             pHasher,
             Hasher::HashAlg_SHA256,
             pvbSecret,
             &vbLabelAndSeed,
             cbMinimumLengthDesired,
             pvbPRF);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF_TLS12

HRESULT
ComputePRF_TLS10(
    Hasher* pHasher,
    const vector<BYTE>* pvbSecret,
    PCSTR szLabel,
    const vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    vector<BYTE>* pvbPRF
)
{
    HRESULT hr = S_OK;
    printf("PRF 1.0\n");

    vector<BYTE> vbLabelAndSeed;
    vector<BYTE> vbS1;
    vector<BYTE> vbS2;
    vector<BYTE> vbS1_Expanded;
    vector<BYTE> vbS2_Expanded;

    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(vbLabelAndSeed.end(), pvbSeed->begin(), pvbSeed->end());

    printf("label + seed = (%d)\n", vbLabelAndSeed.size());
    PrintByteVector(&vbLabelAndSeed);

    // ceil(size / 2)
    size_t cbL_S1 = (pvbSecret->size() + 1) / 2;

    printf("L_S = %d, L_S1 = L_S2 = %d\n", pvbSecret->size(), cbL_S1);

    auto itSecretMidpoint = pvbSecret->begin() + cbL_S1;

    vbS1.assign(pvbSecret->begin(), itSecretMidpoint);

    printf("S1:\n");
    PrintByteVector(&vbS1);

    // makes the two halves overlap by one byte, as required in RFC
    if ((pvbSecret->size() % 2) != 0)
    {
        itSecretMidpoint--;
    }

    vbS2.assign(itSecretMidpoint, pvbSecret->end());

    printf("S2:\n");
    PrintByteVector(&vbS2);

    assert(vbS1.size() == vbS2.size());

    hr = PRF_P_hash(
             pHasher,
             Hasher::HashAlg_MD5,
             &vbS1,
             &vbLabelAndSeed,
             cbMinimumLengthDesired,
             &vbS1_Expanded);

    if (hr != S_OK)
    {
        goto error;
    }

    hr = PRF_P_hash(
             pHasher,
             Hasher::HashAlg_SHA1,
             &vbS2,
             &vbLabelAndSeed,
             cbMinimumLengthDesired,
             &vbS2_Expanded);

    if (hr != S_OK)
    {
        goto error;
    }

    assert(vbS1_Expanded.size() >= cbMinimumLengthDesired);
    assert(vbS2_Expanded.size() >= cbMinimumLengthDesired);
    pvbPRF->resize(cbMinimumLengthDesired);

    transform(
        vbS1_Expanded.begin(),
        vbS1_Expanded.begin() + cbMinimumLengthDesired,
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
    Hasher::HashAlg alg,
    UINT i,
    const vector<BYTE>* pvbSecret,
    const vector<BYTE>* pvbSeed,
    vector<BYTE>* pvbResult
)
{
    HRESULT hr = S_OK;
    vector<BYTE> vbTemp;

    // A(0) = seed
    *pvbResult = *pvbSeed;

    while (i > 0)
    {
        vbTemp = *pvbResult;

        hr = pHasher->HMAC(
                          alg,
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
    Hasher::HashAlg alg,
    const vector<BYTE>* pvbSecret,
    const vector<BYTE>* pvbSeed,
    size_t cbMinimumLengthDesired,
    vector<BYTE>* pvbResult
)
{
    HRESULT hr = S_OK;

    assert(pvbResult->empty());

    // starts from A(1), not A(0)
    for (UINT i = 1; pvbResult->size() < cbMinimumLengthDesired; i++)
    {
        printf("PRF_P generated %d out of %d bytes\n", pvbResult->size(), cbMinimumLengthDesired);

        vector<BYTE> vbIteration;
        vector<BYTE> vbInnerSeed;

        hr = PRF_A(
                 pHasher,
                 alg,
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
                          alg,
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
    SymmetricCipherer::CipherInfo* pCipherInfo,
    Hasher::HashInfo* pHashInfo
)
{
    HRESULT hr = S_OK;

    if (pHashInfo == NULL && pCipherInfo == NULL)
    {
        hr = E_INVALIDARG;
        goto error;
    }

    if (pHashInfo)
    {
        Hasher::HashAlg hashAlg;

        if (*pCipherSuite == MTCS_TLS_RSA_WITH_NULL_SHA ||
            *pCipherSuite == MTCS_TLS_RSA_WITH_RC4_128_SHA ||
            *pCipherSuite == MTCS_TLS_RSA_WITH_3DES_EDE_CBC_SHA ||
            *pCipherSuite == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA ||
            *pCipherSuite == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA)
        {
            hashAlg = Hasher::HashAlg_SHA1;
        }
        else if (*pCipherSuite == MTCS_TLS_RSA_WITH_NULL_SHA256 ||
                 *pCipherSuite == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256 ||
                 *pCipherSuite == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256)
        {
            hashAlg = Hasher::HashAlg_SHA256;
        }
        else
        {
            hr = MT_E_UNSUPPORTED_HASH;
            goto error;
        }

        hr = Hasher::GetHashInfo(hashAlg, pHashInfo);
        if (hr != S_OK)
        {
            goto error;
        }
    }

    if (pCipherInfo)
    {
        SymmetricCipherer::CipherAlg cipherAlg;

        if (*pCipherSuite == MTCS_TLS_RSA_WITH_RC4_128_MD5 ||
            *pCipherSuite ==  MTCS_TLS_RSA_WITH_RC4_128_SHA)
        {
            cipherAlg = SymmetricCipherer::CipherAlg_RC4_128;
        }
        else if (*pCipherSuite == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA ||
                 *pCipherSuite == MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256)
        {
            cipherAlg = SymmetricCipherer::CipherAlg_AES_128;
        }
        else if (*pCipherSuite == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA ||
                 *pCipherSuite == MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256)
        {
            cipherAlg = SymmetricCipherer::CipherAlg_AES_256;
        }
        else
        {
            hr = MT_E_UNSUPPORTED_CIPHER;
            goto error;
        }

        hr = SymmetricCipherer::GetCipherInfo(cipherAlg, pCipherInfo);
        if (hr != S_OK)
        {
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
    HRESULT hr = S_OK;

    // if there are no 0-byte fields, this can be <=
    if (cb < 0)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    hr = ParseFromPriv(pv, cb);

error:
    return hr;
} // end function ParseFrom

HRESULT
MT_Structure::ParseFromVect(
    const vector<BYTE>* pvb
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
    vector<BYTE>* pvb
) const
{
    pvb->clear();
    return SerializeAppendToVect(pvb);
} // end function SerializeToVect

HRESULT
MT_Structure::SerializeAppendToVect(
    vector<BYTE>* pvb
) const
{
    size_t cSize = pvb->size();
    ResizeVector(pvb, cSize + Length());

    vector<BYTE>::iterator end = pvb->begin() + cSize;

    assert(pvb->end() - (end + Length()) >= 0);
    return Serialize(&(*end), Length());
} // end function SerializeAppendToVect


/*********** MT_SecuredStructure *****************/

MT_SecuredStructure::MT_SecuredStructure()
    : MT_Structure(),
      m_pSecurityParameters(nullptr)
{
} // end ctor MT_SecuredStructure

HRESULT
MT_SecuredStructure::CheckSecurity()
{
    assert(SecurityParameters() != nullptr);
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
{
    assert(LengthFieldSize <= sizeof(size_t));
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);
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
    typename std::vector<F>::size_type pos
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

error:
    return hr;
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
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);

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

error:
    return hr;
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

error:
    return hr;
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

error:
    return hr;
} // end function SerializePriv

/*********** MT_FixedLengthStructureBase *****************/

template <typename F, size_t Size>
MT_FixedLengthStructureBase<F, Size>::MT_FixedLengthStructureBase()
    : m_vData()
{
    assert(Size > 0);
}

template <typename F,
          size_t Size>
F*
MT_FixedLengthStructureBase<F, Size>::at(
    typename std::vector<F>::size_type pos
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

error:
    return hr;
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

error:
    return hr;
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

error:
    return hr;
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

error:
    return hr;
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
    : m_structure(),
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
    size_t cbField = 2;
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

error:
    return hr;
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

/*********** MT_TLSPlaintext *****************/

MT_TLSPlaintext::MT_TLSPlaintext()
    : m_contentType(),
      m_protocolVersion(),
      m_vbFragment()
{
} // end ctor MT_TLSPlaintext

HRESULT
MT_TLSPlaintext::ParseFromPriv(
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


    cbField = 2;
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

error:
    return hr;
} // end function ParseFromPriv

MT_UINT16
MT_TLSPlaintext::PayloadLength() const
{
    size_t cbLength = Fragment()->size();
    assert(cbLength <= UINT16_MAX);
    return static_cast<MT_UINT16>(cbLength);
} // end function PayloadLength

size_t
MT_TLSPlaintext::Length() const
{
    size_t cbLength = ContentType()->Length() +
                      ProtocolVersion()->Length() +
                      2 + // sizeof MT_UINT16 payload length
                      PayloadLength();

    return cbLength;
} // end function Length

HRESULT
MT_TLSPlaintext::SerializePriv(
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

    // uint16 length;
    cbField = 2;
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

error:
    return hr;
} // end function SerializePriv

/*********** MT_TLSCiphertext *****************/

MT_TLSCiphertext::MT_TLSCiphertext()
    : m_contentType(),
      m_protocolVersion(),
      m_vbFragment(),
      m_vbDecryptedFragment()
{
} // end ctor MT_TLSCiphertext

HRESULT
MT_TLSCiphertext::ParseFromPriv(
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


    cbField = 2;
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

error:
    return hr;
} // end function ParseFromPriv

size_t
MT_TLSCiphertext::Length() const
{
    size_t cbLength = ContentType()->Length() +
                      ProtocolVersion()->Length() +
                      2 + // sizeof MT_UINT16 payload length
                      Fragment()->size();

    return cbLength;
} // end function Length

HRESULT
MT_TLSCiphertext::Decrypt()
{
    HRESULT hr = S_OK;

    assert(SecurityParameters() != nullptr);
    assert(SecurityParameters()->ClientSymCipherer() != nullptr);

    hr = SecurityParameters()->ClientSymCipherer()->DecryptBuffer(
             Fragment(),
             DecryptedFragment());

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
    return E_NOTIMPL;
} // end function Encrypt

/*********** MT_ContentType *****************/

MT_ContentType::MT_ContentType()
    : m_eType(MTCT_Type_Unknown)
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

    if (Length() > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    MTCT_Type eType = static_cast<MTCT_Type>(pv[0]);

    if (!IsValidContentType(eType))
    {
        hr = MT_E_UNKNOWN_CONTENT_TYPE;
        goto error;
    }

    SetType(eType);

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_ContentType::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    size_t cbField = Length();
    hr = WriteNetworkLong(static_cast<ULONG>(Type()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

bool
MT_ContentType::IsValidContentType(
    MTCT_Type eType
)
{
    return (find(c_rgeValidTypes, c_rgeValidTypes+c_cValidTypes, eType) != c_rgeValidTypes+c_cValidTypes);
} // end function IsValidContentType

const
MT_ContentType::MTCT_Type
MT_ContentType::Type() const
{
    assert(IsValidContentType(m_eType));
    return m_eType;
} // end function Type


/*********** MT_ProtocolVersion *****************/

MT_ProtocolVersion::MT_ProtocolVersion()
    : m_version(0)
{
} // end ctor MT_ProtocolVersion

HRESULT
MT_ProtocolVersion::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    MT_UINT16 version = 0;

    hr = ReadNetworkLong(pv, cb, Length(), &version);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!IsKnownVersion(version))
    {
        wprintf(L"unknown protocol version: %02X\n", version);
        hr = MT_E_UNKNOWN_PROTOCOL_VERSION;
        goto error;
    }

    SetVersion(version);

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_ProtocolVersion::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    hr = WriteNetworkLong(static_cast<ULONG>(Version()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

bool
MT_ProtocolVersion::IsKnownVersion(
    MT_UINT16 version
)
{
    return (version == MTPV_TLS10 ||
            version == MTPV_TLS12);
} // end function IsKnownVersion

MT_UINT16
MT_ProtocolVersion::Version() const
{
    assert(IsKnownVersion(m_version));
    return m_version;
} // end function Version


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
    : m_eType(MTH_Unknown),
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
    size_t cbField = 1;
    MTH_HandshakeType eType = MTH_Unknown;
    size_t cbPayloadLength = 0;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    eType = static_cast<MTH_HandshakeType>(pv[0]);

    if (!IsKnownType(eType))
    {
        hr = MT_E_UNKNOWN_HANDSHAKE_TYPE;
        goto error;
    }

    if (!IsSupportedType(eType))
    {
        hr = MT_E_UNSUPPORTED_HANDSHAKE_TYPE;
        goto error;
    }

    m_eType = eType;

    ADVANCE_PARSE();

    cbField = LengthFieldLength();
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

error:
    return hr;
} // end function ParseFromPriv

size_t
MT_Handshake::Length() const
{
    return 1 + // handshake type
           LengthFieldLength() +
           PayloadLength();
} // end function Length

MT_Handshake::MTH_HandshakeType
MT_Handshake::HandshakeType() const
{
    assert(IsKnownType(m_eType));
    return m_eType;
} // end function HandshakeType

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
    size_t cbField = 1;

    hr = WriteNetworkLong(static_cast<ULONG>(HandshakeType()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = LengthFieldLength();
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

error:
    return hr;
} // end function SerializePriv

/*********** MT_Random *****************/

const size_t MT_Random::c_cbRandomBytes = 28;

MT_Random::MT_Random()
    : m_timestamp(0),
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

    // Random.(uint32 gmt_unix_time)
    size_t cbField = 4;
    hr = ReadNetworkLong(pv, cb, cbField, &m_timestamp);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    // Random.(opaque random_bytes[28])
    cbField = c_cbRandomBytes;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    RandomBytes()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_Random::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 4;

    hr = WriteNetworkLong(GMTUnixTime(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = RandomBytes()->size();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(RandomBytes()->begin(), RandomBytes()->end(), pv);

    ADVANCE_PARSE();

error:
    return hr;
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

    ResizeVector(RandomBytes(), c_cbRandomBytes);
    /*
    hr = WriteRandomBytes(&RandomBytes()->front(), RandomBytes()->size());

    if (hr != S_OK)
    {
        goto error;
    }
    */

error:
    return hr;
} // end function PopulateNow


/*********** MT_ClientHello *****************/

MT_ClientHello::MT_ClientHello()
    : m_protocolVersion(),
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

error:
    return hr;
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
    : m_compressionMethod(MTCM_Unknown)
{
}

HRESULT
MT_CompressionMethod::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    if (pv[0] != MTCM_Null)
    {
        hr = MT_E_UNKNOWN_COMPRESSION_METHOD;
        goto error;
    }

    m_compressionMethod = pv[0];

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_CompressionMethod::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

    hr = WriteNetworkLong(static_cast<ULONG>(Method()), cbField, pv, cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

MT_UINT8
MT_CompressionMethod::Method() const
{
    assert(m_compressionMethod == MTCM_Null);
    return m_compressionMethod;
} // end function Method


/*********** MT_ServerHello *****************/

MT_ServerHello::MT_ServerHello()
    : m_protocolVersion(),
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

error:
    return hr;
} // end function SerializePriv

/*********** MT_Certificate *****************/

MT_Certificate::MT_Certificate()
    : m_certificateList()
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

error:
    return hr;
} // end function SerializePriv

HRESULT
MT_Certificate::PopulateFromFile(
    PCWSTR wszFilename
)
{
    UNREFERENCED_PARAMETER(wszFilename);
    return E_NOTIMPL;
} // end function PopulateFromFile

HRESULT
MT_Certificate::PopulateFromMemory(
    const BYTE* pvCert, size_t cbCert
)
{
    MT_ASN1Cert cert;
    cert.Data()->assign(pvCert, pvCert + cbCert);
    CertificateList()->Data()->assign(1, cert);
    return S_OK;
} // end function PopulateFromMemory

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

error:
    return hr;
} // end function PopulateWithRandom

/*********** MT_PreMasterSecret *****************/

MT_PreMasterSecret::MT_PreMasterSecret()
    : m_clientVersion(),
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

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_PreMasterSecret::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    cbField = ClientVersion()->Length();
    hr = ClientVersion()->Serialize(pv, cb);
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

const MT_CipherSuiteValue c_rgeSupportedCipherSuites[] =
{
      MTCS_TLS_RSA_WITH_NULL_MD5,
      MTCS_TLS_RSA_WITH_NULL_SHA,
      MTCS_TLS_RSA_WITH_NULL_SHA256,
      MTCS_TLS_RSA_WITH_RC4_128_MD5,
      MTCS_TLS_RSA_WITH_RC4_128_SHA,
      MTCS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA,
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256,
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256
};

const ULONG c_cSupportedCipherSuites = ARRAYSIZE(c_rgeSupportedCipherSuites);

const MT_CipherSuiteValue* GetSupportedCipherSuites(size_t* pcCipherSuites)
{
    assert(pcCipherSuites != nullptr);
    *pcCipherSuites = c_cSupportedCipherSuites;
    return c_rgeSupportedCipherSuites;
} // end function GetSupportedCipherSuites

bool
IsKnownCipherSuite(
    MT_CipherSuiteValue eSuite
)
{
    size_t cCipherSuites = 0;
    const MT_CipherSuiteValue* rgeCipherSuites = GetSupportedCipherSuites(&cCipherSuites);

    return (find(
                rgeCipherSuites,
                rgeCipherSuites+cCipherSuites,
                eSuite)
                != rgeCipherSuites+cCipherSuites);
} // end function IsKnownCipherSuite

HRESULT
MT_CipherSuite::KeyExchangeAlgorithm(
    MT_KeyExchangeAlgorithm* pAlg
) const
{
    HRESULT hr = S_OK;

    if (IsKnownCipherSuite(*this))
    {
        *pAlg = MTKEA_rsa;
    }
    else
    {
        hr = MT_E_UNKNOWN_CIPHER_SUITE;
    }

    return hr;
} // end function KeyExchangeAlgorithm

MT_CipherSuite::operator MT_CipherSuiteValue() const
{
    MT_CipherSuiteValue cs;

    assert(Data()->size() <= sizeof(cs));

    HRESULT hr = ReadNetworkLong(
                     &Data()->front(),
                     Data()->size(),
                     Data()->size(),
                     reinterpret_cast<ULONG*>(&cs));

    assert(hr == S_OK);

    return cs;
} // end operator MT_CipherSuiteValue

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

    m_spExchangeKeys.reset(new KeyType());

    hr = ExchangeKeys()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ExchangeKeys()->Length();
    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

/*********** MT_ChangeCipherSpec *****************/

MT_ChangeCipherSpec::MT_ChangeCipherSpec()
    : m_type(MTCCS_ChangeCipherSpc)
{
} // end ctor MT_ChangeCipherSpec

HRESULT
MT_ChangeCipherSpec::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

    hr = ReadNetworkLong(pv, cb, cbField, reinterpret_cast<UINT*>(Type()));
    if (hr != S_OK)
    {
        goto error;
    }

    if (*Type() != MTCCS_ChangeCipherSpc)
    {
        wprintf(L"unrecognized change cipher spec type: %d\n", *Type());
    }

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_ChangeCipherSpec::SerializePriv(
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

    size_t cbField = 1;

    hr = WriteNetworkLong(static_cast<BYTE>(*Type()), cbField, pv, cb);
    assert(hr == S_OK);

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : m_thingy()
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
