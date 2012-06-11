#pragma once
#include <windows.h>
#include <vector>
#include <memory>
#include "mtls_defs.h"
#include "MungeCrypto.h"

#pragma warning(push)
#pragma warning(disable : 4100)
namespace MungeTLS
{

const HRESULT MT_E_INCOMPLETE_MESSAGE                       = 0x80230001;
const HRESULT MT_E_UNKNOWN_CONTENT_TYPE                     = 0x80230002;
const HRESULT MT_E_UNKNOWN_PROTOCOL_VERSION                 = 0x80230003;
const HRESULT MT_E_UNKNOWN_HANDSHAKE_TYPE                   = 0x80230004;
const HRESULT MT_E_UNSUPPORTED_HANDSHAKE_TYPE               = 0x80230005;
const HRESULT MT_E_DATA_SIZE_OUT_OF_RANGE                   = 0x80230006;
const HRESULT MT_E_UNKNOWN_COMPRESSION_METHOD               = 0x80230007;
const HRESULT MT_E_UNKNOWN_CIPHER_SUITE                     = 0x80230008;
const HRESULT MT_E_UNSUPPORTED_KEY_EXCHANGE                 = 0x80230009;
const HRESULT MT_E_BAD_PADDING                              = 0x8023000a;
const HRESULT MT_E_UNSUPPORTED_HASH                         = 0x8023000b;
const HRESULT MT_E_UNSUPPORTED_CIPHER                       = 0x8023000c;
const HRESULT MT_E_BAD_FINISHED_HASH                        = 0x8023000d;
const HRESULT MT_E_BAD_RECORD_MAC                           = 0x8023000e;
const HRESULT MT_E_BAD_RECORD_PADDING                       = 0x8023000f;
const HRESULT E_INSUFFICIENT_BUFFER                         = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

extern const BYTE c_abyCert[];
extern const size_t c_cbCert;

class MT_PreMasterSecret;
class TLSConnection;
class MT_CipherFragment;

class MT_Structure
{
    public:
    MT_Structure() { }
    virtual ~MT_Structure() { }

    HRESULT ParseFrom(const BYTE* pv, size_t cb);
    HRESULT ParseFromVect(const ByteVector* pvb);
    HRESULT Serialize(BYTE* pv, size_t cb) const;
    HRESULT SerializeToVect(ByteVector* pvb) const;
    HRESULT SerializeAppendToVect(ByteVector* pvb) const;
    virtual size_t Length() const = 0;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) { return E_NOTIMPL; }
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const { return E_NOTIMPL; }
};

enum MT_KeyExchangeAlgorithm
{
    MTKEA_dhe_dss,
    MTKEA_dhe_rsa,
    MTKEA_dh_anon,
    MTKEA_rsa,
    MTKEA_dh_dss,
    MTKEA_dh_rsa
};

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
class MT_VariableLengthFieldBase : public MT_Structure
{
    public:
    MT_VariableLengthFieldBase();
    virtual ~MT_VariableLengthFieldBase() { }

    virtual size_t DataLength() const = 0;

    size_t Length() const;
    ACCESSORS(std::vector<F>*, Data, &m_vData);
    size_t Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos);

    size_t MinLength() const { return MinSize; }
    size_t MaxLength() const { return MaxSize; }

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const = 0;

    std::vector<F> m_vData;
};

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
class MT_VariableLengthField : public MT_VariableLengthFieldBase
                                          <F,
                                           LengthFieldSize,
                                           MinSize,
                                           MaxSize>
{
    public:
    virtual size_t DataLength() const;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
class MT_VariableLengthByteField : public MT_VariableLengthFieldBase
                                              <BYTE,
                                               LengthFieldSize,
                                               MinSize,
                                               MaxSize>
{
    public:
    virtual size_t DataLength() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

template <typename F, size_t Size>
class MT_FixedLengthStructureBase : public MT_Structure
{
    public:
    MT_FixedLengthStructureBase();
    virtual ~MT_FixedLengthStructureBase() { }

    ACCESSORS(std::vector<F>*, Data, &m_vData);
    size_t Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos);

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const = 0;

    std::vector<F> m_vData;
};

template <typename F, size_t Size>
class MT_FixedLengthStructure : public MT_FixedLengthStructureBase<F, Size>
{
    public:
    virtual size_t Length() const;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

template <size_t Size>
class MT_FixedLengthByteStructure : public MT_FixedLengthStructureBase
                                               <BYTE,
                                               Size>
{
    public:
    virtual size_t Length() const;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

class MT_ProtocolVersion : public MT_Structure
{
    public:
    enum MTPV_Version
    {
        MTPV_TLS10 = 0x0301,
        MTPV_TLS12 = 0x0303,
    };

    MT_ProtocolVersion();
    ~MT_ProtocolVersion() {};

    MT_UINT16 Version() const;
    void SetVersion(MT_UINT16 ver) { m_version = ver; }

    size_t Length() const { return 2; } // sizeof(MT_UINT16)

    static bool IsKnownVersion(MT_UINT16 version);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT16 m_version;
};

// uint8 CipherSuite[2];    /* Cryptographic suite selector */
class MT_CipherSuite : public MT_FixedLengthByteStructure<2>
{
    public:
    HRESULT KeyExchangeAlgorithm(MT_KeyExchangeAlgorithm* pAlg) const;
    operator MT_CipherSuiteValue() const;
};

class MT_Random : public MT_Structure
{
    public:
    MT_Random();
    ~MT_Random() { }

    size_t Length() const { return 4 + RandomBytes()->size(); }

    MT_UINT32 GMTUnixTime() const { return m_timestamp; }
    void SetGMTUnixTime(MT_UINT32 timestamp) { m_timestamp = timestamp; }

    ACCESSORS(ByteVector*, RandomBytes, &m_vbRandomBytes);

    HRESULT PopulateNow();

    private:
    static const size_t c_cbRandomBytes;

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT32 m_timestamp;
    ByteVector m_vbRandomBytes;
};

class ConnectionParameters
{
    public:
    ConnectionParameters();
    ~ConnectionParameters();

    HRESULT Initialize(PCCERT_CHAIN_CONTEXT pCertChain);

    ACCESSORS(PCCERT_CHAIN_CONTEXT*, CertChain, &m_pCertChain);
    ACCESSORS(PublicKeyCipherer*, PubKeyCipherer, m_spPubKeyCipherer.get());
    ACCESSORS(SymmetricCipherer*, ClientSymCipherer, m_spClientSymCipherer.get());
    ACCESSORS(SymmetricCipherer*, ServerSymCipherer, m_spServerSymCipherer.get());
    ACCESSORS(Hasher*, HashInst, m_spHasher.get());

    ACCESSORS(std::vector<std::shared_ptr<MT_Structure>>*, HandshakeMessages, &m_vHandshakeMessages);
    ACCESSORS(MT_CipherSuite*, CipherSuite, &m_cipherSuite);
    ACCESSORS(ByteVector*, MasterSecret, &m_vbMasterSecret);
    ACCESSORS(MT_ProtocolVersion*, NegotiatedVersion, &m_negotiatedVersion);
    ACCESSORS(MT_UINT64*, ReadSequenceNumber, &m_seqNumRead);
    ACCESSORS(MT_UINT64*, WriteSequenceNumber, &m_seqNumWrite);

    ACCESSORS(ByteVector*, ClientWriteMACKey, &m_vbClientWriteMACKey);
    ACCESSORS(ByteVector*, ServerWriteMACKey, &m_vbServerWriteMACKey);
    ACCESSORS(ByteVector*, ClientWriteKey, &m_vbClientWriteKey);
    ACCESSORS(ByteVector*, ServerWriteKey, &m_vbServerWriteKey);
    ACCESSORS(ByteVector*, ClientWriteIV, &m_vbClientWriteIV);
    ACCESSORS(ByteVector*, ServerWriteIV, &m_vbServerWriteIV);
    ACCESSORS(MT_Random*, ClientRandom, &m_clientRandom);
    ACCESSORS(MT_Random*, ServerRandom, &m_serverRandom);

    const CipherInfo* Cipher() const;
    const HashInfo* Hash() const;

    HRESULT
    ComputePRF(
        const ByteVector* pvbSecret,
        PCSTR szLabel,
        const ByteVector* pvbSeed,
        size_t cbMinimumLengthDesired,
        ByteVector* pvbPRF);

    private:
    MT_CipherSuite m_cipherSuite;
    std::shared_ptr<PublicKeyCipherer> m_spPubKeyCipherer;
    std::shared_ptr<SymmetricCipherer> m_spClientSymCipherer;
    std::shared_ptr<SymmetricCipherer> m_spServerSymCipherer;
    std::shared_ptr<Hasher> m_spHasher;

    MT_ProtocolVersion m_negotiatedVersion;
    ByteVector m_vbMasterSecret;
    MT_Random m_clientRandom;
    MT_Random m_serverRandom;
    ByteVector m_vbClientWriteMACKey;
    ByteVector m_vbServerWriteMACKey;
    ByteVector m_vbClientWriteKey;
    ByteVector m_vbServerWriteKey;
    ByteVector m_vbClientWriteIV;
    ByteVector m_vbServerWriteIV;
    MT_UINT64 m_seqNumRead;
    MT_UINT64 m_seqNumWrite;
    PCCERT_CHAIN_CONTEXT m_pCertChain;

    std::vector<std::shared_ptr<MT_Structure>> m_vHandshakeMessages;
};

class MT_Securable
{
    public:
    MT_Securable();
    virtual ~MT_Securable() { }
    HRESULT CheckSecurity();

    const ConnectionParameters* ConnParams() const { return m_pConnParams; }
    ConnectionParameters* ConnParams() { return const_cast<ConnectionParameters*>(static_cast<const MT_Securable*>(this)->ConnParams()); }
    virtual HRESULT SetConnectionParameters(ConnectionParameters* pSecurityParameters) { m_pConnParams = pSecurityParameters; return S_OK; }

    private:
    virtual HRESULT CheckSecurityPriv() = 0;

    ConnectionParameters* m_pConnParams;
};

template <typename T>
class MT_PublicKeyEncryptedStructure : public MT_Structure
{
    public:
    MT_PublicKeyEncryptedStructure();
    virtual ~MT_PublicKeyEncryptedStructure() { }

    virtual size_t Length() const;

    HRESULT DecryptStructure();
    HRESULT SetCipherer(const PublicKeyCipherer* pCipherer) { m_pCipherer = pCipherer; return S_OK; }

    ACCESSORS(T*, Structure, &m_structure);
    ACCESSORS(ByteVector*, EncryptedStructure, &m_vbEncryptedStructure);

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    ACCESSORS(ByteVector*, PlaintextStructure, &m_vbPlaintextStructure);

    const PublicKeyCipherer* GetCipherer() const { return m_pCipherer; }

    T m_structure;
    ByteVector m_vbPlaintextStructure;
    ByteVector m_vbEncryptedStructure;
    const PublicKeyCipherer* m_pCipherer;
};

class MT_ContentType : public MT_Structure
{
    public:
    enum MTCT_Type
    {
        MTCT_Type_ChangeCipherSpec = 20,
        MTCT_Type_Alert = 21,
        MTCT_Type_Handshake = 22,
        MTCT_Type_ApplicationData = 23,
        MTCT_Type_Unknown = 255,
    };

    MT_ContentType();
    ~MT_ContentType() {};

    size_t Length() const { return 1; }

    const MTCT_Type Type() const;
    void SetType(MTCT_Type eType) { m_eType = eType; }

    static bool IsValidContentType(MTCT_Type eType);

    private:
    static const MTCT_Type c_rgeValidTypes[];
    static const ULONG c_cValidTypes;

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCT_Type m_eType;
};

enum MT_CipherSuiteValue
{
    MTCS_TLS_RSA_WITH_NULL_MD5                 = 0x0001,
    MTCS_TLS_RSA_WITH_NULL_SHA                 = 0x0002,
    MTCS_TLS_RSA_WITH_NULL_SHA256              = 0x003B,
    MTCS_TLS_RSA_WITH_RC4_128_MD5              = 0x0004,
    MTCS_TLS_RSA_WITH_RC4_128_SHA              = 0x0005,
    MTCS_TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A,
    MTCS_TLS_RSA_WITH_AES_128_CBC_SHA          = 0x002F,
    MTCS_TLS_RSA_WITH_AES_256_CBC_SHA          = 0x0035,
    MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256       = 0x003C,
    MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256       = 0x003D
};

const MT_CipherSuiteValue* GetSupportedCipherSuites(size_t* pcCipherSuites);
bool IsKnownCipherSuite(MT_CipherSuiteValue eSuite);

// CipherSuite cipher_suites<2..2^16-1>;
typedef MT_VariableLengthField<MT_CipherSuite, 2, 2, MAXFORBYTES(2)>
        MT_CipherSuites;

// opaque SessionID<0..32>;
class MT_SessionID : public MT_VariableLengthByteField<1, 0, 32>
{
    public:
    MT_SessionID()
        : MT_VariableLengthByteField()
    { }

    HRESULT PopulateWithRandom();
};

class MT_CompressionMethod : public MT_Structure
{
    public:
    enum MTCM_Method
    {
        MTCM_Null = 0,
        MTCM_Unknown = 255,
    };

    MT_CompressionMethod();
    ~MT_CompressionMethod() { }

    size_t Length() const { return 1; }

    MT_UINT8 Method() const;
    void SetMethod(MTCM_Method eMethod) { m_compressionMethod = eMethod; }

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT8 m_compressionMethod;
};

// CompressionMethod compression_methods<1..2^8-1>;
typedef MT_VariableLengthField<MT_CompressionMethod, 1, 1, MAXFORBYTES(1)>
        MT_CompressionMethods;


class MT_RecordLayerMessage : public MT_Structure
{
    public:
    MT_RecordLayerMessage();
    virtual ~MT_RecordLayerMessage() {};

    size_t Length() const;

    ACCESSORS(MT_ContentType*, ContentType, &m_contentType);
    ACCESSORS(MT_ProtocolVersion*, ProtocolVersion, &m_protocolVersion);
    ACCESSORS(ByteVector*, Fragment, &m_vbFragment);

    MT_UINT16 PayloadLength() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_ContentType m_contentType;
    MT_ProtocolVersion m_protocolVersion;
    ByteVector m_vbFragment;
};



class MT_TLSPlaintext : public MT_RecordLayerMessage
{
};

class MT_TLSCiphertext : public MT_RecordLayerMessage, public MT_Securable
{
    public:
    MT_TLSCiphertext();
    ~MT_TLSCiphertext() {};

    ACCESSORS(MT_CipherFragment*, CipherFragment, m_spCipherFragment.get());

    HRESULT Encrypt();
    HRESULT Decrypt();

    HRESULT ToTLSPlaintext(MT_TLSPlaintext* pPlaintext) const;
    HRESULT SetConnectionParameters(ConnectionParameters* pConnectionParameters);

    HRESULT UpdateFragmentSecurity();

    private:
    HRESULT CheckSecurityPriv();

    std::shared_ptr<MT_CipherFragment> m_spCipherFragment;
};

class MT_Handshake : public MT_Structure
{
    public:
    enum MTH_HandshakeType
    {
        MTH_HelloRequest = 0,
        MTH_ClientHello = 1,
        MTH_ServerHello = 2,
        MTH_Certificate = 11,
        MTH_ServerKeyExchange = 12,
        MTH_CertificateRequest = 13,
        MTH_ServerHelloDone = 14,
        MTH_CertificateVerify = 15,
        MTH_ClientKeyExchange = 16,
        MTH_Finished = 20,
        MTH_Unknown = 255,
    };

    MT_Handshake();
    ~MT_Handshake() {}

    size_t PayloadLength() const { return Body()->size(); }
    size_t Length() const;

    ACCESSORS(MTH_HandshakeType*, Type, &m_eType);
    ACCESSORS(ByteVector*, Body, &m_vbBody);

    static bool IsKnownType(MTH_HandshakeType eType);
    static bool IsSupportedType(MTH_HandshakeType eType);

    std::wstring HandshakeTypeString() const;

    private:
    static const MTH_HandshakeType c_rgeKnownTypes[];
    static const ULONG c_cKnownTypes;
    static const MTH_HandshakeType c_rgeSupportedTypes[];
    static const ULONG c_cSupportedTypes;

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    // uint24 length
    size_t LengthFieldLength() const { return 3; }

    MTH_HandshakeType m_eType;
    ByteVector m_vbBody;
};

class MT_Extension : public MT_Structure
{
    public:
    enum MTE_ExtensionType
    {
        MTEE_RenegotiationInfo = 0xff01,
        MTEE_Unknown = 65535
    };

    MT_Extension();
    ~MT_Extension() { }

    size_t Length() const;

    ACCESSORS(MTE_ExtensionType*, ExtensionType, &m_extensionType);
    ACCESSORS(ByteVector*, ExtensionData, &m_vbExtensionData);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTE_ExtensionType m_extensionType;
    ByteVector m_vbExtensionData;
};

// Extension extensions<0..2^16-1>;
typedef MT_VariableLengthField<MT_Extension, 2, 0, MAXFORBYTES(2)> MT_HelloExtensions;

class MT_ClientHello : public MT_Structure
{
    public:
    MT_ClientHello();
    ~MT_ClientHello() { }

    ACCESSORS(MT_ProtocolVersion*, ProtocolVersion, &m_protocolVersion);
    ACCESSORS(MT_Random*, Random, &m_random);
    ACCESSORS(MT_SessionID*, SessionID, &m_sessionID);
    ACCESSORS(MT_CipherSuites*, CipherSuites, &m_cipherSuites);
    ACCESSORS(MT_CompressionMethods*, CompressionMethods, &m_compressionMethods);
    ACCESSORS(MT_HelloExtensions*, Extensions, &m_extensions);

    size_t Length() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    MT_ProtocolVersion m_protocolVersion;
    MT_Random m_random;
    MT_SessionID m_sessionID;
    MT_CipherSuites m_cipherSuites;
    MT_CompressionMethods m_compressionMethods;
    MT_HelloExtensions m_extensions;
};

class MT_ServerHello : public MT_Structure
{
    public:
    MT_ServerHello();
    ~MT_ServerHello() { }

    size_t Length() const;
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    ACCESSORS(MT_ProtocolVersion*, ProtocolVersion, &m_protocolVersion);
    ACCESSORS(MT_Random*, Random, &m_random);
    ACCESSORS(MT_SessionID*, SessionID, &m_sessionID);
    ACCESSORS(MT_CipherSuite*, CipherSuite, &m_cipherSuite);
    ACCESSORS(MT_CompressionMethod*, CompressionMethod, &m_compressionMethod);
    ACCESSORS(MT_HelloExtensions*, Extensions, &m_extensions);

    private:
    MT_ProtocolVersion m_protocolVersion;
    MT_Random m_random;
    MT_SessionID m_sessionID;
    MT_CipherSuite m_cipherSuite;
    MT_CompressionMethod m_compressionMethod;
    MT_HelloExtensions m_extensions;
};

class TLSConnection
{
    public:
    TLSConnection();
    virtual ~TLSConnection() { }

    HRESULT Initialize(PCCERT_CHAIN_CONTEXT pCertChain);

    HRESULT HandleMessage(
        const BYTE* pv,
        size_t cb,
        ByteVector* pvbResponse);

    private:
    HRESULT RespondToClientHello(
        const MT_ClientHello* pClientHello,
        std::vector<std::shared_ptr<MT_RecordLayerMessage>>* pResponses);

    HRESULT RespondToFinished(
        std::vector<std::shared_ptr<MT_RecordLayerMessage>>* pResponses);

    HRESULT RespondToApplicationData(
        std::vector<std::shared_ptr<MT_RecordLayerMessage>>* pResponses);

    HRESULT ComputeMasterSecret(const MT_PreMasterSecret* pPreMasterSecret);
    HRESULT GenerateKeyMaterial();

    ACCESSORS(ConnectionParameters*, ConnParams, &m_connParams);
    ConnectionParameters m_connParams;

    // TODO: absolutely not the right way to do this
    bool m_fSecureMode;
};

// opaque ASN.1Cert<1..2^24-1>;
typedef MT_VariableLengthByteField<3, 1, MAXFORBYTES(3)> MT_ASN1Cert;

// ASN.1Cert certificate_list<0..2^24-1>;
typedef MT_VariableLengthField<MT_ASN1Cert, 3, 0, MAXFORBYTES(3)> MT_CertificateList;

class MT_Certificate : public MT_Structure
{
    public:
    MT_Certificate();
    ~MT_Certificate() { }

    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    size_t Length() const { return CertificateList()->Length(); }

    HRESULT AddCertificateFromMemory(const BYTE* pvCert, size_t cbCert);

    ACCESSORS(MT_CertificateList*, CertificateList, &m_certificateList);

    private:
    MT_CertificateList m_certificateList;
};

class MT_PreMasterSecret : public MT_Structure
{
    typedef MT_FixedLengthByteStructure<46> OpaqueRandom;

    public:
    MT_PreMasterSecret();
    virtual ~MT_PreMasterSecret() { }

    size_t Length() const;

    ACCESSORS(MT_ProtocolVersion*, ClientVersion, &m_clientVersion);
    ACCESSORS(OpaqueRandom*, Random, &m_random);


    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_ProtocolVersion m_clientVersion;
    OpaqueRandom m_random;
};

typedef MT_PublicKeyEncryptedStructure<MT_PreMasterSecret> MT_EncryptedPreMasterSecret;

template <typename KeyType>
class MT_ClientKeyExchange : public MT_Structure
{
    public:
    MT_ClientKeyExchange();
    virtual ~MT_ClientKeyExchange() { }

    size_t Length() const { return ExchangeKeys()->Length(); }

    // TODO: make shared_ptr, I think?
    ACCESSORS(KeyType*, ExchangeKeys, m_spExchangeKeys.get());

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    // HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    std::shared_ptr<KeyType> m_spExchangeKeys;
};

class MT_ChangeCipherSpec : public MT_Structure
{
    public:
    enum MTCCS_Type
    {
        MTCCS_ChangeCipherSpec = 1,
        MTCCS_Unknown = 255
    };

    MT_ChangeCipherSpec();
    ~MT_ChangeCipherSpec() { }

    size_t Length() const { return 1; }

    ACCESSORS(MTCCS_Type*, Type, &m_type);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCCS_Type m_type;
};

class MT_Finished : public MT_Structure, public MT_Securable
{
    typedef MT_FixedLengthByteStructure<12> MTF_VerifyData;

    public:
    MT_Finished();
    ~MT_Finished() { }

    size_t Length() const { return VerifyData()->Length(); }

    ACCESSORS(MTF_VerifyData*, VerifyData, &m_verifyData);
    HRESULT ComputeVerifyData(PCSTR szLabel, ByteVector* pvbVerifyData);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    HRESULT CheckSecurityPriv();

    MTF_VerifyData m_verifyData;
};

class MT_CipherFragment : public MT_Structure, public MT_Securable
{
    public:
    MT_CipherFragment();
    virtual ~MT_CipherFragment() { }

    virtual size_t Length() const;

    ACCESSORS(ByteVector*, Content, &m_vbContent);
    ACCESSORS(ByteVector*, RawContent, &m_vbRawContent);

    protected:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    private:
    HRESULT CheckSecurityPriv() { assert(false); return E_NOTIMPL; }

    ByteVector m_vbContent;
    ByteVector m_vbRawContent;
};

class MT_GenericStreamCipher : public MT_CipherFragment
{
    public:
    MT_GenericStreamCipher();
    ~MT_GenericStreamCipher() { }

    HRESULT
    UpdateWriteSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    ACCESSORS(ByteVector*, MAC, &m_vbMAC);

    HRESULT
    CheckSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    HRESULT
    ComputeSecurityInfo(
        MT_UINT64 sequenceNumber,
        const ByteVector* pvbMACKey,
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion,
        ByteVector* pvbMAC);

    ByteVector m_vbMAC;
};

class MT_GenericBlockCipher_TLS10 : public MT_CipherFragment
{
    public:
    MT_GenericBlockCipher_TLS10();
    ~MT_GenericBlockCipher_TLS10() { }

    ACCESSORS(ByteVector*, MAC, &m_vbMAC);
    ACCESSORS(ByteVector*, Padding, &m_vbPadding);
    MT_UINT8 PaddingLength() const;

    HRESULT
    UpdateWriteSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    HRESULT
    CheckSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    HRESULT
    ComputeSecurityInfo(
        MT_UINT64 sequenceNumber,
        const ByteVector* pvbMACKey,
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion,
        ByteVector* pvbMAC,
        ByteVector* pvbPadding);

    ByteVector m_vbMAC;
    ByteVector m_vbPadding;
};

class MT_GenericBlockCipher_TLS12 : public MT_CipherFragment
{
    public:
    MT_GenericBlockCipher_TLS12();
    ~MT_GenericBlockCipher_TLS12() { }

    ACCESSORS(ByteVector*, IVNext, &m_vbIVNext);
    ACCESSORS(ByteVector*, MAC, &m_vbMAC);
    ACCESSORS(ByteVector*, Padding, &m_vbPadding);
    MT_UINT8 PaddingLength() const;

    HRESULT
    UpdateWriteSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    HRESULT
    CheckSecurity(
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    HRESULT
    ComputeSecurityInfo(
        MT_UINT64 sequenceNumber,
        const ByteVector* pvbMACKey,
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion,
        ByteVector* pvbMAC,
        ByteVector* pvbPadding);

    ByteVector m_vbIVNext;
    ByteVector m_vbMAC;
    ByteVector m_vbPadding;
};

/*
class MT_Thingy : public MT_Structure
{
    public:
    MT_Thingy();
    ~MT_Thingy() { }

    size_t Length() const { return Thingy()->Length(); }

    ACCESSORS(ThingyType*, Thingy, &m_thingy);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    // HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    ThingyType m_thingy;
};
*/

HRESULT
ParseMessage(
    const BYTE* pv,
    size_t cb
);

template <typename N>
HRESULT
ReadNetworkLong(
    const BYTE* pv,
    size_t cb,
    size_t cbToRead,
    N* pResult
);

template <typename I>
HRESULT
WriteNetworkLong(
    I toWrite,
    size_t cbToWrite,
    BYTE* pv,
    size_t cb
);

HRESULT
WriteRandomBytes(
    BYTE* pv,
    size_t cb
);

HRESULT
EpochTimeFromSystemTime(
    const SYSTEMTIME* pST,
    ULARGE_INTEGER* pLI
);

template <typename T>
HRESULT
SerializeMessagesToVector(
    typename std::vector<T>::const_iterator itBegin,
    typename std::vector<T>::const_iterator itEnd,
    ByteVector* pvb
);

template <typename T>
HRESULT
SerializeMessagesToVector(
    typename std::vector<std::shared_ptr<T>>::const_iterator itBegin,
    typename std::vector<std::shared_ptr<T>>::const_iterator itEnd,
    ByteVector* pvb
);

template <typename T>
void ResizeVector(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

template <>
void ResizeVector(ByteVector* pv, typename ByteVector::size_type siz);

template <typename T>
void EnsureVectorSize(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

HRESULT
ComputePRF_TLS12(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbMinimumLengthDesired,
    ByteVector* pvbPRF);

HRESULT
ComputePRF_TLS10(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    PCSTR szLabel,
    const ByteVector* pvbSeed,
    size_t cbMinimumLengthDesired,
    ByteVector* pvbPRF);

HRESULT
CryptoInfoFromCipherSuite(
    const MT_CipherSuite* pCipherSuite,
    CipherInfo* pCipherInfo,
    HashInfo* pHashInfo);

}
#pragma warning(pop)
