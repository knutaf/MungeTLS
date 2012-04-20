#pragma once
#include <windows.h>
#include <vector>
#include <memory>
#include "MungeCrypto.h"

#pragma warning(push)
#pragma warning(disable : 4100)
namespace MungeTLS
{

typedef unsigned long MT_UINT16;

const HRESULT MT_E_INCOMPLETE_MESSAGE                       = 0x80230001;
const HRESULT MT_E_UNKNOWN_CONTENT_TYPE                     = 0x80230002;
const HRESULT MT_E_UNKNOWN_PROTOCOL_VERSION                 = 0x80230003;
const HRESULT MT_E_UNKNOWN_HANDSHAKE_TYPE                   = 0x80230004;
const HRESULT MT_E_UNSUPPORTED_HANDSHAKE_TYPE               = 0x80230005;
const HRESULT MT_E_DATA_SIZE_OUT_OF_RANGE                   = 0x80230006;
const HRESULT MT_E_UNKNOWN_COMPRESSION_METHOD               = 0x80230007;
const HRESULT MT_E_UNKNOWN_CIPHER_SUITE                     = 0x80230008;
const HRESULT MT_E_UNSUPPORTED_KEY_EXCHANGE                 = 0x80230009;
const HRESULT E_INSUFFICIENT_BUFFER                         = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;

#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

extern const BYTE c_abyCert[];
extern const size_t c_cbCert;

class MT_Structure
{
    public:
    MT_Structure() { }
    virtual ~MT_Structure() { }

    HRESULT ParseFrom(const BYTE* pv, size_t cb);
    HRESULT ParseFromVect(const std::vector<BYTE>* pvb);
    HRESULT Serialize(BYTE* pv, size_t cb) const;
    HRESULT SerializeToVect(std::vector<BYTE>* pvb) const;
    HRESULT SerializeAppendToVect(std::vector<BYTE>* pvb) const;
    virtual size_t Length() const = 0;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) { return E_NOTIMPL; }
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const { return E_NOTIMPL; }
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
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const = 0;

    size_t Length() const;
    const std::vector<F>* Data() const { return &m_vData; }
    std::vector<F>* Data() { return const_cast<std::vector<F>*>(static_cast<const MT_VariableLengthFieldBase*>(this)->Data()); }
    size_t Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos);

    size_t MinLength() const { return MinSize; }
    size_t MaxLength() const { return MaxSize; }

    private:
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
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

template <typename F, size_t Size>
class MT_FixedLengthStructureBase : public MT_Structure
{
    public:
    MT_FixedLengthStructureBase();
    virtual ~MT_FixedLengthStructureBase() { }

    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const = 0;

    const std::vector<F>* Data() const { return &m_vData; }
    std::vector<F>* Data() { return const_cast<std::vector<F>*>(static_cast<const MT_FixedLengthStructureBase*>(this)->Data()); }
    size_t Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos);

    private:
    std::vector<F> m_vData;
};

template <typename F, size_t Size>
class MT_FixedLengthStructure : public MT_FixedLengthStructureBase<F, Size>
{
    public:
    virtual size_t Length() const;
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
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

template <typename T>
class MT_PublicKeyEncryptedStructure : public MT_Structure
{
    public:
    MT_PublicKeyEncryptedStructure();
    virtual ~MT_PublicKeyEncryptedStructure() { }

    virtual size_t Length() const;
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    HRESULT DecryptStructure();
    HRESULT SetCipherer(const PublicKeyCipherer* pCipherer) { m_pCipherer = pCipherer; return S_OK; }

    const T* Structure() const { return &m_structure; }
    T* Structure() { return const_cast<T*>(static_cast<const MT_PublicKeyEncryptedStructure<T>*>(this)->Structure()); }

    const std::vector<BYTE>* EncryptedStructure() const { return &m_vbEncryptedStructure; }
    std::vector<BYTE>* EncryptedStructure() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_PublicKeyEncryptedStructure<T>*>(this)->EncryptedStructure()); }

    private:
    const std::vector<BYTE>* PlaintextStructure() const { return &m_vbPlaintextStructure; }
    std::vector<BYTE>* PlaintextStructure() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_PublicKeyEncryptedStructure<T>*>(this)->PlaintextStructure()); }

    const PublicKeyCipherer* GetCipherer() const { return m_pCipherer; }

    T m_structure;
    std::vector<BYTE> m_vbPlaintextStructure;
    std::vector<BYTE> m_vbEncryptedStructure;
    const PublicKeyCipherer* m_pCipherer;
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

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    size_t Length() const { return 1; }

    const MTCT_Type Type() const;
    void SetType(MTCT_Type eType) { m_eType = eType; }

    static bool IsValidContentType(MTCT_Type eType);

    private:
    MTCT_Type m_eType;

    static const MTCT_Type c_rgeValidTypes[];
    static const ULONG c_cValidTypes;
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

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT16 Version() const;
    void SetVersion(MT_UINT16 ver) { m_version = ver; }

    size_t Length() const { return 2; } // sizeof(MT_UINT16)

    static bool IsKnownVersion(MT_UINT16 version);

    private:
    MT_UINT16 m_version;
};

class MT_Random : public MT_Structure
{
    public:
    MT_Random();
    ~MT_Random() { }

    size_t Length() const { return 4 + RandomBytes()->size(); }
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT32 GMTUnixTime() const { return m_timestamp; }
    void SetGMTUnixTime(MT_UINT32 timestamp) { m_timestamp = timestamp; }

    const std::vector<BYTE>* RandomBytes() const { return &m_vbRandomBytes; }
    std::vector<BYTE>* RandomBytes() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Random*>(this)->RandomBytes()); }

    HRESULT PopulateNow();

    private:
    static const size_t c_cbRandomBytes;

    MT_UINT32 m_timestamp;
    std::vector<BYTE> m_vbRandomBytes;
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

// uint8 CipherSuite[2];    /* Cryptographic suite selector */
class MT_CipherSuite : public MT_FixedLengthByteStructure<2>
{
    public:
    HRESULT KeyExchangeAlgorithm(MT_KeyExchangeAlgorithm* pAlg) const;
    operator MT_CipherSuiteValue() const;
};

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
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT8 Method() const;
    void SetMethod(MTCM_Method eMethod) { m_compressionMethod = eMethod; }

    private:
    MT_UINT8 m_compressionMethod;
};

// CompressionMethod compression_methods<1..2^8-1>;
typedef MT_VariableLengthField<MT_CompressionMethod, 1, 1, MAXFORBYTES(1)>
        MT_CompressionMethods;

typedef MT_VariableLengthByteField<2, 0, MAXFORBYTES(2)> MT_HelloExtensions;






class MT_TLSPlaintext : public MT_Structure
{
    public:
    MT_TLSPlaintext();
    ~MT_TLSPlaintext() {};

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    size_t Length() const;

    const MT_ContentType* ContentType() const { return &m_contentType; }
    MT_ContentType* ContentType() { return const_cast<MT_ContentType*>(static_cast<const MT_TLSPlaintext*>(this)->ContentType()); }

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_TLSPlaintext*>(this)->ProtocolVersion()); }

    MT_UINT16 PayloadLength() const;

    const std::vector<BYTE>* Fragment() const { return &m_vbFragment; }
    std::vector<BYTE>* Fragment() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_TLSPlaintext*>(this)->Fragment()); }

    private:
    MT_ContentType m_contentType;
    MT_ProtocolVersion m_protocolVersion;
    std::vector<BYTE> m_vbFragment;
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

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    size_t PayloadLength() const { return Body()->size(); }
    size_t Length() const;

    MTH_HandshakeType HandshakeType() const;
    void SetType(MTH_HandshakeType eType) { m_eType = eType; }

    const std::vector<BYTE>* Body() const { return &m_vbBody; }
    std::vector<BYTE>* Body() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Handshake*>(this)->Body()); }

    static bool IsKnownType(MTH_HandshakeType eType);
    static bool IsSupportedType(MTH_HandshakeType eType);

    private:
    static const MTH_HandshakeType c_rgeKnownTypes[];
    static const ULONG c_cKnownTypes;
    static const MTH_HandshakeType c_rgeSupportedTypes[];
    static const ULONG c_cSupportedTypes;

    // uint24 length
    size_t LengthFieldLength() const { return 3; }

    MTH_HandshakeType m_eType;
    std::vector<BYTE> m_vbBody;
};

class MT_ClientHello : public MT_Structure
{
    public:
    MT_ClientHello();
    ~MT_ClientHello() { }

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_ClientHello*>(this)->ProtocolVersion()); }

    const MT_Random* Random() const { return &m_random; }
    MT_Random* Random() { return const_cast<MT_Random*>(static_cast<const MT_ClientHello*>(this)->Random()); }

    const MT_SessionID* SessionID() const { return &m_sessionID; }
    MT_SessionID* SessionID() { return const_cast<MT_SessionID*>(static_cast<const MT_ClientHello*>(this)->SessionID()); }

    const MT_CipherSuites* CipherSuites() const { return &m_cipherSuites; }
    MT_CipherSuites* CipherSuites() { return const_cast<MT_CipherSuites*>(static_cast<const MT_ClientHello*>(this)->CipherSuites()); }

    const MT_CompressionMethods* CompressionMethods() const { return &m_compressionMethods; }
    MT_CompressionMethods* CompressionMethods() { return const_cast<MT_CompressionMethods*>(static_cast<const MT_ClientHello*>(this)->CompressionMethods()); }

    const MT_HelloExtensions* Extensions() const { return &m_extensions; }
    MT_HelloExtensions* Extensions() { return const_cast<MT_HelloExtensions*>(static_cast<const MT_ClientHello*>(this)->Extensions()); }

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    size_t Length() const;

    private:
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

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_ServerHello*>(this)->ProtocolVersion()); }

    const MT_Random* Random() const { return &m_random; }
    MT_Random* Random() { return const_cast<MT_Random*>(static_cast<const MT_ServerHello*>(this)->Random()); }

    const MT_SessionID* SessionID() const { return &m_sessionID; }
    MT_SessionID* SessionID() { return const_cast<MT_SessionID*>(static_cast<const MT_ServerHello*>(this)->SessionID()); }

    const MT_CipherSuite* CipherSuite() const { return &m_cipherSuite; }
    MT_CipherSuite* CipherSuite() { return const_cast<MT_CipherSuite*>(static_cast<const MT_ServerHello*>(this)->CipherSuite()); }

    const MT_CompressionMethod* CompressionMethod() const { return &m_compressionMethod; }
    MT_CompressionMethod* CompressionMethod() { return const_cast<MT_CompressionMethod*>(static_cast<const MT_ServerHello*>(this)->CompressionMethod()); }

    const MT_HelloExtensions* Extensions() const { return &m_extensions; }
    MT_HelloExtensions* Extensions() { return const_cast<MT_HelloExtensions*>(static_cast<const MT_ServerHello*>(this)->Extensions()); }

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

    HRESULT Initialize();

    HRESULT HandleMessage(
        const BYTE* pv,
        size_t cb,
        std::vector<BYTE>* pvbResponse);

    const PCCERT_CONTEXT* CertContext() const { return &m_pCertContext; }
    PCCERT_CONTEXT* CertContext() { return const_cast<PCCERT_CONTEXT*>(static_cast<const TLSConnection*>(this)->CertContext()); }

    const PublicKeyCipherer* PubKeyCipherer() const { return m_spPubKeyCipherer.get(); }
    PublicKeyCipherer* PubKeyCipherer() { return const_cast<PublicKeyCipherer*>(static_cast<const TLSConnection*>(this)->PubKeyCipherer()); }

    const MT_CipherSuite* CipherSuite() const { return &m_cipherSuite; }
    MT_CipherSuite* CipherSuite() { return const_cast<MT_CipherSuite*>(static_cast<const TLSConnection*>(this)->CipherSuite()); }

    private:
    HRESULT RespondTo(
        const MT_ClientHello* pClientHello,
        std::vector<MT_TLSPlaintext>* pResponses);

    MT_CipherSuite m_cipherSuite;
    PCCERT_CONTEXT m_pCertContext;
    std::shared_ptr<PublicKeyCipherer> m_spPubKeyCipherer;
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

    HRESULT PopulateFromFile(PCWSTR wszFilename);
    HRESULT PopulateFromMemory(const BYTE* pvCert, size_t cbCert);

    const MT_CertificateList* CertificateList() const { return &m_certificateList; }
    MT_CertificateList* CertificateList() { return const_cast<MT_CertificateList*>(static_cast<const MT_Certificate*>(this)->CertificateList()); }

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
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    // HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    const MT_ProtocolVersion* ClientVersion() const { return &m_clientVersion; }
    MT_ProtocolVersion* ClientVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_PreMasterSecret*>(this)->ClientVersion()); }

    const OpaqueRandom* Random() const { return &m_random; }
    OpaqueRandom* Random() { return const_cast<OpaqueRandom*>(static_cast<const MT_PreMasterSecret*>(this)->Random()); }

    private:
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
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    // HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    // TODO: make shared_ptr, I think?
    const KeyType* ExchangeKeys() const { return m_spExchangeKeys.get(); }
    KeyType* ExchangeKeys() { return const_cast<KeyType*>(static_cast<const MT_ClientKeyExchange*>(this)->ExchangeKeys()); }

    private:
    std::shared_ptr<KeyType> m_spExchangeKeys;
};


/*
class MT_Thingy : public MT_Structure
{
    public:
    MT_Thingy();
    ~MT_Thingy() { }

    size_t Length() const { return Thingy->Length(); }
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    // HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    const ThingyType* Thingy() const { return &m_thingy; }
    ThingyType* Thingy() { return const_cast<ThingyType*>(static_cast<const MT_Thingy*>(this)->Thingy()); }

    private:
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
    const std::vector<T>* pvMessages,
    std::vector<BYTE>* pvb
);

template <typename T>
void ResizeVector(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

template <>
void ResizeVector(std::vector<BYTE>* pv, typename std::vector<BYTE>::size_type siz);

template <typename T>
void EnsureVectorSize(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

}
#pragma warning(pop)
