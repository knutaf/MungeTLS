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
const HRESULT MT_E_NO_PREFERRED_CIPHER_SUITE                = 0x80230010;
const HRESULT E_INSUFFICIENT_BUFFER                         = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

const HRESULT MT_S_LISTENER_HANDLED                         = 0x00230002;
const HRESULT MT_S_LISTENER_IGNORED                         = 0x00230003;

const DWORD MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE         = 0x00000000;
const DWORD MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE          = 0x00000001;

/************************** Protocol Constants **********************/

// A public-key-encrypted element is encoded as an opaque vector<0..2^16-1>
const size_t c_cbPublicKeyEncrypted_LFL = 2;

// uint16 length;
const size_t c_cbRecordLayerMessage_Fragment_LFL = 2;

// enum going from 0 - 255
const size_t c_cbContentType_Length = 1;

// uint8 major, minor;
const size_t c_cbProtocolVersion_Length = 2;

// uint8 CipherSuite[2];    /* Cryptographic suite selector */
const size_t c_cbCipherSuite_Length = 2;

// CipherSuite cipher_suites<2..2^16-1>;
const size_t c_cbCipherSuites_LFL = 2;
const size_t c_cbCipherSuites_MinLength = 2;
const size_t c_cbCipherSuites_MaxLength = MAXFORBYTES(c_cbCipherSuites_LFL);

// opaque SessionID<0..32>;
const size_t c_cbSessionID_LFL = 1;
const size_t c_cbSessionID_MinLength = 0;
const size_t c_cbSessionID_MaxLength = 32;

// enum going from 0 - 255
const size_t c_cbHandshakeType_Length = 1;

// uint24 length;
const size_t c_cbHandshake_LFL = 3;

// uint32 gmt_unix_time;
const size_t c_cbRandomTime_Length = 4;

// opaque random_bytes[28];
const size_t c_cbRandomBytes_Length = 28;

// enum going from 0 - 255
const size_t c_cbCompressionMethod_Length = 1;

// CompressionMethod compression_methods<1..2^8-1>;
const size_t c_cbCompressionMethods_LFL = 1;
const size_t c_cbCompressionMethods_MinLength = 1;
const size_t c_cbCompressionMethods_MaxLength = MAXFORBYTES(c_cbCompressionMethods_LFL);

// opaque ASN.1Cert<1..2^24-1>;
const size_t c_cbASN1Cert_LFL = 3;
const size_t c_cbASN1Cert_MinLength = 1;
const size_t c_cbASN1Cert_MaxLength = MAXFORBYTES(c_cbASN1Cert_LFL);

// ASN.1Cert certificate_list<0..2^24-1>;
const size_t c_cbASN1Certs_LFL = 3;
const size_t c_cbASN1Certs_MinLength = 0;
const size_t c_cbASN1Certs_MaxLength = MAXFORBYTES(c_cbASN1Certs_LFL);

// enum going from 0 - 255
const size_t c_cbChangeCipherSpec_Length = 1;

// dunno where this is documented
const size_t c_cbExtensionType_Length = 2;

// dunno where this is documented
const size_t c_cbExtensionData_LFL = 2;

// Extension extensions<0..2^16-1>;
const size_t c_cbHelloExtensions_LFL = 2;
const size_t c_cbHelloExtensions_MinLength = 0;
const size_t c_cbHelloExtensions_MaxLength = MAXFORBYTES(c_cbHelloExtensions_LFL);

// uint8 padding_length;
const size_t c_cbGenericBlockCipher_Padding_LFL = 1;

// enum going from 0 - 255
const size_t c_cbAlertLevel_Length = 1;

// enum going from 0 - 255
const size_t c_cbAlertDescription_Length = 1;

// opaque random[46];
const size_t c_cbPreMasterSecretRandom_Length = 46;

// "The master secret is always exactly 48 bytes in length."
const size_t c_cbMasterSecret_Length = 48;

// opaque verify_data[12];
const size_t c_cbFinishedVerifyData_Length = 12;

// Sequence numbers are of type uint64 and may not exceed 2^64-1.
const size_t c_cbSequenceNumber_Length = 8;

// master_secret = PRF(pre_master_secret, "master secret", ...
const PCSTR c_szMasterSecret_PRFLabel = "master secret";

// key_block = PRF(SecurityParameters.master_secret, "key expansion", ...
const PCSTR c_szKeyExpansion_PRFLabel = "key expansion";

// For Finished messages sent by the server, the string "server finished".
const PCSTR c_szServerFinished_PRFLabel = "server finished";

// For Finished messages sent by the client, the string "client finished".
const PCSTR c_szClientFinished_PRFLabel = "client finished";

// struct { } HelloRequest;
const size_t c_cbHelloRequest_Length = 0;

// RFC 5746 - opaque renegotiated_connection<0..255>;
const size_t c_cbRenegotiatedConnection_LFL = 1;
const size_t c_cbRenegotiatedConnection_MinLength = 0;
const size_t c_cbRenegotiatedConnection_MaxLength = 255;

/************************** End Protocol Constants **********************/

extern const BYTE c_abyCert[];
extern const size_t c_cbCert;

class MT_PreMasterSecret;
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
        MTPV_Unknown = 0,
        MTPV_TLS10 = 0x0301,
        MTPV_TLS11 = 0x0302,
        MTPV_TLS12 = 0x0303,
    };

    MT_ProtocolVersion();
    ~MT_ProtocolVersion() {};

    ACCESSORS(MTPV_Version*, Version, &m_eVersion);

    size_t Length() const { return c_cbProtocolVersion_Length; }
    bool operator==(const MT_ProtocolVersion& rOther) const { return *Version() == *rOther.Version(); }

    static bool IsKnownVersion(MTPV_Version eVersion);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTPV_Version m_eVersion;
};

class MT_CipherSuite : public MT_FixedLengthByteStructure<c_cbCipherSuite_Length>
{
    public:
    MT_CipherSuite();
    MT_CipherSuite(MT_CipherSuiteValue eValue);

    HRESULT KeyExchangeAlgorithm(MT_KeyExchangeAlgorithm* pAlg) const;
    HRESULT Value(MT_CipherSuiteValue* peValue) const;
    HRESULT SetValue(MT_CipherSuiteValue eValue);
    bool operator==(const MT_CipherSuite& rOther) const;
};

class MT_Random : public MT_Structure
{
    public:
    MT_Random();
    ~MT_Random() { }

    size_t Length() const { return c_cbRandomTime_Length + RandomBytes()->size(); }

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

class MT_Extension : public MT_Structure
{
    public:
    enum MTE_ExtensionType
    {
        MTEE_RenegotiationInfo = 0xff01,
        MTEE_Unknown = 65535
    };

    MT_Extension();
    virtual ~MT_Extension() { }

    size_t Length() const;

    ACCESSORS(MTE_ExtensionType*, ExtensionType, &m_extensionType);
    ACCESSORS(ByteVector*, ExtensionData, &m_vbExtensionData);

    protected:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    private:
    MTE_ExtensionType m_extensionType;
    ByteVector m_vbExtensionData;
};

class MT_RenegotiationInfoExtension : public MT_Extension
{
    typedef MT_VariableLengthByteField<
                c_cbRenegotiatedConnection_LFL,
                c_cbRenegotiatedConnection_MinLength,
                c_cbRenegotiatedConnection_MaxLength>
            MT_RenegotiatedConnection;

    public:
    MT_RenegotiationInfoExtension();
    ~MT_RenegotiationInfoExtension() { }

    ACCESSORS(MT_RenegotiatedConnection*, RenegotiatedConnection, &m_renegotiatedConnection);

    // really don't like the design of this. suggestions welcome on improvement
    HRESULT UpdateDerivedFields();

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    MT_RenegotiatedConnection m_renegotiatedConnection;
};

typedef MT_VariableLengthField<
            MT_Extension,
            c_cbHelloExtensions_LFL,
            c_cbHelloExtensions_MinLength,
            c_cbHelloExtensions_MaxLength>
        MT_HelloExtensions;

enum MT_CipherSuiteValue
{
    MTCS_UNKNOWN                               = 0xFFFF,
    MTCS_TLS_RSA_WITH_NULL_NULL                = 0x0000,
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

const std::vector<MT_CipherSuiteValue>* GetCipherSuitePreference();
bool IsKnownCipherSuite(MT_CipherSuiteValue eSuite);

HRESULT
ChooseBestCipherSuite(
    const std::vector<MT_CipherSuiteValue>* pveClientPreference,
    const std::vector<MT_CipherSuiteValue>* pveServerPreference,
    MT_CipherSuiteValue* pePreferredCipherSuite);

typedef MT_VariableLengthField<
            MT_CipherSuite,
            c_cbCipherSuites_LFL,
            c_cbCipherSuites_MinLength,
            c_cbCipherSuites_MaxLength>
        MT_CipherSuites;

class MT_SessionID : public MT_VariableLengthByteField<
                                c_cbSessionID_LFL,
                                c_cbSessionID_MinLength,
                                c_cbSessionID_MaxLength>
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

    size_t Length() const { return c_cbCompressionMethod_Length; }

    ACCESSORS(MTCM_Method*, Method, &m_eMethod);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCM_Method m_eMethod;
};

typedef MT_VariableLengthField<
            MT_CompressionMethod,
            c_cbCompressionMethods_LFL,
            c_cbCompressionMethods_MinLength,
            c_cbCompressionMethods_MaxLength>
        MT_CompressionMethods;

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

typedef MT_VariableLengthByteField<
            c_cbASN1Cert_LFL,
            c_cbASN1Cert_MinLength,
            c_cbASN1Cert_MaxLength>
        MT_ASN1Cert;

typedef MT_VariableLengthField<
            MT_ASN1Cert,
            c_cbASN1Certs_LFL,
            c_cbASN1Certs_MinLength,
            c_cbASN1Certs_MaxLength>
        MT_CertificateList;

typedef MT_FixedLengthByteStructure<c_cbFinishedVerifyData_Length> MT_FinishedVerifyData;

class EndpointParameters
{
    public:
    EndpointParameters();
    ~EndpointParameters() { }

    HRESULT Initialize(
        std::shared_ptr<SymmetricCipherer> spSymCipherer,
        std::shared_ptr<Hasher> spHasher);

    ACCESSORS(std::shared_ptr<SymmetricCipherer>*, SymCipherer, &m_spSymCipherer);
    ACCESSORS(std::shared_ptr<Hasher>*, HashInst, &m_spHasher);
    ACCESSORS(MT_CipherSuite*, CipherSuite, &m_cipherSuite);
    ACCESSORS(MT_ProtocolVersion::MTPV_Version*, Version, &m_eVersion);
    ACCESSORS(MT_UINT64*, SequenceNumber, &m_seqNum);
    ACCESSORS(ByteVector*, Key, &m_vbKey);
    ACCESSORS(ByteVector*, MACKey, &m_vbMACKey);
    ACCESSORS(ByteVector*, IV, &m_vbIV);

    const CipherInfo* Cipher() const;
    const HashInfo* Hash() const;

    private:
    MT_ProtocolVersion::MTPV_Version m_eVersion;
    std::shared_ptr<Hasher> m_spHasher;
    MT_CipherSuite m_cipherSuite;
    std::shared_ptr<SymmetricCipherer> m_spSymCipherer;
    ByteVector m_vbKey;
    ByteVector m_vbMACKey;
    ByteVector m_vbIV;
    MT_UINT64 m_seqNum;
};

class ConnectionParameters
{
    public:
    ConnectionParameters();
    ~ConnectionParameters() { }

    HRESULT Initialize(
        const MT_CertificateList* pCertChain,
        std::shared_ptr<PublicKeyCipherer> spPubKeyCipherer,
        std::shared_ptr<SymmetricCipherer> spClientSymCipherer,
        std::shared_ptr<SymmetricCipherer> spServerSymCipherer,
        std::shared_ptr<Hasher> spHasher);

    ACCESSORS(MT_CertificateList*, CertChain, &m_certChain);
    ACCESSORS(std::shared_ptr<PublicKeyCipherer>*, PubKeyCipherer, &m_spPubKeyCipherer);
    ACCESSORS(MT_ClientHello*, ClientHello, &m_clientHello);
    ACCESSORS(MT_Random*, ClientRandom, &m_clientRandom);
    ACCESSORS(MT_Random*, ServerRandom, &m_serverRandom);
    ACCESSORS(MT_FinishedVerifyData*, ClientVerifyData, &m_clientVerifyData);
    ACCESSORS(MT_FinishedVerifyData*, ServerVerifyData, &m_serverVerifyData);

    ACCESSORS(EndpointParameters*, ReadParams, &m_readParams);
    ACCESSORS(EndpointParameters*, WriteParams, &m_writeParams);

    ACCESSORS(std::vector<std::shared_ptr<MT_Structure>>*, HandshakeMessages, &m_vHandshakeMessages);
    ACCESSORS(ByteVector*, MasterSecret, &m_vbMasterSecret);

    HRESULT CopyCommonParamsTo(ConnectionParameters* pDest);

    // TODO: is this an okay basis for determination?
    bool IsHandshakeInProgress() const { return !HandshakeMessages()->empty(); }

    HRESULT ComputeMasterSecret(const MT_PreMasterSecret* pPreMasterSecret);
    HRESULT GenerateKeyMaterial();

    HRESULT
    ComputePRF(
        const ByteVector* pvbSecret,
        PCSTR szLabel,
        const ByteVector* pvbSeed,
        size_t cbMinimumLengthDesired,
        ByteVector* pvbPRF);

    private:
    MT_CertificateList m_certChain;
    std::shared_ptr<PublicKeyCipherer> m_spPubKeyCipherer;

    MT_ClientHello m_clientHello;
    MT_Random m_clientRandom;
    MT_Random m_serverRandom;
    MT_FinishedVerifyData m_clientVerifyData;
    MT_FinishedVerifyData m_serverVerifyData;

    ByteVector m_vbMasterSecret;
    ByteVector m_vbClientWriteKey;
    ByteVector m_vbServerWriteKey;

    EndpointParameters m_readParams;
    EndpointParameters m_writeParams;

    std::vector<std::shared_ptr<MT_Structure>> m_vHandshakeMessages;
};

class MT_Securable
{
    public:
    MT_Securable();
    virtual ~MT_Securable() { }
    HRESULT CheckSecurity();

    const EndpointParameters* EndParams() const { return m_pEndParams; }
    EndpointParameters* EndParams() { return const_cast<EndpointParameters*>(static_cast<const MT_Securable*>(this)->EndParams()); }
    virtual HRESULT SetSecurityParameters(EndpointParameters* pEndParams) { m_pEndParams = pEndParams; return S_OK; }

    private:
    virtual HRESULT CheckSecurityPriv() = 0;

    EndpointParameters* m_pEndParams;
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

    size_t Length() const { return c_cbContentType_Length; }
    ACCESSORS(MTCT_Type*, Type, &m_eType);

    static bool IsValidContentType(MTCT_Type eType);

    std::wstring ToString() const;

    private:
    static const MTCT_Type c_rgeValidTypes[];
    static const ULONG c_cValidTypes;

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCT_Type m_eType;
};

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

    // TODO: dangerous
    ACCESSORS(MT_CipherFragment*, CipherFragment, m_spCipherFragment.get());

    HRESULT Encrypt();
    HRESULT Decrypt();

    HRESULT ToTLSPlaintext(MT_TLSPlaintext* pPlaintext) const;

    static
    HRESULT
    FromTLSPlaintext(
        const MT_TLSPlaintext* pPlaintext,
        EndpointParameters* pEndParams,
        std::shared_ptr<MT_TLSCiphertext>* pspCiphertext);

    HRESULT SetSecurityParameters(EndpointParameters* pEndParams);

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

    MTH_HandshakeType m_eType;
    ByteVector m_vbBody;
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

class ITLSListener
{
    public:
    virtual HRESULT OnSend(const ByteVector* pvb) = 0;
    virtual HRESULT OnApplicationData(const ByteVector* pvb) = 0;
    virtual HRESULT OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion) = 0;
    virtual HRESULT OnSelectCipherSuite(MT_CipherSuite* pCipherSuite) = 0;

    virtual
    HRESULT
    OnInitializeCrypto(
        MT_CertificateList* pCertChain,
        std::shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
        std::shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
        std::shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
        std::shared_ptr<Hasher>* pspHasher) = 0;

    virtual HRESULT OnCreatingHandshakeMessage(MT_Handshake* pHandshake, DWORD* pfFlags) = 0;

    virtual HRESULT OnEnqueuePlaintext(const MT_TLSPlaintext* pPlaintext) = 0;
    virtual HRESULT OnReceivingPlaintext(const MT_TLSPlaintext* pPlaintext) = 0;
    virtual HRESULT OnHandshakeComplete() = 0;
};

class TLSConnection
{
    public:
    typedef std::vector<std::shared_ptr<MT_RecordLayerMessage>> MessageList;


    TLSConnection(ITLSListener* pListener);
    virtual ~TLSConnection() { }

    HRESULT Initialize();

    HRESULT StartNextHandshake(const MT_ClientHello* pClientHello);
    HRESULT FinishNextHandshake();

    HRESULT HandleMessage(ByteVector* pvb);

    HRESULT EnqueueSendApplicationData(const ByteVector* pvbPayload);
    HRESULT EnqueueStartRenegotiation();

    HRESULT EnqueueMessage(std::shared_ptr<MT_TLSPlaintext> spMessage);
    HRESULT SendQueuedMessages();

    ACCESSORS(MessageList*, PendingSends, &m_pendingSends);
    ITLSListener* Listener() { return m_pListener; }

    private:
    HRESULT RespondToClientHello();

    HRESULT RespondToFinished();

    HRESULT
    AddHandshakeMessage(
        MT_Handshake* pHandshake,
        MT_ProtocolVersion::MTPV_Version version,
        MT_TLSPlaintext** ppPlaintext);

    ACCESSORS(ConnectionParameters*, CurrConn, &m_currentConnection);
    ACCESSORS(ConnectionParameters*, NextConn, &m_nextConnection);
    ConnectionParameters m_currentConnection;
    ConnectionParameters m_nextConnection;
    MessageList m_pendingSends;
    ITLSListener* m_pListener;
};

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
    typedef MT_FixedLengthByteStructure<c_cbPreMasterSecretRandom_Length> OpaqueRandom;

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

    size_t Length() const { return c_cbChangeCipherSpec_Length; }

    ACCESSORS(MTCCS_Type*, Type, &m_eType);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCCS_Type m_eType;
};

class MT_Finished : public MT_Structure, public MT_Securable
{
    public:
    MT_Finished();
    ~MT_Finished() { }

    size_t Length() const { return VerifyData()->Length(); }

    ACCESSORS(MT_FinishedVerifyData*, VerifyData, &m_verifyData);
    HRESULT ComputeVerifyData(PCSTR szLabel, ByteVector* pvbVerifyData);

    HRESULT SetConnectionParameters(const ConnectionParameters* pConnectionParams) { m_pConnectionParams = pConnectionParams; return S_OK; }

    private:
    ACCESSORS(ConnectionParameters*, ConnParams, m_pConnectionParams);

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
    HRESULT CheckSecurityPriv();

    const ConnectionParameters* m_pConnectionParams;
    MT_FinishedVerifyData m_verifyData;
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

class MT_GenericBlockCipher_TLS11 : public MT_CipherFragment
{
    public:
    MT_GenericBlockCipher_TLS11();
    ~MT_GenericBlockCipher_TLS11() { }

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

// same block structure format between 1.1 and 1.2
typedef MT_GenericBlockCipher_TLS11 MT_GenericBlockCipher_TLS12;

enum MT_AlertLevel
{
    MTAL_Warning = 1,
    MTAL_Fatal = 2,
    MTAL_Unknown = 255
};

enum MT_AlertDescription
{
    MTAD_CloseNotify = 0,
    MTAD_UnexpectedMessage = 10,
    MTAD_BadRecordMAC = 20,
    MTAD_DecryptionFailed_RESERVED = 21,
    MTAD_RecordOverflow = 22,
    MTAD_DecompressionFailure = 30,
    MTAD_HandshakeFailure = 40,
    MTAD_NoCertificate_RESERVED = 41,
    MTAD_BadCertificate = 42,
    MTAD_UnsupportedCertificate = 43,
    MTAD_CertificateRevoked = 44,
    MTAD_CertificateExpired = 45,
    MTAD_CertificateUnknown = 46,
    MTAD_IllegalParameter = 47,
    MTAD_UnknownCA = 48,
    MTAD_AccessDenied = 49,
    MTAD_DecodeError = 50,
    MTAD_DecryptError = 51,
    MTAD_ExportRestriction_RESERVED = 60,
    MTAD_ProtocolVersion = 70,
    MTAD_InsufficientSecurity = 71,
    MTAD_InternalError = 80,
    MTAD_UserCanceled = 90,
    MTAD_NoRenegotiation = 100,
    MTAD_UnsupportedExtension = 110,
    MTAD_Unknown = 255
};

class MT_Alert : public MT_Structure
{
    public:
    MT_Alert();
    ~MT_Alert() { }

    size_t Length() const
    {
        return c_cbAlertLevel_Length +
               c_cbAlertDescription_Length;
    }

    ACCESSORS(MT_AlertLevel*, Level, &m_eLevel);
    ACCESSORS(MT_AlertDescription*, Description, &m_eDescription);

    std::wstring ToString() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_AlertLevel m_eLevel;
    MT_AlertDescription m_eDescription;
};

class MT_HelloRequest : public MT_Structure
{
    public:
    MT_HelloRequest();
    ~MT_HelloRequest() { }

    size_t Length() const { return c_cbHelloRequest_Length; }

    private:
    // HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;
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

template <typename T>
HRESULT
ParseStructures(
    const ByteVector* pvb,
    std::vector<T>* pvStructures);

HRESULT
CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    MT_TLSPlaintext* pPlaintext);

HRESULT
CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    MT_TLSPlaintext* pPlaintext);

HRESULT
CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext);

HRESULT
CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext);
}
#pragma warning(pop)
