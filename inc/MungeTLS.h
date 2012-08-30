#pragma once
#include <windows.h>
#include <vector>
#include <memory>
#include "mtls_defs.h"
#include "MungeCrypto.h"

/*
** implementation notes:
** - I am sacrificing a lot in terms of const-ability in favor of being
**   generous about the const-ness of crypto operations like hashing and
**   encrypting. That is, I am not restricting platform-specific crypto
**   functions to be const or not, since I can't predict it. Consequently, this
**   flows outwards through most of the code and eliminates a lot of const
**   opportunities.
*/

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

/*
** used in the ITLSListener callbacks
** handled - the app did something with the callback, or at least acknowledges
**           that it happened
** ignored - the app did not handle the callback, so MungeTLS should use
**           whatever default behavior it has
*/
const HRESULT MT_S_LISTENER_HANDLED                         = 0x00230002;
const HRESULT MT_S_LISTENER_IGNORED                         = 0x00230003;

// flags for ITLSListener::OnCreatingHandshakeMessage's pfFlags
const DWORD MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE         = 0x00000000;
const DWORD MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE          = 0x00000001;


/************************** Protocol Constants **********************/

/*
** these are all constants used in the protocol implementation. all are taken
** straight from some RFC. there are more protocol constants spread out through
** this file near the classes that reference them.
*/

// TLS 1.0: uint8 padding_length;
const size_t c_cbGenericBlockCipher_Padding_LFL = 1;

// TLS 1.0: "The master secret is always exactly 48 bytes in length."
const size_t c_cbMasterSecret_Length = 48;

// TLS 1.0: "Sequence numbers are of type uint64 and may not exceed 2^64-1."
const size_t c_cbSequenceNumber_Length = 8;

// TLS 1.0: master_secret = PRF(pre_master_secret, "master secret", ...
const PCSTR c_szMasterSecret_PRFLabel = "master secret";

/*
** TLS 1.0: key_block = PRF(
**                          SecurityParameters.master_secret,
**                          "key expansion",
**                          ...
*/
const PCSTR c_szKeyExpansion_PRFLabel = "key expansion";

/*
** TLS 1.0: "For Finished messages sent by the server, the string
** 'server finished'."
*/
const PCSTR c_szServerFinished_PRFLabel = "server finished";

/*
** TLS 1.0: "For Finished messages sent by the client, the string
** 'client finished'."
*/
const PCSTR c_szClientFinished_PRFLabel = "client finished";

/************************** End Protocol Constants **********************/

class MT_Structure;
class MT_ProtocolVersion;
class MT_Random;
class MT_SessionID;
class MT_CipherSuite;
class MT_CompressionMethod;
class MT_Extension;
class MT_RenegotiationInfoExtension;
class MT_ClientHello;
class EndpointParameters;
class ConnectionParameters;
class MT_ContentType;
class TLSConnection;
class ITLSListener;
class MT_RecordLayerMessage;
class MT_TLSPlaintext;
class MT_TLSCiphertext;
class MT_Securable;
class MT_ConnectionAware;
class MT_Handshake;
class MT_ServerHello;
class MT_Certificate;
class MT_PreMasterSecret;
class MT_ChangeCipherSpec;
class MT_Finished;
class MT_CipherFragment;
class MT_GenericStreamCipher;
class MT_GenericBlockCipher_TLS10;
class MT_GenericBlockCipher_TLS11;
class MT_Alert;
class MT_HelloRequest;

/*
** the root class of any parseable/serializable structure in the protocol. in
** fact, those are the two primary facilities this provides, plus a Length()
** function that represents the total length of that structure when serialized
*/
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
    // not making these two pure virtual just for convenience
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb)
    {
        UNREFERENCED_PARAMETER(pv);
        UNREFERENCED_PARAMETER(cb);
        assert(false);
        return E_NOTIMPL;
    }

    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const
    {
        UNREFERENCED_PARAMETER(pv);
        UNREFERENCED_PARAMETER(cb);
        assert(false);
        return E_NOTIMPL;
    }
};


/*
** implements a variable length field, which is a standard type given in the
** RFC. From the RFC:
**
** T T'<floor..ceiling>;
**
** where T is the type of the vector (which might be "byte"), and the floor and
** ceiling are given in BYTES, NOT ELEMENTS. There are asserts elsewhere to
** ensure that the templated sizes are properly in range.
*/
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

// a thin wrapper on MT_VariableLengthFieldBase
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

// specializes MT_VariableLengthFieldBase for the common byte vector
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

/*
** a fixed length array as given in the RFC, as in:
**
** T T'[n];
**
** where T is some type and n is given in BYTES, NOT ELEMENTS.
*/
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

// a thin generic wrapper on MT_FixedLengthStructureBase
template <typename F, size_t Size>
class MT_FixedLengthStructure : public MT_FixedLengthStructureBase<F, Size>
{
    public:
    virtual size_t Length() const;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;
};

// a specialization of MT_FixedLengthStructureBase for the common byte array
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

/*
** TLS 1.0:
** struct {
**     uint8 major;
**     uint8 minor;
** } ProtocolVersion;
*/
const size_t c_cbProtocolVersion_Length = 2;
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

/*
** TLS 1.0:
** struct {
**     uint32 gmt_unix_time;
**     opaque random_bytes[28];
** } Random;
*/
const size_t c_cbRandomTime_Length = 4;
const size_t c_cbRandomBytes_Length = 28;
class MT_Random : public MT_Structure
{
    public:
    typedef MT_FixedLengthByteStructure<c_cbRandomBytes_Length> MT_RandomBytes;

    MT_Random();
    ~MT_Random() { }

    size_t Length() const { return c_cbRandomTime_Length + RandomBytes()->Length(); }

    ACCESSORS(MT_UINT32*, GMTUnixTime, &m_timestamp);
    ACCESSORS(MT_RandomBytes*, RandomBytes, &m_randomBytes);

    // fills with the current timestamp, and some random numbers
    HRESULT PopulateNow();

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_UINT32 m_timestamp;
    MT_RandomBytes m_randomBytes;
};

// TLS 1.0: opaque SessionID<0..32>;
const size_t c_cbSessionID_LFL = 1;
const size_t c_cbSessionID_MinLength = 0;
const size_t c_cbSessionID_MaxLength = 32;
class MT_SessionID : public MT_VariableLengthByteField<
                                c_cbSessionID_LFL,
                                c_cbSessionID_MinLength,
                                c_cbSessionID_MaxLength>
{
    public:
    HRESULT PopulateWithRandom();
};

// TLS 1.2: taken basically verbatim.
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

/*
** TLS 1.2:
** enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
**       //  may be extended, e.g., for ECDH -- see [TLSECC]
**      } KeyExchangeAlgorithm;
*/
enum MT_KeyExchangeAlgorithm
{
    MTKEA_dhe_dss,
    MTKEA_dhe_rsa,
    MTKEA_dh_anon,
    MTKEA_rsa,
    MTKEA_dh_dss,
    MTKEA_dh_rsa
};

/*
** TLS 1.0:
** uint8 CipherSuite[2];    // Cryptographic suite selector
*/
const size_t c_cbCipherSuite_Length = 2;
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

// TLS 1.0: CipherSuite cipher_suites<2..2^16-1>;
const size_t c_cbCipherSuites_LFL = 2;
const size_t c_cbCipherSuites_MinLength = 2;
const size_t c_cbCipherSuites_MaxLength = MAXFORBYTES(c_cbCipherSuites_LFL);
typedef MT_VariableLengthField<
            MT_CipherSuite,
            c_cbCipherSuites_LFL,
            c_cbCipherSuites_MinLength,
            c_cbCipherSuites_MaxLength>
        MT_CipherSuites;

const std::vector<MT_CipherSuiteValue>* GetCipherSuitePreference();

bool IsKnownCipherSuite(MT_CipherSuiteValue eSuite);

HRESULT
ChooseBestCipherSuite(
    const std::vector<MT_CipherSuiteValue>* pveClientPreference,
    const std::vector<MT_CipherSuiteValue>* pveServerPreference,
    MT_CipherSuiteValue* pePreferredCipherSuite);

// TLS 1.0: enum { null(0), (255) } CompressionMethod;
const size_t c_cbCompressionMethod_Length = 1;
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

// TLS 1.0: CompressionMethod compression_methods<1..2^8-1>;
const size_t c_cbCompressionMethods_LFL = 1;
const size_t c_cbCompressionMethods_MinLength = 1;
const size_t c_cbCompressionMethods_MaxLength = MAXFORBYTES(c_cbCompressionMethods_LFL);
typedef MT_VariableLengthField<
            MT_CompressionMethod,
            c_cbCompressionMethods_LFL,
            c_cbCompressionMethods_MinLength,
            c_cbCompressionMethods_MaxLength>
        MT_CompressionMethods;

/*
** TLS 1.2:
** struct {
**     ExtensionType extension_type;
**     opaque extension_data<0..2^16-1>;
** } Extension;
**
** enum {
**     signature_algorithms(13), (65535)
** } ExtensionType;
**
** RFC 5746:
**   This document defines a new TLS extension, "renegotiation_info" (with
**   extension type 0xff01)...
*/
const size_t c_cbExtensionType_Length = 2;
const size_t c_cbExtensionData_LFL = 2;
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

/*
** TLS 1.2:
** select (extensions_present) {
**     case false:
**         struct {};
**     case true:
**         Extension extensions<0..2^16-1>;
** };
*/
const size_t c_cbHelloExtensions_LFL = 2;
const size_t c_cbHelloExtensions_MinLength = 0;
const size_t c_cbHelloExtensions_MaxLength = MAXFORBYTES(c_cbHelloExtensions_LFL);
typedef MT_VariableLengthField<
            MT_Extension,
            c_cbHelloExtensions_LFL,
            c_cbHelloExtensions_MinLength,
            c_cbHelloExtensions_MaxLength>
        MT_HelloExtensions;

/*
** RFC 5746:
** struct {
**     opaque renegotiated_connection<0..255>;
** } RenegotiationInfo;
**
** there is some real mess going on here with RenegotiatedConnection(), since
** we have a duplication of data. in this class, we have a
** MT_RenegotiatedConnection member that represents the renegotiation info in
** the form that the RFC specifies it. but in the superclass, we also have
** ExtensionData(), which is used to access the data when we're inserting this
** extension into its containing structure
**
** we're overriding ExtensionData() and RenegotiatedConnection() here to check
** to make sure they're not accessed when the two are out of sync, and we've
** omitted the non-const accessor for RenegotiatedConnection() in favor of a
** real setter that pushes the new value into ExtensionData, itself.
**
** this shortcoming here makes me wonder if I should have gone with all real
** getters and setters instead. may reconsider in the future.
*/
const size_t c_cbRenegotiatedConnection_LFL = 1;
const size_t c_cbRenegotiatedConnection_MinLength = 0;
const size_t c_cbRenegotiatedConnection_MaxLength = 255;
class MT_RenegotiationInfoExtension : public MT_Extension
{
    public:
    typedef MT_VariableLengthByteField<
                c_cbRenegotiatedConnection_LFL,
                c_cbRenegotiatedConnection_MinLength,
                c_cbRenegotiatedConnection_MaxLength>
            MT_RenegotiatedConnection;

    MT_RenegotiationInfoExtension();
    ~MT_RenegotiationInfoExtension() { }

    // overriding from superclass for integrity check
    const ByteVector* ExtensionData() const;

    // needed to implement by hand for integrity check
    const MT_RenegotiatedConnection* RenegotiatedConnection() const;

    // not a normal accessor, so we can push the new value into ExtensionData
    HRESULT SetRenegotiatedConnection(const MT_RenegotiatedConnection* pRenegotiatedConnection);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT CheckExtensionDataIntegrity() const;

    MT_RenegotiatedConnection m_renegotiatedConnection;
};

/*
** TLS 1.0:
** struct {
**     ProtocolVersion client_version;
**     Random random;
**     SessionID session_id;
**     CipherSuite cipher_suites<2..2^16-2>;
**     CompressionMethod compression_methods<1..2^8-1>;
**     select (extensions_present) {
**         case false:
**             struct {};
**         case true:
**             Extension extensions<0..2^16-1>;
**     };
** } ClientHello;
*/
class MT_ClientHello : public MT_Structure
{
    public:
    MT_ClientHello();
    ~MT_ClientHello() { }

    ACCESSORS(MT_ProtocolVersion*, ClientVersion, &m_clientVersion);
    ACCESSORS(MT_Random*, Random, &m_random);
    ACCESSORS(MT_SessionID*, SessionID, &m_sessionID);
    ACCESSORS(MT_CipherSuites*, CipherSuites, &m_cipherSuites);
    ACCESSORS(MT_CompressionMethods*, CompressionMethods, &m_compressionMethods);
    ACCESSORS(MT_HelloExtensions*, Extensions, &m_extensions);

    size_t Length() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);

    MT_ProtocolVersion m_clientVersion;
    MT_Random m_random;
    MT_SessionID m_sessionID;
    MT_CipherSuites m_cipherSuites;
    MT_CompressionMethods m_compressionMethods;
    MT_HelloExtensions m_extensions;
};

// TLS 1.0: opaque ASN.1Cert<1..2^24-1>;
const size_t c_cbASN1Cert_LFL = 3;
const size_t c_cbASN1Cert_MinLength = 1;
const size_t c_cbASN1Cert_MaxLength = MAXFORBYTES(c_cbASN1Cert_LFL);
typedef MT_VariableLengthByteField<
            c_cbASN1Cert_LFL,
            c_cbASN1Cert_MinLength,
            c_cbASN1Cert_MaxLength>
        MT_ASN1Cert;

// TLS 1.0: ASN.1Cert certificate_list<0..2^24-1>;
const size_t c_cbASN1Certs_LFL = 3;
const size_t c_cbASN1Certs_MinLength = 0;
const size_t c_cbASN1Certs_MaxLength = MAXFORBYTES(c_cbASN1Certs_LFL);
typedef MT_VariableLengthField<
            MT_ASN1Cert,
            c_cbASN1Certs_LFL,
            c_cbASN1Certs_MinLength,
            c_cbASN1Certs_MaxLength>
        MT_CertificateList;

/*
** TLS 1.2:
** opaque verify_data[verify_data_length];
**
** In previous versions of TLS, the verify_data was always 12 octets
** long.  In the current version of TLS, it depends on the cipher
** suite.  Any cipher suite which does not explicitly specify
** verify_data_length has a verify_data_length equal to 12.
*/
const size_t c_cbFinishedVerifyData_Length = 12;
typedef MT_FixedLengthByteStructure<c_cbFinishedVerifyData_Length> MT_FinishedVerifyData;

/*
** contains all kinds of information about the unidirectional connection
** between the client and the server. this is most usefully used to represent
** state that is in the process of being negotiated or renegotiated. it is a
** partial representation of the TLS 1.0+ SecurityParameters structure.
*/
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
    bool IsEncrypted() const;

    private:
    std::shared_ptr<Hasher> m_spHasher;
    std::shared_ptr<SymmetricCipherer> m_spSymCipherer;
    MT_ProtocolVersion::MTPV_Version m_eVersion;
    MT_CipherSuite m_cipherSuite;
    ByteVector m_vbKey;
    ByteVector m_vbMACKey;
    ByteVector m_vbIV;
    MT_UINT64 m_seqNum;
};

/*
** the state of a pair of endpoints, either fully handshaked or in the process
** of handshaking (negotiation or renegotiation). Primarily, it consists of
** an endpoint state for both the outgoing and incoming directions, plus some
** other various state
*/
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

    /*
    ** the endpoint-specific parameters can be copied easily using the
    ** accessors for ReadParams and WriteParams. This copies the rest of them.
    */
    HRESULT CopyCommonParamsTo(ConnectionParameters* pDest);

    bool IsHandshakeInProgress() const;

    HRESULT GenerateKeyMaterial(const MT_PreMasterSecret* pPreMasterSecret);

    HRESULT
    ComputePRF(
        const ByteVector* pvbSecret,
        PCSTR szLabel,
        const ByteVector* pvbSeed,
        size_t cbMinimumLengthDesired,
        ByteVector* pvbPRF);

    private:
    HRESULT ComputeMasterSecret(const MT_PreMasterSecret* pPreMasterSecret);

    MT_CertificateList m_certChain;
    std::shared_ptr<PublicKeyCipherer> m_spPubKeyCipherer;

    MT_ClientHello m_clientHello;
    MT_Random m_clientRandom;
    MT_Random m_serverRandom;
    MT_FinishedVerifyData m_clientVerifyData;
    MT_FinishedVerifyData m_serverVerifyData;

    ByteVector m_vbMasterSecret;

    EndpointParameters m_readParams;
    EndpointParameters m_writeParams;

    std::vector<std::shared_ptr<MT_Structure>> m_vHandshakeMessages;
};

/*
** TLS 1.0:
** enum {
**     change_cipher_spec(20), alert(21), handshake(22),
**     application_data(23), (255)
** } ContentType;
*/
const size_t c_cbContentType_Length = 1;
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

    std::wstring ToString() const;

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTCT_Type m_eType;
};

/*
** this is really the top-level entrypoint into MungeTLS. what a shame C++
** forces me to put it so far down in the file. a calling app creates a
** TLSConnection instance, passing in an interface for listening. it then
** calls HandleMessage whenever it receives bytes from the client. similarly,
** it has functions for sending data.
**
** TLSConnection will call back into the app on the IListener interface
** synchronously under HandleMessage, so the app needs to be reentrant that way
**
** there are functions for creating plaintext and ciphertext messages. these
** are member functions because they take input from the current connection
** state, especially as it relates to crypto parameters in use
*/
class TLSConnection
{
    public:
    typedef std::vector<std::shared_ptr<MT_RecordLayerMessage>> MessageList;


    TLSConnection(ITLSListener* pListener);
    virtual ~TLSConnection() { }

    HRESULT Initialize();

    HRESULT HandleMessage(ByteVector* pvb);

    HRESULT EnqueueSendApplicationData(const ByteVector* pvbPayload);
    HRESULT EnqueueStartRenegotiation();

    HRESULT EnqueueMessage(std::shared_ptr<MT_TLSPlaintext> spMessage);
    HRESULT SendQueuedMessages();

    ACCESSORS(MessageList*, PendingSends, &m_pendingSends);
    ITLSListener* Listener() { return m_pListener; }

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

    private:
    HRESULT InitializeConnection(ConnectionParameters* pParams);
    HRESULT StartNextHandshake(MT_ClientHello* pClientHello);
    HRESULT FinishNextHandshake();
    HRESULT HandleHandshakeMessage(const MT_Handshake* pHandshake);

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

/*
** this is the contract between the calling app and MungeTLS as to what
** callbacks it has to implement. These are all used to give the app
** visibility and input into the TLS protocol in action
*/
class ITLSListener
{
    public:
    // called when MTLS has bytes to be sent to the client
    virtual HRESULT OnSend(const ByteVector* pvb) = 0;

    // called when MTLS has received bytes from the client
    virtual HRESULT OnReceivedApplicationData(const ByteVector* pvb) = 0;

    /*
    ** called when a new handshake is starting and MTLS needs (usually
    ** platform-specific) cipherer and hasher objects from the app. the app
    ** also tells the cert chain to use
    */
    virtual
    HRESULT
    OnInitializeCrypto(
        MT_CertificateList* pCertChain,
        std::shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
        std::shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
        std::shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
        std::shared_ptr<Hasher>* pspHasher) = 0;

    /*
    ** called during the handshake when filling in ServerHello.server_version
    ** app should modify pProtocolVersion to set the version they want, or say
    ** "ignored" to use ClientHello.client_version
    */
    virtual HRESULT OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion) = 0;

    /*
    ** called during handshake to choose the cipher suite to be used in the
    ** TLS connection. the app should set pCipherSuite to indicate which
    ** to use. the ClientHello message is passed in so the app can see the
    ** available options. Of course, it can pick something out of the list for
    ** testing if it wants
    **
    ** if the app says "ignore", MTLS chooses from a built-in list
    ** (c_rgeCipherSuitePreference)
    */
    virtual HRESULT OnSelectCipherSuite(const MT_ClientHello* pClientHello, MT_CipherSuite* pCipherSuite) = 0;

    /*
    ** caller can choose flags for handshake messages. at this point the only
    ** choice is whether consecutive handshake messages should be combined into
    ** a single record layer message or separate ones
    */
    virtual HRESULT OnCreatingHandshakeMessage(MT_Handshake* pHandshake, DWORD* pfFlags) = 0;

    /*
    ** tells the app that the handshake is complete, and they can start sending
    ** application layer data. of course, they could always try to send app
    ** data messages earlier for testing purposes
    */
    virtual HRESULT OnHandshakeComplete() = 0;

    /*
    ** called when MTLS has readied a record layer message to be sent. this is
    ** called with the plaintext version of the message regardless of whether
    ** it is going to be transmitted as encrypted, generally for logging
    ** purposes
    */
    virtual HRESULT OnEnqueuePlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted) = 0;

    // same as OnEnqueuePlaintext, but for receiving a decrypted message
    virtual HRESULT OnReceivingPlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted) = 0;

    /*
    ** called when a record layer message is received with a different version
    ** than the current connection parameters know about. usually indicates a
    ** bug in the other side's TLS implementation
    */
    virtual
    HRESULT
    OnReconcileSecurityVersion(
        const MT_TLSCiphertext* pCiphertext,
        MT_ProtocolVersion::MTPV_Version connVersion,
        MT_ProtocolVersion::MTPV_Version recordVersion,
        MT_ProtocolVersion::MTPV_Version* pOverrideVersion) = 0;
};

/*
** an interface that allows a piece of data to be associated with an endpoint
** in a connection. for instance, something that's tied to the current crypto
** algorithms in use or the protocol version currently negotiated. Really, most
** of what this does is provide the EndParams member. I don't think this is
** actually used as a polymorphism tool currently (i.e. no MT_Securable* used)
*/
class MT_Securable
{
    public:
    MT_Securable();
    virtual ~MT_Securable() { }
    HRESULT CheckSecurity();

    // same idiom as ACCESSORS macro
    const EndpointParameters* EndParams() const { return m_pEndParams; }
    EndpointParameters* EndParams() { return const_cast<EndpointParameters*>(static_cast<const MT_Securable*>(this)->EndParams()); }

    virtual HRESULT SetSecurityParameters(EndpointParameters* pEndParams) { m_pEndParams = pEndParams; return S_OK; }

    private:
    // check the security aspects of this structure, e.g. MAC or something
    virtual HRESULT CheckSecurityPriv() = 0;

    EndpointParameters* m_pEndParams;
};

/*
** like MT_Securable, this is basically a class to provide access to a Conn()
** member, for structures that are attached to a whole connection
*/
class MT_ConnectionAware
{
    public:
    MT_ConnectionAware() : m_pConnection(nullptr) { }
    virtual ~MT_ConnectionAware() { }

    const TLSConnection* const* Conn() const { return &m_pConnection; }
    TLSConnection** Conn() { return const_cast<TLSConnection**>(static_cast<const MT_ConnectionAware*>(this)->Conn()); }

    private:
    TLSConnection* m_pConnection;
};

/*
** represents a record layer message, either TLSCompresssed/TLSPlaintext or
** TLSCiphertext, all of which have a few common members. usually this is only
** used when we have messages that are inbound or outbound, and we don't care
** about what type they are--they just need to be sent.
*/
const size_t c_cbRecordLayerMessage_Fragment_LFL = 2;
class MT_RecordLayerMessage : public MT_Structure, public MT_ConnectionAware
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

// nothing special going on with plaintext beyond being a record layer message
class MT_TLSPlaintext : public MT_RecordLayerMessage
{
};

/*
** a plaintext message that knows how to encrypt and decrypt itself with the
** current endpoint parameters. the cipher fragment keeps track of both the
** encrypted and plaintext data
**
** interestingly, SetSecurityParameters and UpdateFragmentSecurity are the
** two crucial functions here that lead to decryping and encrypting,
** respectively
*/
class MT_TLSCiphertext : public MT_RecordLayerMessage, public MT_Securable
{
    public:
    MT_TLSCiphertext();
    ~MT_TLSCiphertext() {};

    ACCESSORS(MT_CipherFragment*, CipherFragment, m_spCipherFragment.get());

    HRESULT ToTLSPlaintext(MT_TLSPlaintext* pPlaintext);

    static
    HRESULT
    FromTLSPlaintext(
        MT_TLSPlaintext* pPlaintext,
        EndpointParameters* pEndParams,
        std::shared_ptr<MT_TLSCiphertext>* pspCiphertext);

    HRESULT SetSecurityParameters(EndpointParameters* pEndParams);
    HRESULT Encrypt();
    HRESULT Decrypt();

    HRESULT UpdateFragmentSecurity();

    HRESULT GetProtocolVersionForSecurity(MT_ProtocolVersion* pVersion);

    HRESULT GenerateNextIV(ByteVector* pvbIV);

    private:
    HRESULT CheckSecurityPriv();

    std::shared_ptr<MT_CipherFragment> m_spCipherFragment;
};

/*
** TLS 1.0:
** struct {
**     HandshakeType msg_type;    // handshake type
**     uint24 length;             // bytes in message
**     select (HandshakeType) {
**         case hello_request:       HelloRequest;
**         case client_hello:        ClientHello;
**         case server_hello:        ServerHello;
**         case certificate:         Certificate;
**         case server_key_exchange: ServerKeyExchange;
**         case certificate_request: CertificateRequest;
**         case server_hello_done:   ServerHelloDone;
**         case certificate_verify:  CertificateVerify;
**         case client_key_exchange: ClientKeyExchange;
**         case finished:            Finished;
**     } body;
** } Handshake;
**
** a container message, kind of like a record layer message, in which many
** different types of handshake data are passed
*/
const size_t c_cbHandshakeType_Length = 1;
const size_t c_cbHandshake_LFL = 3;
class MT_Handshake : public MT_Structure
{
    public:

    /*
    ** TLS 1.0
    ** enum {
    **     hello_request(0), client_hello(1), server_hello(2),
    **     certificate(11), server_key_exchange (12),
    **     certificate_request(13), server_hello_done(14),
    **     certificate_verify(15), client_key_exchange(16),
    **     finished(20), (255)
    ** } HandshakeType;
    */
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
    static const MTH_HandshakeType c_rgeSupportedTypes[];

    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MTH_HandshakeType m_eType;
    ByteVector m_vbBody;
};

/*
** TLS 1.2:
** struct {
**     ProtocolVersion server_version;
**     Random random;
**     SessionID session_id;
**     CipherSuite cipher_suite;
**     CompressionMethod compression_method;
**     select (extensions_present) {
**         case false:
**             struct {};
**         case true:
**             Extension extensions<0..2^16-1>;
**     };
** } ServerHello;
**
** This responds to the client hello and chooses single parameters for cipher
** suite, etc.. based on the available choices from the client.
*/
class MT_ServerHello : public MT_Structure
{
    public:
    MT_ServerHello();
    ~MT_ServerHello() { }

    size_t Length() const;

    ACCESSORS(MT_ProtocolVersion*, ServerVersion, &m_serverVersion);
    ACCESSORS(MT_Random*, Random, &m_random);
    ACCESSORS(MT_SessionID*, SessionID, &m_sessionID);
    ACCESSORS(MT_CipherSuite*, CipherSuite, &m_cipherSuite);
    ACCESSORS(MT_CompressionMethod*, CompressionMethod, &m_compressionMethod);
    ACCESSORS(MT_HelloExtensions*, Extensions, &m_extensions);

    private:
    HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    MT_ProtocolVersion m_serverVersion;
    MT_Random m_random;
    MT_SessionID m_sessionID;
    MT_CipherSuite m_cipherSuite;
    MT_CompressionMethod m_compressionMethod;
    MT_HelloExtensions m_extensions;
};

/*
** TLS 1.0:
** struct {
**     ASN.1Cert certificate_list<0..2^24-1>;
** } Certificate;
*/
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

/*
** TLS 1.0
** struct {
**     select (KeyExchangeAlgorithm) {
**         case rsa: EncryptedPreMasterSecret;
**         case diffie_hellman: DiffieHellmanClientPublicValue;
**     } exchange_keys;
** } ClientKeyExchange;
**
** Currently we only support RSA
*/
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

/*
** TLS 1.0:
** A public-key-encrypted element is encoded as an opaque vector <0..2^16-1>...
**
** this contains both the raw and encrypted bytes of the structure, and is only
** used for decrypting, not encrypting currently.
*/
const size_t c_cbPublicKeyEncrypted_LFL = 2;
template <typename T>
class MT_PublicKeyEncryptedStructure : public MT_Structure
{
    public:
    MT_PublicKeyEncryptedStructure();
    virtual ~MT_PublicKeyEncryptedStructure() { }

    virtual size_t Length() const;

    HRESULT DecryptStructure(PublicKeyCipherer* pCipherer);

    ACCESSORS(T*, Structure, &m_structure);
    ACCESSORS(ByteVector*, EncryptedStructure, &m_vbEncryptedStructure);

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    ACCESSORS(ByteVector*, PlaintextStructure, &m_vbPlaintextStructure);

    T m_structure;
    ByteVector m_vbPlaintextStructure;
    ByteVector m_vbEncryptedStructure;
};

/*
** TLS 1.0:
** struct {
**     ProtocolVersion client_version;
**     opaque random[46];
** } PreMasterSecret;
*/
const size_t c_cbPreMasterSecretRandom_Length = 46;
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

/*
** TLS 1.0
** struct {
**     public-key-encrypted PreMasterSecret pre_master_secret;
** } EncryptedPreMasterSecret;
*/
typedef MT_PublicKeyEncryptedStructure<MT_PreMasterSecret> MT_EncryptedPreMasterSecret;

/*
** TLS 1.0
** struct {
**     enum { change_cipher_spec(1), (255) } type;
** } ChangeCipherSpec;
*/
const size_t c_cbChangeCipherSpec_Length = 1;
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

/*
** TLS 1.0
** struct {
**     opaque verify_data[12];
** } Finished;
*/
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

/*
** TLS 1.2
** select (SecurityParameters.cipher_type) {
**     case stream: GenericStreamCipher;
**     case block:  GenericBlockCipher;
**     case aead:   GenericAEADCipher;
** } fragment;
**
** this is mostly a base class for any of the cipher fragment types, which all
** know how to encrypt, decrypt, and verify themselves in their own way
*/
class MT_CipherFragment : public MT_Structure, public MT_Securable
{
    public:
    MT_CipherFragment(MT_TLSCiphertext* pCiphertext);
    virtual ~MT_CipherFragment() { }

    virtual size_t Length() const;

    virtual HRESULT UpdateWriteSecurity() = 0;

    ACCESSORS(ByteVector*, Content, &m_vbContent);
    ACCESSORS(ByteVector*, RawContent, &m_vbRawContent);

    protected:
    MT_TLSCiphertext* Ciphertext() { return m_pCiphertext; }
    virtual HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    virtual HRESULT SerializePriv(BYTE* pv, size_t cb) const;

    private:
    ByteVector m_vbContent;
    ByteVector m_vbRawContent;
    MT_TLSCiphertext* m_pCiphertext;
};

/*
** TLS 1.0
** stream-ciphered struct {
**     opaque content[TLSCompressed.length];
**     opaque MAC[SecurityParameters.mac_length];
** } GenericStreamCipher;
*/
class MT_GenericStreamCipher : public MT_CipherFragment
{
    public:
    MT_GenericStreamCipher(MT_TLSCiphertext* pCiphertext);
    ~MT_GenericStreamCipher() { }

    HRESULT UpdateWriteSecurity();

    ACCESSORS(ByteVector*, MAC, &m_vbMAC);

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT CheckSecurityPriv();

    HRESULT
    ComputeSecurityInfo(
        MT_UINT64 sequenceNumber,
        const ByteVector* pvbMACKey,
        const MT_ContentType* pContentType,
        const MT_ProtocolVersion* pProtocolVersion,
        ByteVector* pvbMAC);

    ByteVector m_vbMAC;
};

/*
** TLS 1.0
** block-ciphered struct {
**     opaque content[TLSCompressed.length];
**     opaque MAC[CipherSpec.hash_size];
**     uint8 padding[GenericBlockCipher.padding_length];
**     uint8 padding_length;
** } GenericBlockCipher;
*/
class MT_GenericBlockCipher_TLS10 : public MT_CipherFragment
{
    public:
    MT_GenericBlockCipher_TLS10(MT_TLSCiphertext* pCiphertext);
    ~MT_GenericBlockCipher_TLS10() { }

    ACCESSORS(ByteVector*, MAC, &m_vbMAC);
    ACCESSORS(ByteVector*, Padding, &m_vbPadding);
    MT_UINT8 PaddingLength() const;

    HRESULT UpdateWriteSecurity();

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT CheckSecurityPriv();

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

/*
** TLS 1.1
** block-ciphered struct {
**     opaque IV[CipherSpec.block_length];
**     opaque content[TLSCompressed.length];
**     opaque MAC[CipherSpec.hash_size];
**     uint8 padding[GenericBlockCipher.padding_length];
**     uint8 padding_length;
** } GenericBlockCipher;
**
** Note the significant deviation from TLS 1.0 block cipher structure: the
** inclusion of the IV field tells the initialization vector that will be used
** for encrypting or decrypting the next cipher fragment sent or received.
*/
class MT_GenericBlockCipher_TLS11 : public MT_CipherFragment
{
    public:
    MT_GenericBlockCipher_TLS11(MT_TLSCiphertext* pCiphertext);
    ~MT_GenericBlockCipher_TLS11() { }

    ACCESSORS(ByteVector*, IV, &m_vbIVNext);
    ACCESSORS(ByteVector*, MAC, &m_vbMAC);
    ACCESSORS(ByteVector*, Padding, &m_vbPadding);
    MT_UINT8 PaddingLength() const;

    HRESULT UpdateWriteSecurity();

    private:
    HRESULT ParseFromPriv(const BYTE* pv, size_t cb);
    HRESULT CheckSecurityPriv();

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
** TLS 1.2 - A BIT WRONG
** struct {
**     opaque IV[SecurityParameters.record_iv_length];
**     block-ciphered struct {
**         opaque content[TLSCompressed.length];
**         opaque MAC[SecurityParameters.mac_length];
**         uint8 padding[GenericBlockCipher.padding_length];
**         uint8 padding_length;
**     };
** } GenericBlockCipher;
**
** this is NOT the block cipher format we use for our implementation. The RFC
** appears to have a bug in that IV is not within the block ciphered portion.
** instead, we use the TLS 1.1 format, where the block cipher is included in
** the encrypted part. this works in practice, whereas the one in the RFC does
** not.
*/
typedef MT_GenericBlockCipher_TLS11 MT_GenericBlockCipher_TLS12;

/*
** TLS 1.0
** enum { warning(1), fatal(2), (255) } AlertLevel;
*/
const size_t c_cbAlertLevel_Length = 1;
enum MT_AlertLevel
{
    MTAL_Warning = 1,
    MTAL_Fatal = 2,
    MTAL_Unknown = 255
};

/*
** TLS 1.2
** enum {
**     close_notify(0),
**     unexpected_message(10),
**     bad_record_mac(20),
**     decryption_failed_RESERVED(21),
**     record_overflow(22),
**     decompression_failure(30),
**     handshake_failure(40),
**     no_certificate_RESERVED(41),
**     bad_certificate(42),
**     unsupported_certificate(43),
**     certificate_revoked(44),
**     certificate_expired(45),
**     certificate_unknown(46),
**     illegal_parameter(47),
**     unknown_ca(48),
**     access_denied(49),
**     decode_error(50),
**     decrypt_error(51),
**     export_restriction_RESERVED(60),
**     protocol_version(70),
**     insufficient_security(71),
**     internal_error(80),
**     user_canceled(90),
**     no_renegotiation(100),
**     unsupported_extension(110),
**     (255)
** } AlertDescription;
*/
const size_t c_cbAlertDescription_Length = 1;
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

/*
** TLS 1.0
** struct {
**     AlertLevel level;
**     AlertDescription description;
** } Alert;
*/
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

/*
** TLS 1.0
** struct { } HelloRequest;
*/
const size_t c_cbHelloRequest_Length = 0;
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

/* boilerplate for defining new structures
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

// attempt to parse many of the same type from a block of data
template <typename T>
HRESULT
ParseStructures(
    const ByteVector* pvb,
    std::vector<T>* pvStructures);

template <typename T>
void ResizeVector(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

// specialized for byte vector
template <>
void ResizeVector(ByteVector* pv, typename ByteVector::size_type siz);

HRESULT
CryptoInfoFromCipherSuite(
    const MT_CipherSuite* pCipherSuite,
    CipherInfo* pCipherInfo,
    HashInfo* pHashInfo);

}
