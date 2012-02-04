#pragma once
#include <windows.h>
#include <vector>

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
const HRESULT E_INSUFFICIENT_BUFFER                         = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;

#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

extern const BYTE c_abyCert[];
extern const ULONG c_cbCert;

class MT_Structure
{
    public:
    MT_Structure() { }
    virtual ~MT_Structure() { }

    HRESULT ParseFrom(const BYTE* pv, LONGLONG cb);
    HRESULT ParseFromVect(const std::vector<BYTE>* pvb);
    HRESULT Serialize(BYTE* pv, LONGLONG cb) const;
    HRESULT SerializeToVect(std::vector<BYTE>* pvb) const;
    HRESULT SerializeAppendToVect(std::vector<BYTE>* pvb) const;
    virtual ULONG Length() const = 0;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb) { return E_NOTIMPL; }
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const { return E_NOTIMPL; }
};

template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
class MT_VariableLengthFieldBase : public MT_Structure
{
    public:
    MT_VariableLengthFieldBase();
    virtual ~MT_VariableLengthFieldBase() { }

    virtual ULONG Length() const = 0;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const = 0;

    const std::vector<F>* Data() const { return &m_vData; }
    std::vector<F>* Data() { return const_cast<std::vector<F>*>(static_cast<const MT_VariableLengthFieldBase*>(this)->Data()); }
    ULONG Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos) { return const_cast<F*>(static_cast<const MT_VariableLengthFieldBase*>(this)->at(pos)); }

    private:
    std::vector<F> m_vData;
};

template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
class MT_VariableLengthField : public MT_VariableLengthFieldBase
                                          <F,
                                           LengthFieldSize,
                                           MinSize,
                                           MaxSize>
{
    public:
    virtual ULONG Length() const;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
};

template <ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
class MT_VariableLengthByteField : public MT_VariableLengthFieldBase
                                              <BYTE,
                                               LengthFieldSize,
                                               MinSize,
                                               MaxSize>
{
    public:
    ULONG Length() const;
    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
};

template <typename F, ULONG Size>
class MT_FixedLengthStructureBase : public MT_Structure
{
    public:
    MT_FixedLengthStructureBase();
    virtual ~MT_FixedLengthStructureBase() { }

    virtual ULONG Length() const = 0;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb) = 0;
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const = 0;

    const std::vector<F>* Data() const { return &m_vData; }
    std::vector<F>* Data() { return const_cast<std::vector<F>*>(static_cast<const MT_FixedLengthStructureBase*>(this)->Data()); }
    ULONG Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos) { return const_cast<F*>(static_cast<const MT_FixedLengthStructureBase*>(this)->at(pos)); }

    private:
    std::vector<F> m_vData;
};

template <typename F, ULONG Size>
class MT_FixedLengthStructure : public MT_FixedLengthStructureBase<F, Size>
{
    public:
    virtual ULONG Length() const;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
};

template <ULONG Size>
class MT_FixedLengthByteStructure : public MT_FixedLengthStructureBase
                                               <BYTE,
                                               Size>
{
    public:
    virtual ULONG Length() const;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    virtual HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
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

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
    ULONG Length() const { return 1; }

    const MTCT_Type Type() const;
    void SetType(MTCT_Type eType) { m_eType = eType; }

    static bool IsValidContentType(MTCT_Type eType);

    private:
    MTCT_Type m_eType;

    static const MTCT_Type c_rgeValidTypes[];
    static const DWORD c_cValidTypes;
};

class MT_ProtocolVersion : public MT_Structure
{
    public:
    enum MTPV_Version
    {
        MTPV_TLS10 = 0x0301,
    };

    MT_ProtocolVersion();
    ~MT_ProtocolVersion() {};

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;

    MT_UINT16 Version() const;
    void SetVersion(MT_UINT16 ver) { m_version = ver; }

    ULONG Length() const { return 2; } // sizeof(MT_UINT16)

    static bool IsKnownVersion(MT_UINT16 version);

    private:
    MT_UINT16 m_version;
};

class MT_Random : public MT_Structure
{
    public:
    MT_Random();
    ~MT_Random() { }

    ULONG Length() const { return 4 + RandomBytes()->size(); }
    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;

    MT_UINT32 GMTUnixTime() const { return m_timestamp; }
    void SetGMTUnixTime(MT_UINT32 timestamp) { m_timestamp = timestamp; }

    const std::vector<BYTE>* RandomBytes() const { return &m_vbRandomBytes; }
    std::vector<BYTE>* RandomBytes() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Random*>(this)->RandomBytes()); }

    HRESULT PopulateNow();

    private:
    static const ULONG c_cbRandomBytes;

    MT_UINT32 m_timestamp;
    std::vector<BYTE> m_vbRandomBytes;
};

// uint8 CipherSuite[2];    /* Cryptographic suite selector */
typedef MT_FixedLengthByteStructure<2> MT_CipherSuite;

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

    ULONG Length() const { return 1; }
    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;

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

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
    ULONG Length() const;

    const MT_ContentType* ContentType() const { return &m_contentType; }
    MT_ContentType* ContentType() { return const_cast<MT_ContentType*>(static_cast<const MT_TLSPlaintext*>(this)->ContentType()); }

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_TLSPlaintext*>(this)->ProtocolVersion()); }

    MT_UINT16 PayloadLength() const { return Fragment()->size(); }

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

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
    ULONG PayloadLength() const { return Body()->size(); }
    ULONG Length() const;

    MTH_HandshakeType HandshakeType() const;
    void SetType(MTH_HandshakeType eType) { m_eType = eType; }

    const std::vector<BYTE>* Body() const { return &m_vbBody; }
    std::vector<BYTE>* Body() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Handshake*>(this)->Body()); }

    static bool IsKnownType(MTH_HandshakeType eType);
    static bool IsSupportedType(MTH_HandshakeType eType);

    private:
    static const MTH_HandshakeType c_rgeKnownTypes[];
    static const DWORD c_cKnownTypes;
    static const MTH_HandshakeType c_rgeSupportedTypes[];
    static const DWORD c_cSupportedTypes;

    // uint24 length
    ULONG LengthFieldLength() const { return 3; }

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

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    ULONG Length() const;

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

    ULONG Length() const;
    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;

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
    ~TLSConnection() { }

    HRESULT HandleMessage(
        const BYTE* pv,
        LONGLONG cb,
        std::vector<BYTE>* pvbResponse);

    private:
    HRESULT RespondTo(
        const MT_ClientHello* pClientHello,
        std::vector<MT_TLSPlaintext>* pResponses);
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

    HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;
    ULONG Length() const { return CertificateList()->Length(); }

    HRESULT PopulateFromFile(PCWSTR wszFilename);
    HRESULT PopulateFromConst(const BYTE* pvCert, LONGLONG cbCert);

    const MT_CertificateList* CertificateList() const { return &m_certificateList; }
    MT_CertificateList* CertificateList() { return const_cast<MT_CertificateList*>(static_cast<const MT_Certificate*>(this)->CertificateList()); }

    private:
    MT_CertificateList m_certificateList;
};


/*
class MT_Thingy : public MT_Structure
{
    public:
    MT_Thingy();
    ~MT_Thingy() { }

    ULONG Length() const { return m_thingy.size(); }
    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);
    // HRESULT SerializePriv(BYTE* pv, LONGLONG cb) const;

    private:
    std::vector<BYTE> m_thingy;
};
*/

HRESULT
ParseMessage(
    const BYTE* pv,
    LONGLONG cb
);

template <typename N>
HRESULT
ReadNetworkLong(
    const BYTE* pv,
    LONGLONG cb,
    ULONG cbToRead,
    N* pResult
);

HRESULT
WriteNetworkLong(
    ULONG toWrite,
    ULONG cbToWrite,
    BYTE* pv,
    LONGLONG cb
);

HRESULT
WriteRandomBytes(
    BYTE* pv,
    LONGLONG cb
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

void ResizeVector(std::vector<BYTE>* pv, std::vector<BYTE>::size_type siz);

}
#pragma warning(pop)
