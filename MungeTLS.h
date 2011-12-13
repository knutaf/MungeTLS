#pragma once
#include <windows.h>
#include <vector>

namespace MungeTLS
{

typedef unsigned long MT_UINT16;

const HRESULT MT_E_INCOMPLETE_MESSAGE                       = 0x80230001;
const HRESULT MT_E_UNKNOWN_CONTENT_TYPE                     = 0x80230002;
const HRESULT MT_E_UNKNOWN_PROTOCOL_VERSION                 = 0x80230003;
const HRESULT MT_E_UNKNOWN_HANDSHAKE_TYPE                   = 0x80230004;
const HRESULT MT_E_UNSUPPORTED_HANDSHAKE_TYPE               = 0x80230005;
const HRESULT MT_E_DATA_SIZE_OUT_OF_RANGE                   = 0x80230006;

typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;

class MT_Structure
{
    public:
    MT_Structure() { }
    virtual ~MT_Structure() { }

    HRESULT ParseFrom(const BYTE* pv, LONGLONG cb);
    HRESULT ParseFromVect(const std::vector<BYTE>* pvb);
    virtual ULONG Length() const = 0;

    private:
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb) = 0;
};

template <typename F>
class MT_VariableLengthField : public MT_Structure
{
    public:
    MT_VariableLengthField
    (
        ULONG cbLengthFieldSize,
        ULONG cMinElements,
        ULONG cMaxElements
    );

    virtual ~MT_VariableLengthField() { }

    ULONG Length() const;
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);

    const std::vector<F>* Data() const { return &m_vData; }
    std::vector<F>* Data() { return const_cast<std::vector<F>*>(static_cast<const MT_VariableLengthField*>(this)->Data()); }
    ULONG Count() const { return Data()->size(); }

    const F* at(typename std::vector<F>::size_type pos) const { return &(Data()->at(pos)); }
    F* at(typename std::vector<F>::size_type pos) { return const_cast<F*>(static_cast<const MT_VariableLengthField*>(this)->at(pos)); }

    private:
    ULONG m_cbLengthFieldSize;
    ULONG m_cMinElements;
    ULONG m_cMaxElements;
    std::vector<F> m_vData;
};

class MT_FixedLengthStructure : public MT_Structure
{
    public:
    MT_FixedLengthStructure::MT_FixedLengthStructure(ULONG cbLength);
    virtual ~MT_FixedLengthStructure() { }

    ULONG Length() const { return m_cbLength; }
    virtual HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);

    const std::vector<BYTE>* Data() const { return &m_vbData; }
    std::vector<BYTE>* Data() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_FixedLengthStructure*>(this)->Data()); }
    ULONG Count() const { return Data()->size(); }

    private:
    ULONG m_cbLength;
    std::vector<BYTE> m_vbData;
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

    const MTCT_Type Type() const;
    void SetType(MTCT_Type eType) { m_eType = eType; }

    ULONG Length() const { return 1; }

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

    MT_UINT32 GMTUnixTime() const { return m_timestamp; }

    const std::vector<BYTE>* RandomBytes() const { return &m_vbRandomBytes; }
    std::vector<BYTE>* RandomBytes() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Random*>(this)->RandomBytes()); }

    private:
    static const ULONG c_cbRandomBytes;

    MT_UINT32 m_timestamp;
    std::vector<BYTE> m_vbRandomBytes;
};

class MT_CipherSuite : public MT_FixedLengthStructure
{
    public:
    MT_CipherSuite()

          // uint8 CipherSuite[2];    /* Cryptographic suite selector */
        : MT_FixedLengthStructure(2)
    { }
};

typedef MT_VariableLengthField<MT_CipherSuite> MT_CipherSuites;

class MT_SessionID : public MT_VariableLengthField<BYTE>
{
    public:
    MT_SessionID()
        : MT_VariableLengthField(1, 0, 32)
    { }
};

class MT_TLSPlaintext : public MT_Structure
{
    public:
    MT_TLSPlaintext();
    ~MT_TLSPlaintext() {};

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);

    const MT_ContentType* ContentType() const { return &m_contentType; }
    MT_ContentType* ContentType() { return const_cast<MT_ContentType*>(static_cast<const MT_TLSPlaintext*>(this)->ContentType()); }

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_TLSPlaintext*>(this)->ProtocolVersion()); }

    MT_UINT16 PayloadLength() const { return Fragment()->size(); }

    ULONG Length() const { return m_cbLength; }
    void SetLength(ULONG len) { m_cbLength = len; }

    const std::vector<BYTE>* Fragment() const { return &m_vbFragment; }
    std::vector<BYTE>* Fragment() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_TLSPlaintext*>(this)->Fragment()); }

    private:
    MT_ContentType m_contentType;
    MT_ProtocolVersion m_protocolVersion;
    ULONG m_cbLength;
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
    MTH_HandshakeType HandshakeType() const;
    ULONG PayloadLength() const { return Body()->size(); }
    ULONG Length() const { return m_cbLength; }
    void SetLength(ULONG cb) { m_cbLength += cb; }

    const std::vector<BYTE>* Body() const { return &m_vbBody; }
    std::vector<BYTE>* Body() { return const_cast<std::vector<BYTE>*>(static_cast<const MT_Handshake*>(this)->Body()); }

    static bool IsKnownType(MTH_HandshakeType eType);
    static bool IsSupportedType(MTH_HandshakeType eType);

    private:
    static const MTH_HandshakeType c_rgeKnownTypes[];
    static const DWORD c_cKnownTypes;
    static const MTH_HandshakeType c_rgeSupportedTypes[];
    static const DWORD c_cSupportedTypes;

    MTH_HandshakeType m_eType;
    ULONG m_cbLength;
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

    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);

    ULONG Length() const { return m_cbLength; }
    void SetLength(ULONG cb) { m_cbLength += cb; }

    private:
    MT_ProtocolVersion m_protocolVersion;
    MT_Random m_random;
    MT_SessionID m_sessionID;
    MT_CipherSuites m_cipherSuites;
    ULONG m_cbLength;
};


/*
class MT_Thingy : public MT_Structure
{
    public:
    MT_Thingy();
    ~MT_Thingy() { }

    ULONG Length() const { return m_thingy.size(); }
    HRESULT ParseFromPriv(const BYTE* pv, LONGLONG cb);

    private:
    std::vector<BYTE> m_thingy;
};
*/

HRESULT
ParseMessage(
    const BYTE* pv,
    LONGLONG cb
);

HRESULT
ReadNetworkLong(
    const BYTE* pv,
    LONGLONG cb,
    ULONG cbToRead,
    ULONG* pResult
);

}
