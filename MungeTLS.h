#pragma once
#include <windows.h>
#include <vector>

namespace MungeTLS
{

typedef unsigned long UINT16;

const HRESULT MT_E_INCOMPLETE_MESSAGE                       = 0x80230001;
const HRESULT MT_E_UNKNOWN_CONTENT_TYPE                     = 0x80230002;
const HRESULT MT_E_UNKNOWN_PROTOCOL_VERSION                 = 0x80230003;
const HRESULT MT_E_UNKNOWN_HANDSHAKE_TYPE                   = 0x80230004;
const HRESULT MT_E_UNSUPPORTED_HANDSHAKE_TYPE               = 0x80230005;

class MT_ContentType
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

    HRESULT ParseFrom(const BYTE* pv, DWORD cb);

    const MTCT_Type Type() const;
    void SetType(MTCT_Type eType) { m_eType = eType; }

    UINT16 Length() const { return 1; }

    static bool IsValidContentType(MTCT_Type eType);

    private:
    MTCT_Type m_eType;

    static const MTCT_Type c_rgeValidTypes[];
    static const DWORD c_cValidTypes;
};

class MT_ProtocolVersion
{
    public:
    enum MTPV_Version
    {
        MTPV_TLS10 = 0x0301,
    };

    MT_ProtocolVersion();
    ~MT_ProtocolVersion() {};

    HRESULT ParseFrom(const BYTE* pv, DWORD cb);

    const UINT16 Version() const;
    void SetVersion(UINT16 ver) { m_version = ver; }

    UINT16 Length() const { return 2; } // sizeof(UINT16)

    static bool IsKnownVersion(UINT16 version);

    private:
    UINT16 m_version;
};

class MT_TLSPlaintext
{
    public:
    MT_TLSPlaintext();
    ~MT_TLSPlaintext() {};

    HRESULT ParseFrom(const BYTE* pv, DWORD cb);

    const MT_ContentType* ContentType() const { return &m_contentType; }
    MT_ContentType* ContentType() { return const_cast<MT_ContentType*>(static_cast<const MT_TLSPlaintext*>(this)->ContentType()); }

    const MT_ProtocolVersion* ProtocolVersion() const { return &m_protocolVersion; }
    MT_ProtocolVersion* ProtocolVersion() { return const_cast<MT_ProtocolVersion*>(static_cast<const MT_TLSPlaintext*>(this)->ProtocolVersion()); }

    UINT16 PayloadLength() const { return Fragment()->size(); }

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

class MT_Handshake
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

    HRESULT ParseFrom(const BYTE* pv, DWORD cb);
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

HRESULT
ParseMessage(
    const BYTE* pv,
    DWORD cb
);

}
