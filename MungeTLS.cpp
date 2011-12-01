#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>

#include "MungeTLS.h"

namespace MungeTLS
{

using namespace std;

HRESULT
ParseMessage(
    const BYTE* pv,
    DWORD cb
)
{
    HRESULT hr = S_OK;

    MT_TLSPlaintext message;
    hr = message.ParseFrom(pv, cb);

    if (hr == S_OK)
    {
        printf("successfully parsed TLSPlaintext. CT=%d\n", message.ContentType()->Type());

        if (message.ContentType()->Type() == MT_ContentType::MTCT_Type_Handshake)
        {
            MT_Handshake handshakeMessage;
            hr = handshakeMessage.ParseFrom(&(message.Fragment()->front()), message.Fragment()->size());

            if (hr == S_OK)
            {
                printf("successfully parsed Handshake. type=%d\n", handshakeMessage.HandshakeType());
            }
            else
            {
                printf("failed to parse handshake: %08LX\n", hr);
            }
        }
    }
    else
    {
        printf("failed to parse message: %08LX\n", hr);
    }

    return hr;
} // end function ParseMessage

/*********** MT_TLSPlaintext *****************/

MT_TLSPlaintext::MT_TLSPlaintext()
    : m_contentType(),
      m_protocolVersion(),
      m_cbLength(0),
      m_vbFragment()
{
} // end ctor MT_TLSPlaintext

HRESULT
MT_TLSPlaintext::ParseFrom(
    const BYTE* pv,
    DWORD cb
)
{
    HRESULT hr = S_OK;
    DWORD cbAdvance = 0;
    ULONG cbFragmentLength = 0;

    SetLength(0);

    hr = ContentType()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbAdvance = ContentType()->Length();
    pv += cbAdvance;
    cb -= cbAdvance;
    SetLength(Length() + cbAdvance);

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbAdvance = ProtocolVersion()->Length();
    pv += cbAdvance;
    cb -= cbAdvance;
    SetLength(Length() + cbAdvance);


    cbAdvance = 2;
    if (cbAdvance > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    cbFragmentLength = pv[0] << 8 | pv[1];
    pv += cbAdvance;
    cb -= cbAdvance;
    SetLength(Length() + cbAdvance);

    if (cbFragmentLength > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Fragment()->assign(pv, pv + cbFragmentLength);

    pv += cbAdvance;
    cb -= cbAdvance;
    SetLength(Length() + cbAdvance);

error:
    return hr;
} // end function ParseFrom


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

const DWORD MT_ContentType::c_cValidTypes = ARRAYSIZE(c_rgeValidTypes);


HRESULT
MT_ContentType::ParseFrom(
    const BYTE* pv,
    DWORD cb
)
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    MTCT_Type eType = static_cast<MTCT_Type>(*pv);

    if (!IsValidContentType(eType))
    {
        hr = MT_E_UNKNOWN_CONTENT_TYPE;
        goto error;
    }

    SetType(eType);

error:
    return hr;
} // end function ParseFrom

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
MT_ProtocolVersion::ParseFrom(
    const BYTE* pv,
    DWORD cb
)
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    UINT16 version = (pv[0] << 8) | pv[1];

    if (!IsKnownVersion(version))
    {
        hr = MT_E_UNKNOWN_PROTOCOL_VERSION;
        goto error;
    }

    SetVersion(version);

error:
    return hr;
} // end function ParseFrom

bool
MT_ProtocolVersion::IsKnownVersion(
    UINT16 version
)
{
    return (version == MTPV_TLS10);
} // end function IsKnownVersion

const
UINT16
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

const DWORD MT_Handshake::c_cKnownTypes = ARRAYSIZE(c_rgeKnownTypes);

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

const DWORD MT_Handshake::c_cSupportedTypes = ARRAYSIZE(c_rgeSupportedTypes);

MT_Handshake::MT_Handshake()
    : m_cbLength(0),
      m_eType(MTH_Unknown),
      m_vbBody()
{
} // end ctor MT_Handshake

HRESULT
MT_Handshake::ParseFrom(
    const BYTE* pv,
    DWORD cb)
{
    HRESULT hr = S_OK;
    DWORD cbField = 1;
    MTH_HandshakeType eType = MTH_Unknown;
    DWORD cbPayloadLength = 0;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    eType = static_cast<MTH_HandshakeType>(*pv);

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

    pv += cbField;
    cb -= cbField;
    SetLength(Length() + cbField);

    cbField = 3;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    cbPayloadLength = (pv[0] << 16) | (pv[1] << 8) | pv[2];

    pv += cbField;
    cb -= cbField;
    SetLength(Length() + cbField);

    cbField = cbPayloadLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Body()->assign(pv, pv + cbPayloadLength);

    pv += cbField;
    cb -= cbField;
    SetLength(Length() + cbField);

error:
    return hr;
} // end function ParseFrom

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

}
