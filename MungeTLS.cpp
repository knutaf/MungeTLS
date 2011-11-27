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
        printf("successfully parsed message. CT=%d\n", message.ContentType()->Type());
    }
    else
    {
        printf("failed to parse message: %08LX\n", hr);
    }

    return hr;
} // end function ParseMessage

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
    UINT16 cbFragmentLength = 0;

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

    Fragment()->assign(pv, pv + cb);
    assert(Fragment()->size() == cbFragmentLength);

error:
    return hr;
} // end function ParseFrom

MT_ContentType::MT_ContentType()
    : m_eType(MTCT_Type_Unknown)
{
}


const MT_ContentType::MTCT_Type MT_ContentType::s_rgeValidTypes[] =
{
    MTCT_Type_ChangeCipherSpec,
    MTCT_Type_Alert,
    MTCT_Type_Handshake,
    MTCT_Type_ApplicationData,
    MTCT_Type_Unknown,
};

const DWORD MT_ContentType::s_cValidTypes = ARRAYSIZE(s_rgeValidTypes);


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
    return (find(s_rgeValidTypes, s_rgeValidTypes+s_cValidTypes, eType) != s_rgeValidTypes+s_cValidTypes);

    /* TODO: remove
    for (DWORD i = 0; i < s_cValidTypes; i++)
    {
        if (s_rgeValidTypes[i] == eType)
        {
            return true;
        }
    }

    return false;
    */
} // end function IsValidContentType

const
MT_ContentType::MTCT_Type
MT_ContentType::Type() const
{
    assert(IsValidContentType(m_eType));
    return m_eType;
}

MT_ProtocolVersion::MT_ProtocolVersion()
    : m_version(0)
{
}

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
}

const
UINT16
MT_ProtocolVersion::Version() const
{
    assert(IsKnownVersion(m_version));
    return m_version;
}

}
