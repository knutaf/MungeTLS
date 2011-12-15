#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>

#include "MungeTLS.h"

namespace MungeTLS
{

using namespace std;



/*********** TLSConnection *****************/

TLSConnection::TLSConnection()
{
} // end ctor TLSConnection

HRESULT
TLSConnection::ParseMessage(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;

    if (cb < 0)
    {
        return E_UNEXPECTED;
    }

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

                        MT_ServerHello serverHello;
                        hr = RespondTo(&clientHello, &serverHello);

                        vector<BYTE> vbServerHello;
                        hr = serverHello.Serialize(&vbServerHello);

                        // TODO: actually send
                    }
                    else
                    {
                        printf("failed to parse client hello: %08LX\n", hr);
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
    }
    else
    {
        printf("failed to parse message: %08LX\n", hr);
    }

    return hr;
} // end function ParseMessage

HRESULT
TLSConnection::RespondTo(
    const MT_ClientHello* pClientHello,
    MT_ServerHello* pServerHello
)
{
    /*
    MT_ContentType contentType;
    contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

    MT_ProtocolVersion protocolVersion;
    protocolVersion.SetType(MT_ProtocolVersion::MTPV_TLS10);

    MT_TLSPlaintext plaintext;

    *(plaintext.ContentType()) = contentType;
    *(plaintext.ProtocolVersion()) = protocolVersion;
    */

    return S_OK;
} // end function RespondTo





template <typename N>
HRESULT
ReadNetworkLong(
    const BYTE* pv,
    LONGLONG cb,
    ULONG cbToRead,
    N* pResult
)
{
    assert(pResult != nullptr);
    assert(cbToRead <= sizeof(ULONG));

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

/*********** MT_Structure *****************/

HRESULT
MT_Structure::ParseFrom(
    const BYTE* pv,
    LONGLONG cb
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
    vector<BYTE>* pvb
) const
{
    // TODO: impl
    return S_OK;
} // end function Serialize


/*********** MT_VariableLengthField *****************/

template <typename F>
MT_VariableLengthField<F>::MT_VariableLengthField
(
    ULONG cbLengthFieldSize,
    ULONG cbMinSize,
    ULONG cbMaxSize
)
    : m_cbLengthFieldSize(cbLengthFieldSize),
      m_cbMinSize(cbMinSize),
      m_cbMaxSize(cbMaxSize),
      m_vData()
{
    assert(m_cbLengthFieldSize <= sizeof(ULONG));
}

template <>
HRESULT
MT_VariableLengthField<BYTE>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = m_cbLengthFieldSize;
    ULONG cbDataLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbDataLength);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    if (cbDataLength < m_cbMinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbDataLength > m_cbMaxSize)
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

error:
    return hr;
} // end function ParseFromPriv

template <typename F>
HRESULT
MT_VariableLengthField<F>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = m_cbLengthFieldSize;
    LONGLONG cbTotalElementsSize = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbTotalElementsSize);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    if (cbTotalElementsSize < m_cbMinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > m_cbMaxSize)
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
        pv += cbField;
        cb -= cbField;
        cbTotalElementsSize -= cbField;
    }

    assert(cbTotalElementsSize >= 0);

error:
    return hr;
} // end function ParseFromPriv

template <>
ULONG
MT_VariableLengthField<BYTE>::Length() const
{
    assert((1UL << (m_cbLengthFieldSize * 8)) - 1 >= m_cbMaxSize);
    return m_cbLengthFieldSize + Count();
} // end function Length

template <typename F>
ULONG
MT_VariableLengthField<F>::Length() const
{
    assert((1UL << (m_cbLengthFieldSize * 8)) - 1 >= m_cbMaxSize);

    ULONG cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        0,
        [](ULONG sofar, const F& next)
        {
            return sofar + next.Length();
        });

    return m_cbLengthFieldSize + cbTotalDataLength;
} // end function Length


/*********** MT_FixedLengthStructure *****************/

template <typename F>
MT_FixedLengthStructure<F>::MT_FixedLengthStructure(
    ULONG cbSize
)
    : m_cbSize(cbSize),
      m_vData()
{
    assert(m_cbSize > 0);
}

template <>
HRESULT
MT_FixedLengthStructure<BYTE>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = m_cbSize;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Data()->assign(pv, pv + cbField);

error:
    return hr;
} // end function ParseFromPriv

template <typename F>
HRESULT
MT_FixedLengthStructure<F>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    LONGLONG cbTotalElementsSize = m_cbSize;

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

        LONGLONG cbField = elem.Length();
        pv += cbField;
        cb -= cbField;
        cbTotalElementsSize -= cbField;
    }

    assert(Length() == m_cbSize);

error:
    return hr;
} // end function ParseFromPriv

template <>
ULONG
MT_FixedLengthStructure<BYTE>::Length() const
{
    assert(m_cbSize == Data()->size());
    return m_cbSize;
} // end function Length

template <typename F>
ULONG
MT_FixedLengthStructure<F>::Length() const
{
    ULONG cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        0,
        [](ULONG sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(m_cbSize == cbTotalDataLength);

    return cbTotalDataLength;
} // end function Length

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
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = 0;
    ULONG cbFragmentLength = 0;

    hr = ContentType()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ContentType()->Length();
    pv += cbField;
    cb -= cbField;

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    pv += cbField;
    cb -= cbField;


    cbField = 2;
    hr = ReadNetworkLong(pv, cb, cbField, &cbFragmentLength);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = cbFragmentLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Fragment()->assign(pv, pv + cbField);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function ParseFromPriv

ULONG
MT_TLSPlaintext::Length() const
{
    ULONG cbLength = ContentType()->Length() +
                     ProtocolVersion()->Length() +
                     PayloadLength();

    return cbLength;
} // end function Length

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
MT_ContentType::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
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
    LONGLONG cb
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
        hr = MT_E_UNKNOWN_PROTOCOL_VERSION;
        goto error;
    }

    SetVersion(version);

error:
    return hr;
} // end function ParseFromPriv

bool
MT_ProtocolVersion::IsKnownVersion(
    MT_UINT16 version
)
{
    return (version == MTPV_TLS10);
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
    : m_eType(MTH_Unknown),
      m_vbBody()
{
} // end ctor MT_Handshake

HRESULT
MT_Handshake::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
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

    pv += cbField;
    cb -= cbField;

    cbField = 3;
    hr = ReadNetworkLong(pv, cb, cbField, &cbPayloadLength);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = cbPayloadLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Body()->assign(pv, pv + cbField);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function ParseFromPriv

ULONG
MT_Handshake::Length() const
{
    return 1 + // handshake type
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

/*********** MT_Random *****************/

const ULONG MT_Random::c_cbRandomBytes = 28;

MT_Random::MT_Random()
    : m_timestamp(0),
      m_vbRandomBytes()
{
} // end ctor MT_Random

HRESULT
MT_Random::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;

    // Random.(uint32 gmt_unix_time)
    DWORD cbField = 4;
    hr = ReadNetworkLong(pv, cb, cbField, &m_timestamp);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    // Random.(opaque random_bytes[28])
    cbField = c_cbRandomBytes;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    RandomBytes()->assign(pv, pv + cbField);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function ParseFromPriv


/*********** MT_ClientHello *****************/

MT_ClientHello::MT_ClientHello()
    : m_protocolVersion(),
      m_random(),
      m_sessionID(),

      // CipherSuite cipher_suites<2..2^16-1>;
      m_cipherSuites(2, 2, (1<<(2*8)) - 1),

      // CompressionMethod compression_methods<1..2^8-1>;
      m_compressionMethods(1, 1, (1<<(1*8)) - 1),

      m_extensions(2, 0, (1<<(2*8)) - 1)
{
}

HRESULT
MT_ClientHello::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = 0;

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    pv += cbField;
    cb -= cbField;

    hr = Random()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Random()->Length();
    pv += cbField;
    cb -= cbField;

    hr = SessionID()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = SessionID()->Length();
    pv += cbField;
    cb -= cbField;

    hr = CipherSuites()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CipherSuites()->Length();
    pv += cbField;
    cb -= cbField;

    hr = CompressionMethods()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CompressionMethods()->Length();
    pv += cbField;
    cb -= cbField;

    hr = Extensions()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Extensions()->Length();
    pv += cbField;
    cb -= cbField;

error:
    return hr;
}

ULONG
MT_ClientHello::Length() const
{
    ULONG cbLength = ProtocolVersion()->Length() +
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
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = 1;

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

error:
    return hr;
} // end function ParseFromPriv

MT_UINT8
MT_CompressionMethod::Method() const
{
    assert(m_compressionMethod == MTCM_Null);
    return m_compressionMethod;
} // end function Method



/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : m_thingy()
{
}

HRESULT
MT_Thingy::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = 0;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    hr = Something()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Something()->Length();
    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function ParseFromPriv

ULONG
MT_Thingy::Length() const
{
    ULONG cbLength = Something()->Length;
    return cbLength;
} // end function Length
*/

}
