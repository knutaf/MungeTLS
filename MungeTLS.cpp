#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>

#include "MungeTLS.h"

namespace MungeTLS
{

using namespace std;



/*********** TLSConnection *****************/

TLSConnection::TLSConnection()
{
} // end ctor TLSConnection

HRESULT
TLSConnection::HandleMessage(
    const BYTE* pv,
    LONGLONG cb,
    vector<BYTE>* pvbResponse
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

                        MT_TLSPlaintext response;
                        hr = RespondTo(&clientHello, &response);

                        if (hr == S_OK)
                        {
                            hr = response.SerializeToVect(pvbResponse);
                        }
                        else
                        {
                            printf("failed RespondTo: %08LX\n", hr);
                        }
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
    MT_TLSPlaintext* pMessage
)
{
    HRESULT hr = S_OK;

    MT_ProtocolVersion protocolVersion;
    MT_Random random;
    MT_SessionID sessionID;
    const MT_CipherSuite* cipherSuite;
    MT_CompressionMethod compressionMethod;
    MT_ServerHello serverHello;
    MT_Handshake handshake;
    MT_ContentType contentType;
    MT_TLSPlaintext plaintext;

    protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);

    hr = random.PopulateNow();
    if (hr != S_OK)
    {
        goto error;
    }

    assert(pClientHello->CipherSuites()->Count() > 0);
    cipherSuite = pClientHello->CipherSuites()->at(0);

    compressionMethod.SetMethod(MT_CompressionMethod::MTCM_Null);

    *(serverHello.ProtocolVersion()) = protocolVersion;
    *(serverHello.Random()) = random;
    *(serverHello.SessionID()) = sessionID;
    *(serverHello.CipherSuite()) = *cipherSuite;
    *(serverHello.CompressionMethod()) = compressionMethod;
    // not setting server extensions

    handshake.SetType(MT_Handshake::MTH_ServerHello);
    hr = serverHello.SerializeToVect(handshake.Body());
    if (hr != S_OK)
    {
        goto error;
    }

    contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

    *(plaintext.ContentType()) = contentType;
    *(plaintext.ProtocolVersion()) = protocolVersion;

    hr = handshake.SerializeToVect(plaintext.Fragment());
    if (hr != S_OK)
    {
        goto error;
    }

    *pMessage = plaintext;

error:
    return hr;
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

HRESULT
WriteNetworkLong(
    ULONG toWrite,
    ULONG cbToWrite,
    BYTE* pv,
    LONGLONG cb
)
{
    assert(pv != nullptr);
    assert(cbToWrite <= sizeof(ULONG));

    HRESULT hr = S_OK;

    if (cbToWrite > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    while (cbToWrite > 0)
    {
        pv[cbToWrite - 1] = (toWrite & 0xFF);

        toWrite >>= 8;
        cbToWrite--;
    }

error:
    return hr;
} // end function WriteNetworkLong

HRESULT
WriteRandomBytes(
    BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_FALSE;
    int r = 0;
    ULONG cbR = 0;

    while (cb > 0)
    {
        hr = S_OK;

        if (cbR == 0)
        {
            r = rand();
            cbR = sizeof(r);
        }

        pv[0] = r & 0xFF;

        pv++;
        cb--;
        cbR--;
        r >>= 8;
    }

    return hr;
} // end function WriteRandomBytes

HRESULT
EpochTimeFromSystemTime(
    const SYSTEMTIME* pST,
    ULARGE_INTEGER* pLI
)
{
    assert(pLI != nullptr);
    assert(pST != nullptr);

    HRESULT hr = S_OK;

    const SYSTEMTIME st1Jan1970 =
    {
        1970, // year
        1,    // month
        0,    // day of week
        1,    // day
        0,    // hour
        0,    // min
        0,    // sec
        0     // ms
    };

    FILETIME ft = {0};
    FILETIME ft1Jan1970 = {0};
    ULARGE_INTEGER li1Jan1970 = {0};

    if (!SystemTimeToFileTime(pST, &ft))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    pLI->LowPart = ft.dwLowDateTime;
    pLI->HighPart = ft.dwHighDateTime;

    if (!SystemTimeToFileTime(&st1Jan1970, &ft1Jan1970))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    li1Jan1970.LowPart = ft1Jan1970.dwLowDateTime;
    li1Jan1970.HighPart = ft1Jan1970.dwHighDateTime;

    hr = ULongLongSub(pLI->QuadPart, li1Jan1970.QuadPart, &pLI->QuadPart);

    if (hr != S_OK)
    {
        goto error;
    }

    // convert from 100 ns to ms
    pLI->QuadPart /= 10000000ULL;

error:
    return hr;
} // end function EpochTimeFromSystemTime

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
    BYTE* pv,
    LONGLONG cb
) const
{
    return SerializePriv(pv, cb);
} // end function Serialize

HRESULT
MT_Structure::SerializeToVect(
    vector<BYTE>* pvb
) const
{
    pvb->resize(Length());
    return Serialize(&(pvb->front()), pvb->size());
} // end function SerializeToVect


/*********** MT_VariableLengthFieldBase *****************/

template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::MT_VariableLengthFieldBase()
{
    assert(LengthFieldSize <= sizeof(ULONG));
}

/*********** MT_VariableLengthField *****************/

template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = LengthFieldSize;
    LONGLONG cbTotalElementsSize = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbTotalElementsSize);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    if (cbTotalElementsSize < MinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > MaxSize)
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


template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
ULONG
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::Length() const
{
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);

    ULONG cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        0,
        [](ULONG sofar, const F& next)
        {
            return sofar + next.Length();
        });

    return LengthFieldSize + cbTotalDataLength;
} // end function Length

template <typename F,
          ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    ULONG cbField = LengthFieldSize;

    hr = WriteNetworkLong(Data()->size(), cbField, pv, cb);
    assert(hr == S_OK);

    pv += cbField;
    cb -= cbField;

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        pv += cbField;
        cb -= cbField;
    }

error:
    return hr;
} // end function SerializePriv



/*********** MT_VariableLengthByteField *****************/

template <ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = LengthFieldSize;
    ULONG cbDataLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbDataLength);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    if (cbDataLength < MinSize)
    {
        hr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbDataLength > MaxSize)
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

template <ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
ULONG
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::Length() const
{
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);
    return LengthFieldSize + Count();
} // end function Length

template <ULONG LengthFieldSize,
          ULONG MinSize,
          ULONG MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    ULONG cbField = LengthFieldSize;

    hr = WriteNetworkLong(Data()->size(), cbField, pv, cb);
    assert(hr == S_OK);

    pv += cbField;
    cb -= cbField;

    cbField = Data()->size();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

/*********** MT_FixedLengthStructureBase *****************/

template <typename F, ULONG Size>
MT_FixedLengthStructureBase<F, Size>::MT_FixedLengthStructureBase()
    : m_vData()
{
    assert(Size > 0);
}

/*********** MT_FixedLengthStructure *****************/

template <typename F, ULONG Size>
HRESULT
MT_FixedLengthStructure<F, Size>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    LONGLONG cbTotalElementsSize = Size;

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

    assert(Length() == Size);

error:
    return hr;
} // end function ParseFromPriv

template <typename F, ULONG Size>
HRESULT
MT_FixedLengthStructure<F, Size>::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        ULONG cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        pv += cbField;
        cb -= cbField;
    }

error:
    return hr;
} // end function SerializePriv

template <typename F, ULONG Size>
ULONG
MT_FixedLengthStructure<F, Size>::Length() const
{
    ULONG cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        0,
        [](ULONG sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(Size == cbTotalDataLength);

    return cbTotalDataLength;
} // end function Length

/*********** MT_FixedLengthByteStructure *****************/

template <ULONG Size>
HRESULT
MT_FixedLengthByteStructure<Size>::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    DWORD cbField = Size;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Data()->assign(pv, pv + cbField);

error:
    return hr;
} // end function ParseFromPriv

template <ULONG Size>
HRESULT
MT_FixedLengthByteStructure<Size>::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    ULONG cbField = Data()->size();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

template <ULONG Size>
ULONG
MT_FixedLengthByteStructure<Size>::Length() const
{
    assert(Size == Data()->size());
    return Size;
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
                     2 + // sizeof MT_UINT16 payload length
                     PayloadLength();

    return cbLength;
} // end function Length

HRESULT
MT_TLSPlaintext::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = ContentType()->Length();

    hr = ContentType()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = ProtocolVersion()->Length();
    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    // uint16 length;
    cbField = 2;
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = PayloadLength();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(Fragment()->begin(), Fragment()->end(), pv);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

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

HRESULT
MT_ContentType::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;

    ULONG cbField = Length();
    hr = WriteNetworkLong(Type(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

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

HRESULT
MT_ProtocolVersion::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = Length();

    hr = WriteNetworkLong(Version(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

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
    ULONG cbField = 1;
    MTH_HandshakeType eType = MTH_Unknown;
    ULONG cbPayloadLength = 0;

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
           3 + // uint24 length
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

HRESULT
MT_Handshake::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = 1;

    hr = WriteNetworkLong(HandshakeType(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = 3;
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    std::copy(Body()->begin(), Body()->end(), pv);

error:
    return hr;
} // end function SerializePriv

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
    ULONG cbField = 4;
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

HRESULT
MT_Random::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = 4;

    hr = WriteNetworkLong(GMTUnixTime(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = RandomBytes()->size();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(RandomBytes()->begin(), RandomBytes()->end(), pv);

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

HRESULT
MT_Random::PopulateNow()
{
    HRESULT hr = S_OK;

    SYSTEMTIME st = {0};
    GetSystemTime(&st);

    ULARGE_INTEGER li = {0};
    hr = EpochTimeFromSystemTime(&st, &li);

    if (hr != S_OK)
    {
        goto error;
    }

    MT_UINT32 t = 0;
    hr = ULongLongToULong(li.QuadPart, &t);

    if (hr != S_OK)
    {
        goto error;
    }

    SetGMTUnixTime(t);

    RandomBytes()->resize(c_cbRandomBytes);
    hr = WriteRandomBytes(&RandomBytes()->front(), RandomBytes()->size());

    if (hr != S_OK)
    {
        goto error;
    }

error:
    return hr;
} // end function PopulateNow


/*********** MT_ClientHello *****************/

MT_ClientHello::MT_ClientHello()
    : m_protocolVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuites(),
      m_compressionMethods(),
      m_extensions()
{
}

HRESULT
MT_ClientHello::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    ULONG cbField = 0;

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
    ULONG cbField = 1;

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

HRESULT
MT_CompressionMethod::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = 1;

    hr = WriteNetworkLong(Method(), cbField, pv, cb);

    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

MT_UINT8
MT_CompressionMethod::Method() const
{
    assert(m_compressionMethod == MTCM_Null);
    return m_compressionMethod;
} // end function Method


/*********** MT_ServerHello *****************/

MT_ServerHello::MT_ServerHello()
    : m_protocolVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuite(),
      m_compressionMethod(),
      m_extensions()
{
} // end ctor MT_ServerHello

ULONG
MT_ServerHello::Length() const
{
    ULONG cbLength = ProtocolVersion()->Length() +
                     Random()->Length() +
                     SessionID()->Length() +
                     CipherSuite()->Length() +
                     CompressionMethod()->Length() +
                     Extensions()->Length();

    return cbLength;
} // end function Length

HRESULT
MT_ServerHello::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    HRESULT hr = S_OK;
    ULONG cbField = ProtocolVersion()->Length();

    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = Random()->Length();
    hr = Random()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = SessionID()->Length();
    hr = SessionID()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = CipherSuite()->Length();
    hr = CipherSuite()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = CompressionMethod()->Length();
    hr = CompressionMethod()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

    cbField = Extensions()->Length();
    hr = Extensions()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    pv += cbField;
    cb -= cbField;

error:
    return hr;
} // end function SerializePriv

/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : m_thingy()
{
} // end ctor MT_Thingy

HRESULT
MT_Thingy::ParseFromPriv(
    const BYTE* pv,
    LONGLONG cb
)
{
    HRESULT hr = S_OK;
    ULONG cbField = 0;

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

HRESULT
MT_Thingy::SerializePriv(
    BYTE* pv,
    LONGLONG cb
) const
{
    return E_NOTIMPL;
} // end function SerializePriv
*/

}
