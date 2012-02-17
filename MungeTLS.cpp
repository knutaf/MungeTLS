#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>

#include "MungeTLS.h"

#define SAFE_SUB(h, l, r)              \
{                                      \
    (h) = SizeTSub((l), (r), &(l));    \
    if ((h) != S_OK) { goto error; }   \
}                                      \

#define ADVANCE_PARSE()                \
{                                      \
    pv += cbField;                     \
    SAFE_SUB(hr, cb, cbField);         \
}                                      \

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
    size_t cb,
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

                        vector<MT_TLSPlaintext> responseMessages;
                        hr = RespondTo(&clientHello, &responseMessages);

                        if (hr == S_OK)
                        {
                            printf("got %u messages to respond with\n", responseMessages.size());
                            hr = SerializeMessagesToVector(&responseMessages, pvbResponse);
                            //hr = responseMessages[0].SerializeToVect(pvbResponse);
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
    vector<MT_TLSPlaintext>* pResponses
)
{
    HRESULT hr = S_OK;
    UNREFERENCED_PARAMETER(pClientHello);

    // Server Hello
    {
        MT_ProtocolVersion protocolVersion;
        MT_Random random;
        MT_SessionID sessionID;
        MT_CipherSuite cipherSuite;
        MT_CompressionMethod compressionMethod;
        MT_HelloExtensions extensions;
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

        hr = sessionID.PopulateWithRandom();
        if (hr != S_OK)
        {
            goto error;
        }

        // rsa + sha256 cbc
        *(cipherSuite.at(0)) = 0x00;
        *(cipherSuite.at(1)) = 0x35;

        compressionMethod.SetMethod(MT_CompressionMethod::MTCM_Null);

        /* renegotation info
        *(extensions.at(0)) = 0xff;
        *(extensions.at(1)) = 0x01;
        *(extensions.at(2)) = 0x00;
        *(extensions.at(3)) = 0x01;
        *(extensions.at(4)) = 0x00;
        */

        *(serverHello.ProtocolVersion()) = protocolVersion;
        *(serverHello.Random()) = random;
        *(serverHello.SessionID()) = sessionID;
        *(serverHello.CipherSuite()) = cipherSuite;
        *(serverHello.CompressionMethod()) = compressionMethod;
        *(serverHello.Extensions()) = extensions;

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

        pResponses->push_back(plaintext);
    }

    assert(hr == S_OK);

    // Certificate
    {
        MT_Certificate certificate;
        MT_Handshake handshake;
        MT_ContentType contentType;
        MT_TLSPlaintext plaintext;
        MT_ProtocolVersion protocolVersion;

        hr = certificate.PopulateFromMemory(c_abyCert, c_cbCert);
        if (hr != S_OK)
        {
            goto error;
        }

        handshake.SetType(MT_Handshake::MTH_Certificate);
        hr = certificate.SerializeToVect(handshake.Body());

        protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);
        contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

        *(plaintext.ContentType()) = contentType;
        *(plaintext.ProtocolVersion()) = protocolVersion;

        hr = handshake.SerializeToVect(plaintext.Fragment());
        if (hr != S_OK)
        {
            goto error;
        }

        pResponses->push_back(plaintext);
    }

    assert(hr == S_OK);

    // Server Hello Done
    {
        MT_Handshake handshake;
        MT_ContentType contentType;
        MT_TLSPlaintext plaintext;
        MT_ProtocolVersion protocolVersion;

        protocolVersion.SetVersion(MT_ProtocolVersion::MTPV_TLS10);
        handshake.SetType(MT_Handshake::MTH_ServerHelloDone);
        contentType.SetType(MT_ContentType::MTCT_Type_Handshake);

        *(plaintext.ContentType()) = contentType;
        *(plaintext.ProtocolVersion()) = protocolVersion;

        hr = handshake.SerializeToVect(plaintext.Fragment());
        if (hr != S_OK)
        {
            goto error;
        }

        pResponses->push_back(plaintext);
    }

error:
    return hr;
} // end function RespondTo





template <typename N>
HRESULT
ReadNetworkLong(
    const BYTE* pv,
    size_t cb,
    size_t cbToRead,
    N* pResult
)
{
    assert(pResult != nullptr);
    assert(cbToRead <= sizeof(size_t));

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

template <typename I>
HRESULT
WriteNetworkLong(
    I toWrite,
    size_t cbToWrite,
    BYTE* pv,
    size_t cb
)
{
    assert(pv != nullptr);
    assert(cbToWrite <= sizeof(I));

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
    size_t cb
)
{
    HRESULT hr = S_FALSE;
    int r = 0;
    size_t cbR = 0;

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

template <typename T>
HRESULT
SerializeMessagesToVector(
    const std::vector<T>* pvMessages,
    std::vector<BYTE>* pvb
)
{
    HRESULT hr = S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(pvMessages->begin(), pvMessages->end(),
        [&hr, &cbTotal, pvb](const T& pStructure)
        {
            if (hr == S_OK)
            {
                cbTotal += pStructure.Length();
                hr = pStructure.SerializeAppendToVect(pvb);
            }
        }
    );

    if (hr == S_OK)
    {
        assert(cbTotal == pvb->size());
    }

    return hr;
} // end function SerializeMessagesToVector

template <typename T>
void
ResizeVector<T>(
    std::vector<T>* pv,
    typename std::vector<T>::size_type siz
)
{
    pv->resize(siz);
} // end function ResizeVector<T>

template <>
void
ResizeVector<BYTE>(
    std::vector<BYTE>* pv,
    typename std::vector<BYTE>::size_type siz
)
{
    pv->resize(siz, 0x23);
} // end function ResizeVector<BYTE>

template <typename T>
void
EnsureVectorSize<T>(
    std::vector<T>* pVect,
    typename std::vector<T>::size_type siz
)
{
    if (siz > pVect->size())
    {
        pVect->resize(siz);
    }
} // end function EnsureVectorSize

/*********** MT_Structure *****************/

HRESULT
MT_Structure::ParseFrom(
    const BYTE* pv,
    size_t cb
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
    size_t cb
) const
{
    return SerializePriv(pv, cb);
} // end function Serialize

HRESULT
MT_Structure::SerializeToVect(
    vector<BYTE>* pvb
) const
{
    pvb->clear();
    return SerializeAppendToVect(pvb);
} // end function SerializeToVect

HRESULT
MT_Structure::SerializeAppendToVect(
    vector<BYTE>* pvb
) const
{
    size_t cSize = pvb->size();
    ResizeVector(pvb, cSize + Length());

    vector<BYTE>::iterator end = pvb->begin() + cSize;

    assert(pvb->end() - (end + Length()) >= 0);
    return Serialize(&(*end), Length());
} // end function SerializeAppendToVect


/*********** MT_VariableLengthFieldBase *****************/

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::MT_VariableLengthFieldBase()
{
    assert(LengthFieldSize <= sizeof(size_t));
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);
}

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::Length() const
{
    return LengthFieldSize + DataLength();
} // end function Length

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
F*
MT_VariableLengthFieldBase
<F, LengthFieldSize, MinSize, MaxSize>
::at(
    typename std::vector<F>::size_type pos
)
{
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
}

/*********** MT_VariableLengthField *****************/

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbTotalElementsSize = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbTotalElementsSize);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

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
        ADVANCE_PARSE();
        SAFE_SUB(hr, cbTotalElementsSize, cbField);
    }

error:
    return hr;
} // end function ParseFromPriv


template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::DataLength() const
{
    assert((1UL << (LengthFieldSize * 8)) - 1 >= MaxSize);

    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(cbTotalDataLength <= MaxSize);
    assert(cbTotalDataLength >= MinSize);

    return cbTotalDataLength;
} // end function DataLength

template <typename F,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthField
<F, LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = LengthFieldSize;

    hr = WriteNetworkLong(DataLength(), cbField, pv, cb);
    assert(hr == S_OK);

    ADVANCE_PARSE();

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        ADVANCE_PARSE();
    }

error:
    return hr;
} // end function SerializePriv



/*********** MT_VariableLengthByteField *****************/

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbDataLength = 0;

    hr = ReadNetworkLong(pv, cb, cbField, &cbDataLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

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

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::DataLength() const
{
    size_t cbTotalDataLength = Count();
    assert(cbTotalDataLength <= MaxSize);
    assert(cbTotalDataLength >= MinSize);

    return cbTotalDataLength;
} // end function DataLength

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
HRESULT
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = LengthFieldSize;

    hr = WriteNetworkLong(DataLength(), cbField, pv, cb);
    assert(hr == S_OK);

    ADVANCE_PARSE();

    cbField = DataLength();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

/*********** MT_FixedLengthStructureBase *****************/

template <typename F, size_t Size>
MT_FixedLengthStructureBase<F, Size>::MT_FixedLengthStructureBase()
    : m_vData()
{
    assert(Size > 0);
}

template <typename F,
          size_t Size>
F*
MT_FixedLengthStructureBase<F, Size>::at(
    typename std::vector<F>::size_type pos
)
{
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
}

/*********** MT_FixedLengthStructure *****************/

template <typename F, size_t Size>
HRESULT
MT_FixedLengthStructure<F, Size>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbTotalElementsSize = Size;

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

        size_t cbField = elem.Length();
        ADVANCE_PARSE();
        SAFE_SUB(hr, cbTotalElementsSize, cbField);
    }

    assert(Length() == Size);

error:
    return hr;
} // end function ParseFromPriv

template <typename F, size_t Size>
HRESULT
MT_FixedLengthStructure<F, Size>::SerializePriv(
    BYTE* pv,
    size_t cb
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
        size_t cbField = iter->Length();

        hr = iter->Serialize(pv, cb);
        assert(hr == S_OK);

        ADVANCE_PARSE();
    }

error:
    return hr;
} // end function SerializePriv

template <typename F, size_t Size>
size_t
MT_FixedLengthStructure<F, Size>::Length() const
{
    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const F& next)
        {
            return sofar + next.Length();
        });

    assert(Size == cbTotalDataLength);

    return cbTotalDataLength;
} // end function Length

/*********** MT_FixedLengthByteStructure *****************/

template <size_t Size>
HRESULT
MT_FixedLengthByteStructure<Size>::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = Size;

    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Data()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

template <size_t Size>
HRESULT
MT_FixedLengthByteStructure<Size>::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    if (Length() > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    size_t cbField = Data()->size();

    assert(cbField <= cb);
    std::copy(Data()->begin(), Data()->end(), pv);

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

template <size_t Size>
size_t
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
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;
    size_t cbFragmentLength = 0;

    hr = ContentType()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ContentType()->Length();
    ADVANCE_PARSE();

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    ADVANCE_PARSE();


    cbField = 2;
    hr = ReadNetworkLong(pv, cb, cbField, &cbFragmentLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbFragmentLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Fragment()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

MT_UINT16
MT_TLSPlaintext::PayloadLength() const
{
    size_t cbLength = Fragment()->size();
    assert(cbLength <= UINT16_MAX);
    return static_cast<MT_UINT16>(cbLength);
} // end function PayloadLength

size_t
MT_TLSPlaintext::Length() const
{
    size_t cbLength = ContentType()->Length() +
                      ProtocolVersion()->Length() +
                      2 + // sizeof MT_UINT16 payload length
                      PayloadLength();

    return cbLength;
} // end function Length

HRESULT
MT_TLSPlaintext::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = ContentType()->Length();

    hr = ContentType()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = ProtocolVersion()->Length();
    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    // uint16 length;
    cbField = 2;
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = PayloadLength();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(Fragment()->begin(), Fragment()->end(), pv);

    ADVANCE_PARSE();

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

const ULONG MT_ContentType::c_cValidTypes = ARRAYSIZE(c_rgeValidTypes);


HRESULT
MT_ContentType::ParseFromPriv(
    const BYTE* pv,
    size_t cb
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
    size_t cb
) const
{
    HRESULT hr = S_OK;

    size_t cbField = Length();
    hr = WriteNetworkLong(static_cast<ULONG>(Type()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

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
    size_t cb
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
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = Length();

    hr = WriteNetworkLong(static_cast<ULONG>(Version()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

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

const ULONG MT_Handshake::c_cKnownTypes = ARRAYSIZE(c_rgeKnownTypes);

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

const ULONG MT_Handshake::c_cSupportedTypes = ARRAYSIZE(c_rgeSupportedTypes);

MT_Handshake::MT_Handshake()
    : m_eType(MTH_Unknown),
      m_vbBody()
{
} // end ctor MT_Handshake

HRESULT
MT_Handshake::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 1;
    MTH_HandshakeType eType = MTH_Unknown;
    size_t cbPayloadLength = 0;

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

    ADVANCE_PARSE();

    cbField = LengthFieldLength();
    hr = ReadNetworkLong(pv, cb, cbField, &cbPayloadLength);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = cbPayloadLength;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    Body()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

size_t
MT_Handshake::Length() const
{
    return 1 + // handshake type
           LengthFieldLength() +
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
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

    hr = WriteNetworkLong(static_cast<ULONG>(HandshakeType()), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = LengthFieldLength();
    hr = WriteNetworkLong(PayloadLength(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = PayloadLength();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(Body()->begin(), Body()->end(), pv);

    ADVANCE_PARSE();

error:
    return hr;
} // end function SerializePriv

/*********** MT_Random *****************/

const size_t MT_Random::c_cbRandomBytes = 28;

MT_Random::MT_Random()
    : m_timestamp(0),
      m_vbRandomBytes()
{
} // end ctor MT_Random

HRESULT
MT_Random::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;

    // Random.(uint32 gmt_unix_time)
    size_t cbField = 4;
    hr = ReadNetworkLong(pv, cb, cbField, &m_timestamp);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    // Random.(opaque random_bytes[28])
    cbField = c_cbRandomBytes;
    if (cbField > cb)
    {
        hr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    RandomBytes()->assign(pv, pv + cbField);

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_Random::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 4;

    hr = WriteNetworkLong(GMTUnixTime(), cbField, pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = RandomBytes()->size();
    if (cbField > cb)
    {
        hr = E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(RandomBytes()->begin(), RandomBytes()->end(), pv);

    ADVANCE_PARSE();

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

    ResizeVector(RandomBytes(), c_cbRandomBytes);
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
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

    hr = ProtocolVersion()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = ProtocolVersion()->Length();
    ADVANCE_PARSE();

    hr = Random()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Random()->Length();
    ADVANCE_PARSE();

    hr = SessionID()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = SessionID()->Length();
    ADVANCE_PARSE();

    hr = CipherSuites()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CipherSuites()->Length();
    ADVANCE_PARSE();

    hr = CompressionMethods()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = CompressionMethods()->Length();
    ADVANCE_PARSE();

    hr = Extensions()->ParseFrom(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    cbField = Extensions()->Length();
    ADVANCE_PARSE();

error:
    return hr;
}

size_t
MT_ClientHello::Length() const
{
    size_t cbLength = ProtocolVersion()->Length() +
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
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

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

    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

HRESULT
MT_CompressionMethod::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = 1;

    hr = WriteNetworkLong(static_cast<ULONG>(Method()), cbField, pv, cb);

    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

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

size_t
MT_ServerHello::Length() const
{
    size_t cbLength = ProtocolVersion()->Length() +
                      Random()->Length() +
                      SessionID()->Length() +
                      CipherSuite()->Length() +
                      CompressionMethod()->Length();

    if (Extensions()->Count() > 0)
    {
        cbLength += Extensions()->Length();
    }

    return cbLength;
} // end function Length

HRESULT
MT_ServerHello::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;
    size_t cbField = ProtocolVersion()->Length();

    hr = ProtocolVersion()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = Random()->Length();
    hr = Random()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = SessionID()->Length();
    hr = SessionID()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = CipherSuite()->Length();
    hr = CipherSuite()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    cbField = CompressionMethod()->Length();
    hr = CompressionMethod()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

    ADVANCE_PARSE();

    if (Extensions()->Count() > 0)
    {
        cbField = Extensions()->Length();
        hr = Extensions()->Serialize(pv, cb);
        if (hr != S_OK)
        {
            goto error;
        }

        ADVANCE_PARSE();
    }

error:
    return hr;
} // end function SerializePriv

/*********** MT_Certificate *****************/

MT_Certificate::MT_Certificate()
    : m_certificateList()
{
} // end ctor MT_Certificate

HRESULT
MT_Certificate::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    HRESULT hr = S_OK;

    hr = CertificateList()->Serialize(pv, cb);
    if (hr != S_OK)
    {
        goto error;
    }

error:
    return hr;
} // end function SerializePriv

HRESULT
MT_Certificate::PopulateFromFile(
    PCWSTR wszFilename
)
{
    UNREFERENCED_PARAMETER(wszFilename);
    return E_NOTIMPL;
} // end function PopulateFromFile

HRESULT
MT_Certificate::PopulateFromMemory(
    const BYTE* pvCert, size_t cbCert
)
{
    MT_ASN1Cert cert;
    cert.Data()->assign(pvCert, pvCert + cbCert);
    CertificateList()->Data()->assign(1, cert);
    return S_OK;
} // end function PopulateFromMemory

/*********** MT_SessionID *****************/

HRESULT
MT_SessionID::PopulateWithRandom()
{
    HRESULT hr = S_OK;

    ResizeVector(Data(), MaxLength());
    hr = WriteRandomBytes(&Data()->front(), Data()->size());

    if (hr != S_OK)
    {
        goto error;
    }

error:
    return hr;
} // end function PopulateWithRandom

/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : m_thingy()
{
} // end ctor MT_Thingy

HRESULT
MT_Thingy::ParseFromPriv(
    const BYTE* pv,
    size_t cb
)
{
    HRESULT hr = S_OK;
    size_t cbField = 0;

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
    ADVANCE_PARSE();

error:
    return hr;
} // end function ParseFromPriv

size_t
MT_Thingy::Length() const
{
    size_t cbLength = Something()->Length;
    return cbLength;
} // end function Length

HRESULT
MT_Thingy::SerializePriv(
    BYTE* pv,
    size_t cb
) const
{
    return E_NOTIMPL;
} // end function SerializePriv
*/

const BYTE c_abyCert[] = {
  0x30, 0x82, 0x03, 0x01, 0x30, 0x82, 0x01, 0xed, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x10, 0xfb, 0x40, 0xc2, 0x4a, 0x2f, 0xad, 0xdd, 0x8c, 0x49,
  0x95, 0xf7, 0xdd, 0x63, 0xcd, 0x21, 0xa3, 0x30, 0x09, 0x06, 0x05, 0x2b,
  0x0e, 0x03, 0x02, 0x1d, 0x05, 0x00, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10,
  0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x6d, 0x74, 0x6c, 0x73, 0x2d,
  0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x30, 0x30, 0x34,
  0x30, 0x31, 0x30, 0x38, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33,
  0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
  0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x09, 0x6d, 0x74, 0x6c, 0x73, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x82,
  0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
  0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc0, 0x7f, 0x56, 0x8a, 0x9c,
  0x86, 0xed, 0x96, 0x93, 0xc9, 0x7f, 0x0b, 0x6a, 0x48, 0x01, 0x84, 0xd6,
  0xe2, 0xc5, 0xd9, 0xca, 0xee, 0xa4, 0x79, 0xb5, 0x31, 0xd7, 0x23, 0x89,
  0x34, 0x8c, 0x22, 0x0f, 0x6e, 0x2e, 0xc7, 0x09, 0x45, 0x06, 0x9c, 0x00,
  0x1c, 0x07, 0x9d, 0xdc, 0xd2, 0x21, 0xd9, 0xac, 0xcf, 0x94, 0x02, 0x97,
  0x7e, 0x85, 0x2e, 0xad, 0xc4, 0xdd, 0x36, 0xab, 0x1c, 0xe8, 0x41, 0xa9,
  0xc2, 0x59, 0xa4, 0x92, 0xb5, 0x57, 0xed, 0x36, 0x9e, 0xf9, 0xa6, 0xf8,
  0x3a, 0x1c, 0xdf, 0xaa, 0xf1, 0xa7, 0x56, 0xbf, 0x3b, 0xfc, 0xdf, 0xdb,
  0x14, 0x9c, 0xe0, 0x9c, 0x1d, 0x6c, 0xf0, 0x3e, 0x30, 0xb4, 0x5b, 0xdd,
  0xd4, 0xcb, 0x9a, 0x13, 0x5c, 0x6b, 0xe9, 0xc4, 0x85, 0x13, 0xbb, 0x75,
  0x38, 0xaf, 0x98, 0x3f, 0xa8, 0xd1, 0x26, 0x5f, 0x0d, 0xa5, 0x93, 0x70,
  0xb6, 0x2c, 0xbd, 0x07, 0xe8, 0xb5, 0x2a, 0xa6, 0x72, 0xb0, 0x39, 0xd9,
  0x98, 0x9e, 0xc7, 0x14, 0x3d, 0x32, 0x0c, 0x27, 0x10, 0xbb, 0xb4, 0x5c,
  0xce, 0x4e, 0xb7, 0x71, 0x09, 0x97, 0x6e, 0x5e, 0xce, 0xa5, 0x73, 0x6b,
  0x05, 0x24, 0xe3, 0xda, 0xb2, 0x8f, 0xc3, 0x51, 0xcb, 0xa1, 0x6d, 0x53,
  0x8b, 0x23, 0x56, 0x66, 0x6a, 0x55, 0x6a, 0xb7, 0x1a, 0xd3, 0x3e, 0x6c,
  0x64, 0x96, 0xee, 0x1c, 0xab, 0x58, 0xd7, 0x75, 0xbd, 0x76, 0xa7, 0x2c,
  0x62, 0xbd, 0x15, 0x80, 0xd5, 0xf4, 0x3b, 0xac, 0xbb, 0xaa, 0xe5, 0x64,
  0x7c, 0xbb, 0xdb, 0x1e, 0xb9, 0x04, 0x78, 0xe4, 0x6c, 0xa3, 0x8e, 0xed,
  0x3f, 0x36, 0x72, 0xcc, 0x1f, 0xde, 0x60, 0xd0, 0xc0, 0x34, 0xbd, 0x29,
  0xc4, 0x34, 0x21, 0x04, 0x6c, 0x95, 0x2c, 0x8e, 0xe9, 0xc8, 0xfe, 0x71,
  0x4e, 0x9d, 0x3c, 0x12, 0x06, 0xd5, 0x39, 0x34, 0x47, 0x1d, 0x2f, 0x02,
  0x03, 0x01, 0x00, 0x01, 0xa3, 0x57, 0x30, 0x55, 0x30, 0x0c, 0x06, 0x03,
  0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x45,
  0x06, 0x03, 0x55, 0x1d, 0x01, 0x04, 0x3e, 0x30, 0x3c, 0x80, 0x10, 0xec,
  0xbb, 0x52, 0x93, 0xa3, 0x4f, 0x99, 0x99, 0x1c, 0x54, 0xcc, 0xd2, 0x55,
  0xa8, 0xa9, 0xc1, 0xa1, 0x16, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06,
  0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x6d, 0x74, 0x6c, 0x73, 0x2d, 0x74,
  0x65, 0x73, 0x74, 0x82, 0x10, 0xfb, 0x40, 0xc2, 0x4a, 0x2f, 0xad, 0xdd,
  0x8c, 0x49, 0x95, 0xf7, 0xdd, 0x63, 0xcd, 0x21, 0xa3, 0x30, 0x09, 0x06,
  0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
  0x00, 0xb6, 0x75, 0xad, 0x54, 0x1c, 0x7a, 0x91, 0xfa, 0xa0, 0x66, 0x83,
  0x5a, 0x27, 0x69, 0xb3, 0x61, 0xf7, 0x1b, 0x1f, 0xaa, 0x96, 0x70, 0x9f,
  0xab, 0x45, 0xa8, 0x21, 0x87, 0x22, 0xe2, 0x54, 0xb6, 0x9b, 0x0a, 0xc5,
  0xe9, 0xdb, 0x7d, 0xc5, 0x0c, 0x12, 0x24, 0xde, 0xe7, 0xa3, 0x9f, 0x63,
  0x03, 0x78, 0x57, 0x76, 0x11, 0x18, 0xfe, 0x7b, 0x58, 0x48, 0xa1, 0x85,
  0x57, 0xe7, 0x2e, 0x70, 0x84, 0xda, 0x52, 0x4a, 0x9e, 0xc3, 0x77, 0x8c,
  0x0b, 0x31, 0x0a, 0x17, 0x8f, 0xa0, 0x8f, 0x4a, 0xc3, 0x6e, 0x56, 0x80,
  0xad, 0x3a, 0xae, 0x89, 0xbc, 0x3b, 0xf5, 0xf4, 0x14, 0x0e, 0x56, 0xbd,
  0x18, 0x26, 0x39, 0x5e, 0xda, 0xf1, 0x79, 0x89, 0x27, 0x43, 0x21, 0xe6,
  0xc7, 0x17, 0x91, 0xcc, 0x93, 0xe5, 0x28, 0x9f, 0x04, 0x56, 0x1a, 0xad,
  0x76, 0xa3, 0x77, 0xec, 0xe6, 0xd3, 0xc1, 0xd2, 0x60, 0x78, 0xa6, 0x7d,
  0xcf, 0x4c, 0x3e, 0xaa, 0xf5, 0x76, 0xce, 0xc7, 0x54, 0x58, 0x11, 0x5e,
  0xaa, 0x35, 0xbc, 0xfe, 0xbd, 0xb8, 0x36, 0xbc, 0x15, 0xec, 0x9d, 0x1a,
  0x02, 0x47, 0x56, 0xc5, 0x0e, 0xa3, 0xc9, 0x1b, 0x25, 0x47, 0xc4, 0x1f,
  0xaa, 0xa3, 0xf5, 0xa2, 0xfa, 0x35, 0xd1, 0x96, 0x87, 0xf0, 0x00, 0x66,
  0x46, 0x60, 0x37, 0xe2, 0x0e, 0x91, 0x64, 0xa9, 0xb1, 0x34, 0x23, 0xb1,
  0x53, 0xad, 0x7b, 0xdc, 0x5e, 0x65, 0x67, 0x51, 0xd9, 0x05, 0xb3, 0xfd,
  0x44, 0x22, 0xc0, 0x54, 0x43, 0x5c, 0xc4, 0xe2, 0xe9, 0x3e, 0x45, 0x4c,
  0xd5, 0x16, 0x8a, 0x31, 0x87, 0x37, 0xd0, 0x25, 0x7d, 0x82, 0xb2, 0x8a,
  0xde, 0xf0, 0x0a, 0x1f, 0x47, 0x4d, 0x7c, 0xb7, 0xde, 0x7c, 0x97, 0xeb,
  0xb9, 0xdc, 0xc2, 0x73, 0x8e, 0xa1, 0x9a, 0x8b, 0x29, 0x80, 0x32, 0x79,
  0x43, 0x6d, 0x3f, 0x04, 0x14};

const size_t c_cbCert = ARRAYSIZE(c_abyCert);

}
