#ifndef MTLS_INC_MUNGETLS_INL_HPP
#define MTLS_INC_MUNGETLS_INL_HPP
#include <assert.h>
#include <vector>
#include <memory>
#include <numeric>
#include "MungeTLS.h"
#include "mtls_helper.h"

namespace MungeTLS
{

using namespace std;

/*********** Utility functions *****************/

/*
** Serializes a number of structures to a vector, contiguously. "T" here should
** typically be a subclass of MT_Structure.
*/
template <typename T>
MTERR
SerializeMessagesToVector(
    typename vector<T>::const_iterator itBegin,
    typename vector<T>::const_iterator itEnd,
    ByteVector* pvb
)
{
    MTERR mr = MT_S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(itBegin, itEnd,
        [&mr, &cbTotal, pvb](const T& rStructure)
        {
            if (mr == MT_S_OK)
            {
                cbTotal += rStructure.Length();
                mr = rStructure.SerializeAppendToVect(pvb);
            }
        }
    );

    // if we succeeded, our tracked size should match the vector's size
    assert(mr != MT_S_OK || cbTotal == pvb->size());

    return mr;
} // end function SerializeMessagesToVector

// exactly the same as above, but using shared ptrs
template <typename T>
MTERR
SerializeMessagesToVector(
    typename vector<shared_ptr<T>>::const_iterator itBegin,
    typename vector<shared_ptr<T>>::const_iterator itEnd,
    ByteVector* pvb
)
{
    MTERR mr = MT_S_OK;
    size_t cbTotal = 0;

    pvb->clear();
    for_each(itBegin, itEnd,
        [&mr, &cbTotal, pvb](const shared_ptr<T>& rspStructure)
        {
            if (mr == MT_S_OK)
            {
                cbTotal += rspStructure->Length();
                mr = rspStructure->SerializeAppendToVect(pvb);
            }
        }
    );

    // if we succeeded, our tracked size should match the vector's size
    assert(mr != MT_S_OK || cbTotal == pvb->size());

    return mr;
} // end function SerializeMessagesToVector

/*
** considers pvb as a byte blob containing one or more structures of type T.
** tries to parse all of the contiguous structures out of it
*/
template <typename T>
MTERR
ParseStructures(
    const ByteVector* pvb,
    vector<T>* pvStructures
)
{
    MTERR mr = MT_S_OK;
    vector<T> vStructures;

    const MT_BYTE* pv = &pvb->front();
    size_t cb = pvb->size();

    assert(cb > 0);

    while (cb > 0)
    {
        size_t cbField = 0;

        // instantiate an object of type T at the end
        vStructures.emplace_back();

        // try to populate the new element by parsing from the byte blob
        mr = vStructures.back().ParseFrom(pv, cb);
        if (mr != MT_S_OK)
        {
            // if we failed to parse, remove the new element and exit
            vStructures.pop_back();
            break;
        }

        cbField = vStructures.back().Length();
        ADVANCE_PARSE();
    }

    if (vStructures.empty())
    {
        // if we parsed nothing, there must have been some error
        assert(mr != MT_S_OK);
        goto error;
    }

    // append newly parsed structures to the input vector
    pvStructures->insert(
        pvStructures->end(),
        vStructures.begin(),
        vStructures.end());

done:
    return mr;

error:
    goto done;
} // end function ParseStructures


/*********** MT_VariableLengthFieldBase *****************/

template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MT_VariableLengthFieldBase
<T, LengthFieldSize, MinSize, MaxSize>
::MT_VariableLengthFieldBase()
    : MT_Structure()
{
    MT_C_ASSERT(LengthFieldSize <= sizeof(size_t));
    MT_C_ASSERT(MAXFORBYTES(LengthFieldSize) >= MaxSize);
    MT_C_ASSERT(MaxSize >= MinSize);
} // end ctor MT_VariableLengthFieldBase

template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthFieldBase
<T, LengthFieldSize, MinSize, MaxSize>
::Length() const
{
    return LengthFieldSize + DataLength();
} // end function Length

template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
T*
MT_VariableLengthFieldBase
<T, LengthFieldSize, MinSize, MaxSize>
::at(
    typename vector<T>::size_type pos
)
{
    // adds auto-resizing. risky!
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
} // end function at


/*********** MT_VariableLengthField *****************/

/*
** parse a number of structures of type T out of a chunk of bytes. essentially,
** T needs to be a subclass of MT_Structure
*/
template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MTERR
MT_VariableLengthField
<T, LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbTotalElementsSize = 0;

    CHKOK(ReadNetworkLong(pv, cb, cbField, &cbTotalElementsSize));

    ADVANCE_PARSE();

    if (cbTotalElementsSize < MinSize)
    {
        mr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > MaxSize)
    {
        mr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbTotalElementsSize > cb)
    {
        mr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    while (cbTotalElementsSize > 0)
    {
        T elem;

        /*
        ** the overall vector declares that it's only taking up
        ** cbTotalElementsSize bytes, so don't consume anything beyond that.
        */
        CHKOK(elem.ParseFrom(pv, cbTotalElementsSize));

        Data()->push_back(elem);

        // deduct from both cb and cbTotalElementsSize
        cbField = elem.Length();
        ADVANCE_PARSE();
        SAFE_SUB(mr, cbTotalElementsSize, cbField);
    }

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv


template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
size_t
MT_VariableLengthField
<T, LengthFieldSize, MinSize, MaxSize>
::DataLength() const
{
    // count the byte length of all the elements
    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const T& next)
        {
            return sofar + next.Length();
        });

    assert(cbTotalDataLength <= MaxSize);
    assert(cbTotalDataLength >= MinSize);

    return cbTotalDataLength;
} // end function DataLength

template <typename T,
          size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MTERR
MT_VariableLengthField
<T, LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = LengthFieldSize;

    CHKOK(WriteNetworkLong(DataLength(), cbField, pv, cb));

    ADVANCE_PARSE();

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        SERIALIZEPSTRUCT(iter);
    }

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_VariableLengthByteField *****************/

template <size_t LengthFieldSize,
          size_t MinSize,
          size_t MaxSize>
MTERR
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = LengthFieldSize;
    size_t cbDataLength = 0;

    CHKOK(ReadNetworkLong(pv, cb, cbField, &cbDataLength));

    ADVANCE_PARSE();

    if (cbDataLength < MinSize)
    {
        mr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    if (cbDataLength > MaxSize)
    {
        mr = MT_E_DATA_SIZE_OUT_OF_RANGE;
        goto error;
    }

    PARSEVB(cbDataLength, Data());

done:
    return mr;

error:
    goto done;
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
MTERR
MT_VariableLengthByteField
<LengthFieldSize, MinSize, MaxSize>
::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = LengthFieldSize;

    CHKOK(WriteNetworkLong(DataLength(), cbField, pv, cb));

    ADVANCE_PARSE();

    SERIALIZEPVB(Data());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_FixedLengthStructureBase *****************/

template <typename T, size_t Size>
MT_FixedLengthStructureBase<T, Size>::MT_FixedLengthStructureBase()
    : MT_Structure(),
      m_vData()
{
    MT_C_ASSERT(Size > 0);
} // end ctor MT_FixedLengthStructureBase

template <typename T,
          size_t Size>
T*
MT_FixedLengthStructureBase<T, Size>::at(
    typename vector<T>::size_type pos
)
{
    // automatic vector resizing, oh my!
    if (pos >= Data()->size())
    {
        ResizeVector(Data(), pos + 1);
    }

    return &(Data()->at(pos));
} // end function at


/*********** MT_FixedLengthStructure *****************/

template <typename T, size_t Size>
MTERR
MT_FixedLengthStructure<T, Size>::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbTotalElementsSize = Size;

    if (cbTotalElementsSize > cb)
    {
        mr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    // don't consume more than the declared cbTotalElementsSize
    while (cbTotalElementsSize > 0)
    {
        T elem;
        CHKOK(elem.ParseFrom(pv, cbTotalElementsSize));

        Data()->push_back(elem);

        // advance both cb and cbTotalElementsSize
        size_t cbField = elem.Length();
        ADVANCE_PARSE();

        SAFE_SUB(mr, cbTotalElementsSize, cbField);
    }

    assert(Length() == Size);

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

template <typename T, size_t Size>
MTERR
MT_FixedLengthStructure<T, Size>::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;

    for (auto iter = Data()->begin(); iter != Data()->end(); iter++)
    {
        size_t cbField = 0;
        SERIALIZEPSTRUCT(iter);
    }

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

template <typename T, size_t Size>
size_t
MT_FixedLengthStructure<T, Size>::Length() const
{
    // count up the size of the elements in this vector
    size_t cbTotalDataLength = accumulate(
        Data()->begin(),
        Data()->end(),
        static_cast<size_t>(0),
        [](size_t sofar, const T& next)
        {
            return sofar + next.Length();
        });

    assert(Size == cbTotalDataLength);

    return cbTotalDataLength;
} // end function Length


/*********** MT_FixedLengthByteStructure *****************/

template <size_t Size>
MTERR
MT_FixedLengthByteStructure<Size>::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    PARSEVB(Size, Data());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

template <size_t Size>
MTERR
MT_FixedLengthByteStructure<Size>::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    assert(Length() <= cb);

    SERIALIZEPVB(Data());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

template <size_t Size>
size_t
MT_FixedLengthByteStructure<Size>::Length() const
{
    assert(Size == Data()->size());
    return Size;
} // end function Length


/*********** MT_PublicKeyEncryptedStructure *****************/

template <typename T>
MT_PublicKeyEncryptedStructure<T>::MT_PublicKeyEncryptedStructure()
    : MT_Structure(),
      m_structure(),
      m_vbEncryptedStructure(),
      m_vbPlaintextStructure()
{
} // end ctor MT_PublicKeyEncryptedStructure

template <typename T>
MTERR
MT_PublicKeyEncryptedStructure<T>::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbPublicKeyEncrypted_LFL;
    size_t cbStructureLength = 0;

    CHKOK(ReadNetworkLong(pv, cb, cbField, &cbStructureLength));

    ADVANCE_PARSE();

    PARSEVB(cbStructureLength, EncryptedStructure());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

template <typename T>
size_t
MT_PublicKeyEncryptedStructure<T>::Length() const
{
    return EncryptedStructure()->size();
} // end function Length

template <typename T>
MTERR
MT_PublicKeyEncryptedStructure<T>::DecryptStructure(
    PublicKeyCipherer* pCipherer
)
{
    MTERR mr = MT_S_OK;
    PlaintextStructure()->clear();

    CHKOK(pCipherer->DecryptBufferWithPrivateKey(
             EncryptedStructure(),
             PlaintextStructure()));

    CHKOK(Structure()->ParseFromVect(PlaintextStructure()));

done:
    return mr;

error:
    goto done;
} // end function DecryptStructure


/*********** MT_ClientKeyExchange *****************/

template <typename KeyType>
MT_ClientKeyExchange<KeyType>::MT_ClientKeyExchange()
    : m_spExchangeKeys()
{
} // end ctor MT_ClientKeyExchange

template <typename KeyType>
MTERR
MT_ClientKeyExchange<KeyType>::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    assert(ExchangeKeys() == nullptr);

    m_spExchangeKeys = shared_ptr<KeyType>(new KeyType());

    PARSEPSTRUCT(ExchangeKeys());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

}
#endif
