#ifndef MTLS_LIB_MTLS_HELPER_H
#define MTLS_LIB_MTLS_HELPER_H
#include <vector>
#include "MungeTLS.h"

namespace MungeTLS
{

// PLATFORM: needs to be implemented
MTERR MT_SizeTToByte(size_t s, MT_BYTE* pb);
MTERR MT_SizeTSub(size_t l, size_t r, size_t* pOut);
MTERR GetCurrentGMTTime(MT_UINT32* pTime);

MTERR PrintByteVector(const ByteVector* pvb);

template <typename N>
MTERR
ReadNetworkLong(
    const MT_BYTE* pv,
    size_t cb,
    size_t cbToRead,
    N* pResult
);

template <typename I>
MTERR
WriteNetworkLong(
    I toWrite,
    size_t cbToWrite,
    MT_BYTE* pv,
    size_t cb
);

MTERR
WriteRandomBytes(
    MT_BYTE* pv,
    size_t cb
);

template <typename T>
void ResizeVector(std::vector<T>* pVect, typename std::vector<T>::size_type siz);

// totally specialized for byte vector
template <>
void ResizeVector(ByteVector* pv, typename ByteVector::size_type siz);

}

#include "mtls_helper-inl.hpp"
#endif
