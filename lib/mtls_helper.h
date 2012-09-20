#ifndef MTLS_LIB_MTLS_HELPER_H
#define MTLS_LIB_MTLS_HELPER_H
#include "MungeTLS.h"

namespace MungeTLS
{

// PLATFORM: needs to be implemented
MTERR MT_SizeTToByte(size_t s, MT_BYTE* pb);
MTERR MT_SizeTSub(size_t l, size_t r, size_t* pOut);

MTERR PrintByteVector(const ByteVector* pvb);

}
#endif
