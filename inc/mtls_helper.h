#ifndef MTLS_LIB_MTLS_HELPER_H
#define MTLS_LIB_MTLS_HELPER_H
#include <vector>
#include "MungeTLS.h"

namespace MungeTLS
{

/*
** PLATFORM: needs to be implemented
** same contract as SizeTToByte on Windows, but returning an MTERR
*/
MTERR
MT_SizeTToByte(
    _In_ size_t s,
    _Out_ MT_BYTE* pb);

/*
** PLATFORM: needs to be implemented
** same contract as SizeTSub on Windows, but returning an MTERR
*/
MTERR
MT_SizeTSub(
    _In_ size_t l,
    _In_ size_t r,
    _Out_ size_t* pOut);

/*
** PLATFORM: needs to be implemented
** pTime should receive a 32-bit time value representing seconds since midnight
** on Jan 1 1970 GMT, which is suitable for inclusion in the "gmt_unix_time"
** field in the TLS RFC.
*/
MTERR
GetCurrentGMTTime(
    _Out_ MT_UINT32* pTime);

MTERR_T
PrintByteVector(
    _In_ const ByteVector* pvb);

template <typename N>
MTERR
ReadNetworkLong(
    _In_reads_bytes_(cb) const MT_BYTE* pv,
    _In_ size_t cb,
    _In_ size_t cbToRead,
    _Out_ N* pResult);

template <typename I>
MTERR
WriteNetworkLong(
    _In_ I toWrite,
    _In_ size_t cbToWrite,
    _Out_writes_bytes_(cb) MT_BYTE* pv,
    _In_ size_t cb);

MTERR
WriteRandomBytes(
    _Out_writes_bytes_all_(cb) MT_BYTE* pv,
    _In_ size_t cb);

template <typename T>
void
ResizeVector(
    _Inout_ std::vector<T>* pVect,
    _In_ typename std::vector<T>::size_type siz);

// totally specialized for byte vector
template <>
void
ResizeVector(
    _Inout_ ByteVector* pv,
    _In_ typename ByteVector::size_type cb);


/**************** Serializing helper functions and macros ****************/

MTERR
ParseByteVector(
    _In_ size_t cbField,
    _In_reads_bytes_(cb) const MT_BYTE* pv,
    _In_ size_t cb,
    _Out_ ByteVector* pvb);

MTERR
SerializeByteVector(
    _In_ const ByteVector* pvb,
    _Out_writes_bytes_(cb) MT_BYTE* pv,
    _In_ size_t cb);

// catches underflow errors in a MTERR
#define SAFE_SUB(m, l, r)                                          \
{                                                                  \
    (m) = MT_SizeTSub((l), (r), &(l));                             \
    if ((m) != MT_S_OK) { goto error; }                            \
}                                                                  \

#define ADVANCE_PARSE()                                            \
{                                                                  \
    pv += cbField;                                                 \
    SAFE_SUB(mr, cb, cbField);                                     \
}                                                                  \

#define PARSEVB(len, vect)                                         \
{                                                                  \
    cbField = (len);                                               \
    CHKOK(ParseByteVector(cbField, pv, cb, (vect)));               \
    ADVANCE_PARSE();                                               \
}                                                                  \

#define SERIALIZEPVB(vect)                                         \
{                                                                  \
    cbField = (vect)->size();                                      \
    CHKOK(SerializeByteVector((vect), pv, cb));                    \
    ADVANCE_PARSE();                                               \
}                                                                  \

#define PARSEPSTRUCT(s)                                            \
{                                                                  \
    CHKOK((s)->ParseFrom(pv, cb));                                 \
    cbField = (s)->Length();                                       \
    ADVANCE_PARSE();                                               \
}                                                                  \

#define PARSESTRUCT(s) PARSEPSTRUCT(&(s))

#define SERIALIZEPSTRUCT(s)                                        \
{                                                                  \
    cbField = (s)->Length();                                       \
    CHKOK((s)->Serialize(pv, cb));                                 \
    ADVANCE_PARSE();                                               \
}                                                                  \

}

#include "mtls_helper-inl.hpp"
#endif
