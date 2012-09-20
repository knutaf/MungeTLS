#ifndef MTLS_INC_MTLS_DEFS_H
#define MTLS_INC_MTLS_DEFS_H
#include <stdio.h>
#include <vector>

namespace MungeTLS
{

#define MT_C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#define MT_UNREFERENCED_PARAMETER(P)          (P)

// PLATFORM: may need to fix these typedefs for another platform
// see mtls_helper.h for C_ASSERTs about sizeof
typedef unsigned char MT_BYTE;
typedef unsigned char MT_UINT8;
typedef unsigned short MT_UINT16;
typedef unsigned long MT_UINT32;

#ifdef WINDOWS
typedef unsigned __int64 MT_UINT64;
#endif

MT_C_ASSERT(sizeof(MT_BYTE) == 1);
MT_C_ASSERT(sizeof(MT_UINT8) == 1);
MT_C_ASSERT(sizeof(MT_UINT16) == 2);
MT_C_ASSERT(sizeof(MT_UINT32) == 4);
MT_C_ASSERT(sizeof(MT_UINT64) == 8);

// just for convenience, since it's used everywhere
typedef std::vector<MT_BYTE> ByteVector;

typedef MT_UINT32 MTERR;
bool MT_Succeeded(MTERR mr);
bool MT_Failed(MTERR mr);

// 2^(b*8) - 1
#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define WSTRINGIFY2(x) L## #x
#define WSTRINGIFY(x) WSTRINGIFY2(x)

#define LOGFAIL(tag, stmt, err) wprintf(tag L" %s:%u - %s == %08LX\n", WIDEN(__FILE__), __LINE__, WSTRINGIFY(stmt), (err)); \

#define CHKSUC(stmt)                                        \
{                                                           \
    mr = (stmt);                                            \
    if (MT_Failed(mr))                                      \
    {                                                       \
        LOGFAIL(L"FAILED", (stmt), mr);                     \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKOK(stmt)                                         \
{                                                           \
    mr = (stmt);                                            \
    if (mr != MT_S_OK)                                      \
    {                                                       \
        LOGFAIL(L"!= MT_S_OK", (stmt), mr);                 \
        goto error;                                         \
    }                                                       \
}                                                           \

/*
** if we did extra validation and stuff in these accessors, we'd want to avoid
** code duplication by using Effective C++ Item 3's technique. look it up if
** you want to see some cool trickery
*/
#define ACCESSOR_RO(returnType, name, member)                    \
    virtual const returnType name() const { return member; }     \

#define ACCESSOR_RW(returnType, name, member)                    \
    virtual returnType name() { return member; }                 \

#define ACCESSORS(returnType, name, member)                      \
    ACCESSOR_RO(returnType, name, member)                        \
    ACCESSOR_RW(returnType, name, member)                        \

}
#endif
