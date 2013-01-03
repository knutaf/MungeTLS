#ifndef MTLS_INC_MTLS_DEFS_H
#define MTLS_INC_MTLS_DEFS_H
#include <stdio.h>
#include <vector>

namespace MungeTLS
{

#define MT_C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#define MT_UNREFERENCED_PARAMETER(P)          (P)

// PLATFORM: may need to fix these typedefs for another platform
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

const MTERR MT_S_OK                                       = 0x00000000;
const MTERR MT_S_FALSE                                    = 0x00000001;
const MTERR MT_E_FAIL                                     = 0x80230000;
const MTERR MT_E_INSUFFICIENT_BUFFER                      = 0x80230011;
const MTERR MT_E_NOTIMPL                                  = 0x80234001;
const MTERR MT_E_INVALIDARG                               = 0x80230057;


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

// accessors for regular non-pointer members.
#define ACCESSOR_GETTER_RO(returnType, name, member)                          \
    virtual const returnType* Get ## name() const                             \
    {                                                                         \
        return &(member);                                                     \
    }                                                                         \

#define ACCESSOR_GETTER_RW(returnType, name, member)                          \
    virtual returnType* Get ## name()                                         \
    {                                                                         \
        return &(member);                                                     \
    }                                                                         \

#define ACCESSOR_SETTER(dataType, name, member)                               \
    virtual MTERR Set ## name(const dataType* accset_val)                     \
    {                                                                         \
        (member) = *accset_val;                                               \
        return MT_S_OK;                                                       \
    }                                                                         \

#define ACCESSOR_SETTER_VAL(dataType, name, member)                           \
    virtual MTERR Set ## name(dataType accset_val)                            \
    {                                                                         \
        (member) = accset_val;                                                \
        return MT_S_OK;                                                       \
    }                                                                         \

#define ACCESSOR_GETTERS(returnType, name, member)                            \
    ACCESSOR_GETTER_RO(returnType, name, member)                              \
    ACCESSOR_GETTER_RW(returnType, name, member)                              \

#define ACCESSOR_SETTERS(returnType, name, member)                            \
    ACCESSOR_SETTER(returnType, name, member)                                 \
    ACCESSOR_SETTER_VAL(returnType, name, member)                             \

#define ACCESSORS(returnType, name, member)                                   \
    ACCESSOR_GETTERS(returnType, name, member)                                \
    ACCESSOR_SETTERS(returnType, name, member)                                \


/*
** accessors for pointers. doesn't allow assigning to the referenced value,
** only the pointer itself
*/
#define ACCESSOR_PTR_GETTER_RO(returnType, name, member)                      \
    virtual const returnType* Get ## name() const                             \
    {                                                                         \
        return (member);                                                      \
    }                                                                         \

#define ACCESSOR_PTR_GETTER_RW(returnType, name, member)                      \
    virtual returnType* Get ## name()                                         \
    {                                                                         \
        return (member);                                                      \
    }                                                                         \

#define ACCESSOR_PTR_SETTER(dataType, name, member)                           \
    virtual MTERR Set ## name(dataType* accset_val)                           \
    {                                                                         \
        (member) = accset_val;                                                \
        return MT_S_OK;                                                       \
    }                                                                         \

#define ACCESSOR_PTR_GETTERS(returnType, name, member)                        \
    ACCESSOR_PTR_GETTER_RO(returnType, name, member)                          \
    ACCESSOR_PTR_GETTER_RW(returnType, name, member)                          \

#define ACCESSOR_PTR_SETTERS(returnType, name, member)                        \
    ACCESSOR_PTR_SETTER(returnType, name, member)                             \

#define ACCESSORS_PTR(returnType, name, member)                               \
    ACCESSOR_PTR_GETTERS(returnType, name, member)                            \
    ACCESSOR_PTR_SETTERS(returnType, name, member)                            \


// accessors for shared pointers
#define ACCESSOR_SP_GETTER_RO(returnType, name, member)                       \
    virtual std::shared_ptr<const returnType> Get ## name() const             \
    {                                                                         \
        return member;                                                        \
    }                                                                         \

#define ACCESSOR_SP_GETTER_RW(returnType, name, member)                       \
    virtual std::shared_ptr<returnType> Get ## name()                         \
    {                                                                         \
        return member;                                                        \
    }                                                                         \

#define ACCESSOR_SP_SETTER(dataType, name, member)                            \
    virtual MTERR Set ## name(std::shared_ptr<dataType> accset_val)           \
    {                                                                         \
        (member) = accset_val;                                                \
        return MT_S_OK;                                                       \
    }                                                                         \

#define ACCESSOR_SP_GETTERS(returnType, name, member)                         \
    ACCESSOR_SP_GETTER_RO(returnType, name, member)                           \
    ACCESSOR_SP_GETTER_RW(returnType, name, member)                           \

#define ACCESSOR_SP_SETTERS(returnType, name, member)                         \
    ACCESSOR_SP_SETTER(returnType, name, member)                              \

#define ACCESSORS_SP(returnType, name, member)                                \
    ACCESSOR_SP_GETTERS(returnType, name, member)                             \
    ACCESSOR_SP_SETTERS(returnType, name, member)                             \

}
#endif
