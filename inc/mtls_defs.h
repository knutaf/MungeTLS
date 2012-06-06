#pragma once
#include <windows.h>
#include <vector>

namespace MungeTLS
{

#define ACCESSOR_RO(returnType, name, member) \
    const returnType name() const { return member; } \

#define ACCESSOR_RW(returnType, name, member) \
    returnType name() { return const_cast<returnType>(static_cast<std::remove_pointer<decltype(this)>::type const*>(this)->name()); } \

#define ACCESSORS(returnType, name, member) \
    ACCESSOR_RO(returnType, name, member) \
    ACCESSOR_RW(returnType, name, member) \

typedef std::vector<BYTE> ByteVector;

typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;
typedef ULONGLONG MT_UINT64;

#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

}
