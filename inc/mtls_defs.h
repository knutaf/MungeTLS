#pragma once
#include <windows.h>
#include <vector>

namespace MungeTLS
{

#define ACCESSORS(returnType, name, member) \
    const returnType name() const { return member; } \
    returnType name() { return const_cast<returnType>(static_cast<std::remove_pointer<decltype(this)>::type const*>(this)->name()); } \

typedef unsigned long MT_UINT16;

typedef std::vector<BYTE> ByteVector;

typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;

#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

}
