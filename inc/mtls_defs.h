#pragma once
#include <windows.h>
#include <vector>

namespace MungeTLS
{

/*
** this idiom is taken from Effective C++, I believe. I should look up which
** number it is and put it in here, because it's really excellent. since this
** is only used for a member where we own the variable ourselves, the RW
** version knows that it is okay to relax/remove the const restriction when
** handing it out
**
** there is some wacky c++ magic going on with the decltype that I am not
** really expert enough to explain. it's important to cast the "this" pointer
** to its const version in order to avoid 
** TODO: why not just "return member"?
*/
#define ACCESSOR_RO(returnType, name, member) \
    virtual const returnType name() const { return member; } \

#define ACCESSOR_RW(returnType, name, member) \
    virtual returnType name() { return const_cast<returnType>(static_cast<std::remove_pointer<decltype(this)>::type const*>(this)->name()); } \

#define ACCESSORS(returnType, name, member) \
    ACCESSOR_RO(returnType, name, member) \
    ACCESSOR_RW(returnType, name, member) \

// just for convenience, since it's used everywhere
typedef std::vector<BYTE> ByteVector;

// we never use sizeof on these things, by design
typedef ULONG MT_UINT8;
typedef ULONG MT_UINT16;
typedef ULONG MT_UINT32;
typedef ULONGLONG MT_UINT64;

// 2^(b*8) - 1
#define MAXFORBYTES(b) ((1 << ((b) * 8)) - 1)

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define WSTRINGIFY2(x) L## #x
#define WSTRINGIFY(x) WSTRINGIFY2(x)

#define LOGFAIL(tag, stmt) wprintf(tag L" %s:%u - %s == %08LX\n", WIDEN(__FILE__), __LINE__, WSTRINGIFY(stmt), hr); \

#define CHKSUC(stmt)                                        \
{                                                           \
    hr = (stmt);                                            \
    if (FAILED(hr))                                         \
    {                                                       \
        LOGFAIL(L"FAILED", (stmt));                         \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKOK(stmt)                                         \
{                                                           \
    hr = (stmt);                                            \
    if (hr != S_OK)                                         \
    {                                                       \
        LOGFAIL(L"!= S_OK", (stmt));                        \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKWIN(stmt)                                        \
{                                                           \
    if (!(stmt))                                            \
    {                                                       \
        hr = HRESULT_FROM_WIN32(GetLastError());            \
        LOGFAIL(L"FALSE", (stmt));                          \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKNUL(stmt)                                        \
{                                                           \
    if (NULL == (stmt))                                     \
    {                                                       \
        hr = HRESULT_FROM_WIN32(GetLastError());            \
        LOGFAIL(L"NULL", (stmt));                           \
        goto error;                                         \
    }                                                       \
}                                                           \

}
