#include "precomp.h"

#include <windows.h>
#include <vector>
#include <assert.h>

#include "MungeCrypto.h"

namespace MungeTLS
{

using namespace std;

const SymmetricCipherer::CipherInfo SymmetricCipherer::c_rgCiphers[] =
{
    {
        SymmetricCipherer::CipherAlg_RC4_128,
        SymmetricCipherer::CipherType_Stream,
        16,
        0,
        0
    },
    {
        SymmetricCipherer::CipherAlg_AES_128,
        SymmetricCipherer::CipherType_Block,
        16,
        16,
        16
    },
    {
        SymmetricCipherer::CipherAlg_AES_256,
        SymmetricCipherer::CipherType_Block,
        32,
        16,
        16
    }
};

const Hasher::HashInfo Hasher::c_rgHashes[] =
{
    {
        Hasher::HashAlg_MD5,
        16,
        16,
    },
    {
        Hasher::HashAlg_SHA1,
        20,
        20,
    },
    {
        Hasher::HashAlg_SHA256,
        32,
        32,
    }
};

HRESULT
Hasher::GetHashInfo(
    HashAlg alg,
    HashInfo* pHashInfo
)
{
    HashInfo info;

    assert(static_cast<int>(alg) >= 0);
    assert(static_cast<int>(alg) < ARRAYSIZE(c_rgHashes));

    info = c_rgHashes[alg];

    assert(alg == info.alg);

    *pHashInfo = info;
    return S_OK;
} // end function GetHashInfo

HRESULT
SymmetricCipherer::GetCipherInfo(
    CipherAlg alg,
    CipherInfo* pCipherInfo
)
{
    CipherInfo info;

    assert(static_cast<int>(alg) >= 0);
    assert(static_cast<int>(alg) < ARRAYSIZE(c_rgCiphers));

    info = c_rgCiphers[alg];

    assert(alg == info.alg);

    *pCipherInfo = info;

    return S_OK;
} // end function GetCipherInfo

}
