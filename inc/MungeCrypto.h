#pragma once
#include <windows.h>
#include <vector>
#include "mtls_defs.h"
#include "MungeTLS.h"

namespace MungeTLS
{

enum MT_CipherSuiteValue;

class SymmetricCipherer
{
    public:

    enum CipherAlg
    {
        CipherAlg_RC4_128 = 0,
        CipherAlg_AES_128 = 1,
        CipherAlg_AES_256 = 2
    };

    enum CipherType
    {
        CipherType_Stream,
        CipherType_Block
    };

    struct CipherInfo
    {
        CipherAlg alg;
        CipherType type;
        size_t cbKeyMaterialSize;
        size_t cbIVSize;
        size_t cbBlockSize;
    };

    virtual
    HRESULT
    Initialize(
        const ByteVector* pvbKey,
        const CipherInfo* pCipherInfo) = 0;

    virtual
    HRESULT
    EncryptBuffer(
        const ByteVector* pvbCleartext,
        ByteVector* pvbEncrypted) const = 0;

    virtual
    HRESULT
    DecryptBuffer(
        const ByteVector* pvbEncrypted,
        ByteVector* pvbDecrypted) const = 0;

    static
    HRESULT
    GetCipherInfo(
        CipherAlg alg,
        CipherInfo* pCipherInfo);

    private:
    static const CipherInfo c_rgCiphers[];
};

class PublicKeyCipherer
{
    public:
    virtual
    HRESULT
    EncryptBufferWithPublicKey(
        const ByteVector* pvbCleartext,
        ByteVector* pvbEncrypted) const = 0;

    virtual
    HRESULT
    DecryptBufferWithPrivateKey(
        const ByteVector* pvbEncrypted,
        ByteVector* pvbDecrypted) const = 0;

    virtual
    HRESULT
    EncryptBufferWithPrivateKey(
        const ByteVector* pvbCleartext,
        ByteVector* pvbEncrypted) const = 0;
};

class Hasher
{
    public:
    enum HashAlg
    {
        HashAlg_MD5       = 0,
        HashAlg_SHA1      = 1,
        HashAlg_SHA256    = 2
    };

    struct HashInfo
    {
        HashAlg alg;
        size_t cbHashSize;
        size_t cbHashKeySize;
    };

    virtual
    HRESULT
    Hash(
        HashAlg alg,
        const ByteVector* pvbText,
        ByteVector* pvbHash) = 0;

    virtual
    HRESULT
    HMAC(
        Hasher::HashAlg alg,
        const ByteVector* pvbKey,
        const ByteVector* pvbText,
        ByteVector* pvbHMAC) = 0;

    static
    HRESULT
    GetHashInfo(
        HashAlg alg,
        HashInfo* pHashInfo);

    private:
    static const HashInfo c_rgHashes[];
};


}
