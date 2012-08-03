#pragma once
#include <windows.h>
#include <vector>
#include "mtls_defs.h"
#include "MungeTLS.h"

namespace MungeTLS
{

enum MT_CipherSuiteValue;

enum CipherAlg
{
    CipherAlg_Unknown,
    CipherAlg_NULL,
    CipherAlg_RSA,
    CipherAlg_RC4_128,
    CipherAlg_AES_128,
    CipherAlg_AES_256
};

enum CipherType
{
    CipherType_Stream,
    CipherType_Block,
    CipherType_Asymmetric_Block
};

struct CipherInfo
{
    CipherAlg alg;
    CipherType type;
    size_t cbKeyMaterialSize;
    size_t cbIVSize;
    size_t cbBlockSize;
    bool operator==(const CipherInfo& rOther) const { return alg == rOther.alg; }
};

enum HashAlg
{
    HashAlg_Unknown,
    HashAlg_NULL,
    HashAlg_MD5,
    HashAlg_SHA1,
    HashAlg_SHA256
};

struct HashInfo
{
    HashAlg alg;
    size_t cbHashSize;
    size_t cbHashKeySize;
    bool operator==(const HashInfo& rOther) const { return alg == rOther.alg; }
};

const CipherInfo c_CipherInfo_RSA =
{
    CipherAlg_RSA,
    CipherType_Asymmetric_Block,
    16,
    0,
    0
};

const CipherInfo c_CipherInfo_NULL =
{
    CipherAlg_NULL,
    CipherType_Stream,
    0,
    0,
    0
};

const CipherInfo c_CipherInfo_RC4_128 =
{
    CipherAlg_RC4_128,
    CipherType_Stream,
    16,
    0,
    0
};

const CipherInfo c_CipherInfo_AES_128 =
{
    CipherAlg_AES_128,
    CipherType_Block,
    16,
    16,
    16
};

const CipherInfo c_CipherInfo_AES_256 =
{
    CipherAlg_AES_256,
    CipherType_Block,
    32,
    16,
    16
};

const HashInfo c_HashInfo_NULL =
{
    HashAlg_NULL,
    0,
    0
};

const HashInfo c_HashInfo_MD5 =
{
    HashAlg_MD5,
    16,
    16,
};

const HashInfo c_HashInfo_SHA1 =
{
    HashAlg_SHA1,
    20,
    20,
};

const HashInfo c_HashInfo_SHA256 =
{
    HashAlg_SHA256,
    32,
    32,
};

class SymmetricCipherer
{
    public:
    SymmetricCipherer();
    virtual ~SymmetricCipherer() { }

    virtual
    HRESULT
    Initialize(
        const ByteVector* pvbKey,
        const CipherInfo* pCipherInfo) = 0;

    virtual
    HRESULT
    EncryptBuffer(
        const ByteVector* pvbCleartext,
        const ByteVector* pvbIV,
        ByteVector* pvbEncrypted);

    virtual
    HRESULT
    DecryptBuffer(
        const ByteVector* pvbEncrypted,
        const ByteVector* pvbIV,
        ByteVector* pvbDecrypted);

    ACCESSORS(CipherInfo*, Cipher, &m_cipherInfo);

    private:
    CipherInfo m_cipherInfo;
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
    virtual
    HRESULT
    Hash(
        const HashInfo* pHashInfo,
        const ByteVector* pvbText,
        ByteVector* pvbHash);

    virtual
    HRESULT
    HMAC(
        const HashInfo* pHashInfo,
        const ByteVector* pvbKey,
        const ByteVector* pvbText,
        ByteVector* pvbHMAC);
};

}
