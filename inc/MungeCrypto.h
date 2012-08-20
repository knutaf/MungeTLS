#pragma once
#include <windows.h>
#include <vector>
#include "mtls_defs.h"

// this header contains purely crypto related constants and definitions

namespace MungeTLS
{

enum CipherAlg
{
    CipherAlg_Unknown,
    CipherAlg_NULL,
    CipherAlg_RSA,
    CipherAlg_RC4_128,
    CipherAlg_AES_128,
    CipherAlg_AES_256
};

/*
** stream, e.g. RC4
** block, e.g. AES
** asymmetric block, e.g. RSA
*/
enum CipherType
{
    CipherType_Stream,
    CipherType_Block,
    CipherType_Asymmetric_Block
};

/*
** cbKeyMaterialSize - size of the encryption key in bytes
** cbIVSize - size of the initialization vector in bytes
** cbBlockSize - size of the block produced by encrypting
*/
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

/*
** cbHashSize - size of the data produced by the hash
** cbMACKeySize - size of the key used as input to a MAC using this hash algo
**                (usually the same as the hash size)
*/
struct HashInfo
{
    HashAlg alg;
    size_t cbHashSize;
    size_t cbMACKeySize;
    bool operator==(const HashInfo& rOther) const { return alg == rOther.alg; }
};

const CipherInfo c_CipherInfo_RSA =
{
    CipherAlg_RSA,
    CipherType_Asymmetric_Block,
    0,                               // key material size
    0,                               // IV size
    0                                // block size
};

const CipherInfo c_CipherInfo_NULL =
{
    CipherAlg_NULL,
    CipherType_Stream,
    0,                               // key material size
    0,                               // IV size
    0                                // block size
};

const CipherInfo c_CipherInfo_RC4_128 =
{
    CipherAlg_RC4_128,
    CipherType_Stream,
    16,                               // key material size
    0,                                // IV size
    0                                 // block size
};

const CipherInfo c_CipherInfo_AES_128 =
{
    CipherAlg_AES_128,
    CipherType_Block,
    16,                               // key material size
    16,                               // IV size
    16                                // block size
};

const CipherInfo c_CipherInfo_AES_256 =
{
    CipherAlg_AES_256,
    CipherType_Block,
    32,                               // key material size
    16,                               // IV size
    16                                // block size
};

const HashInfo c_HashInfo_NULL =
{
    HashAlg_NULL,
    0,                                // hash size
    0                                 // MAC key size
};

const HashInfo c_HashInfo_MD5 =
{
    HashAlg_MD5,
    16,                               // hash size
    16,                               // MAC key size
};

const HashInfo c_HashInfo_SHA1 =
{
    HashAlg_SHA1,
    20,                               // hash size
    20,                               // MAC key size
};

const HashInfo c_HashInfo_SHA256 =
{
    HashAlg_SHA256,
    32,                               // hash size
    32,                               // MAC key size
};

/*
** an interface used for encrypting and decrypting using public key
** cryptography, e.g. RSA. the app should implement these in an object for
** their specific platform
*/
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

/*
** an interface used for simply encrypting and decrypting data using symmetric
** encryption, such as RC4 or AES. In the RFC this is referred to as a "bulk
** cipher". apps will implement this interface for their platform
*/
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

/*
** an interface for hashing data and performing a HMAC (hashed message
** authentication code). an app should implement this for their platform. Since
** hashing is usually stateless, there is no Initialize function here.
*/
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
