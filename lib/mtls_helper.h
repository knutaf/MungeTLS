#pragma once
#include <windows.h>
#include <intsafe.h>
#include <wincrypt.h>
#include <memory>
#include <vector>
#include "MungeTLS.h"
#include "MungeCrypto.h"

#define SAFE_SUB(h, l, r)              \
{                                      \
    (h) = SizeTSub((l), (r), &(l));    \
    if ((h) != S_OK) { goto error; }   \
}                                      \

#define ADVANCE_PARSE()                \
{                                      \
    pv += cbField;                     \
    SAFE_SUB(hr, cb, cbField);         \
}                                      \

namespace MungeTLS
{

class KeyAndProv
{
    public:
    KeyAndProv();
    ~KeyAndProv();
    KeyAndProv& operator=(const KeyAndProv& rOther);

    void Init(HCRYPTPROV hProv, BOOL fCallerFree);
    HCRYPTKEY GetKey() const { return m_hKey; }
    HCRYPTPROV GetProv() const { return m_hProv; }
    void SetKey(HCRYPTKEY hKey);
    void Detach();

    private:
    void Clear();

    HCRYPTPROV m_hProv;
    HCRYPTKEY m_hKey;
    BOOL m_fCallerFree;
};

HRESULT
LookupCertificate(
    DWORD dwCertStoreFlags,
    PCWSTR wszStoreName,
    PCWSTR wszSubjectName,
    PCCERT_CONTEXT* ppCertContext);

HRESULT
GetPrivateKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPrivateKey);

HRESULT
GetPublicKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPublicKey);

class WindowsSymmetricCipherer : public SymmetricCipherer
{
    public:
    WindowsSymmetricCipherer();
    ~WindowsSymmetricCipherer() { }

    HRESULT
    Initialize(
        const ByteVector* pvbKey,
        const CipherInfo* pCipherInfo);

    HRESULT
    EncryptBuffer(
        const ByteVector* pvbCleartext,
        const ByteVector* pvbIV,
        ByteVector* pvbEncrypted) const;

    HRESULT
    DecryptBuffer(
        const ByteVector* pvbEncrypted,
        const ByteVector* pvbIV,
        ByteVector* pvbDecrypted) const;

    static
    HRESULT
    WindowsCipherAlgFromMTCipherAlg(
        SymmetricCipherer::CipherAlg alg,
        ALG_ID* pAlgID);

    ACCESSORS(CipherInfo*, Cipher, &m_cipherInfo);

    private:
    ACCESSORS(KeyAndProv*, Key, &m_key);

    KeyAndProv m_key;
    CipherInfo m_cipherInfo;
};

class WindowsPublicKeyCipherer : public PublicKeyCipherer
{
    public:
    WindowsPublicKeyCipherer();
    ~WindowsPublicKeyCipherer() { }

    HRESULT Initialize(
        std::shared_ptr<KeyAndProv> spPublicKeyProv,
        std::shared_ptr<KeyAndProv> spPrivateKeyProv);

    HRESULT Initialize(PCCERT_CONTEXT pCertCContext);

    HRESULT
    EncryptBufferWithPublicKey(
        const ByteVector* pvbCleartext,
        ByteVector* pvbEncrypted) const;

    HRESULT
    DecryptBufferWithPrivateKey(
        const ByteVector* pvbEncrypted,
        ByteVector* pvbDecrypted) const;

    HRESULT
    EncryptBufferWithPrivateKey(
        const ByteVector* pvbCleartext,
        ByteVector* pvbEncrypted) const;

    private:
    HCRYPTKEY PublicKey() const { return PublicKeyAndProv()->GetKey(); }
    HCRYPTKEY PrivateKey() const { return PrivateKeyAndProv()->GetKey(); }

    std::shared_ptr<KeyAndProv> PrivateKeyAndProv() const { return m_spPrivateKeyProv; }
    std::shared_ptr<KeyAndProv> PublicKeyAndProv() const { return m_spPublicKeyProv; }

    std::shared_ptr<KeyAndProv> m_spPublicKeyProv;
    std::shared_ptr<KeyAndProv> m_spPrivateKeyProv;
};

class WindowsHasher : public Hasher
{
    public:
    HRESULT
    Hash(
        Hasher::HashAlg alg,
        const ByteVector* pvbText,
        ByteVector* pvbHash);

    HRESULT
    HMAC(
        Hasher::HashAlg alg,
        const ByteVector* pvbKey,
        const ByteVector* pvbText,
        ByteVector* pvbHMAC);

    private:
    static
    HRESULT WindowsHashAlgFromMTHashAlg(
        Hasher::HashAlg alg,
        ALG_ID* pAlg);
};

HRESULT
EncryptBuffer(
    const ByteVector* pvbCleartext,
    HCRYPTKEY hKey,
    const SymmetricCipherer::CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted);

HRESULT
DecryptBuffer(
    const ByteVector* pvbEncrypted,
    HCRYPTKEY hKey,
    const SymmetricCipherer::CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted);

ByteVector ReverseByteOrder(const ByteVector* pvb);

HRESULT PrintByteVector(const ByteVector* pvb);

HRESULT
ImportSymmetricKey(
    const ByteVector* pvbKey,
    ALG_ID algID,
    KeyAndProv* pKey);

}
