#pragma once
#include <windows.h>
#include <intsafe.h>
#include <wincrypt.h>
#include <memory>
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
        const std::vector<BYTE>* pvbKey,
        const CipherInfo* pCipherInfo);

    HRESULT
    EncryptBuffer(
        const std::vector<BYTE>* pvbCleartext,
        std::vector<BYTE>* pvbEncrypted) const;

    HRESULT
    DecryptBuffer(
        const std::vector<BYTE>* pvbEncrypted,
        std::vector<BYTE>* pvbDecrypted) const;

    static
    HRESULT
    WindowsCipherAlgFromMTCipherAlg(
        SymmetricCipherer::CipherAlg alg,
        ALG_ID* pAlgID);

    private:
    ACCESSORS(CipherInfo*, Cipher, &m_cipherInfo);
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
        const std::vector<BYTE>* pvbCleartext,
        std::vector<BYTE>* pvbEncrypted) const;

    HRESULT
    DecryptBufferWithPrivateKey(
        const std::vector<BYTE>* pvbEncrypted,
        std::vector<BYTE>* pvbDecrypted) const;

    HRESULT
    EncryptBufferWithPrivateKey(
        const std::vector<BYTE>* pvbCleartext,
        std::vector<BYTE>* pvbEncrypted) const;

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
        const std::vector<BYTE>* pvbText,
        std::vector<BYTE>* pvbHash);

    HRESULT
    HMAC(
        Hasher::HashAlg alg,
        const std::vector<BYTE>* pvbKey,
        const std::vector<BYTE>* pvbText,
        std::vector<BYTE>* pvbHMAC);

    private:
    static
    HRESULT WindowsHashAlgFromMTHashAlg(
        Hasher::HashAlg alg,
        ALG_ID* pAlg);
};

HRESULT
EncryptBuffer(
    const std::vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    std::vector<BYTE>* pvbEncrypted);

HRESULT
DecryptBuffer(
    const std::vector<BYTE>* pvbEncrypted,
    HCRYPTKEY hKey,
    SymmetricCipherer::CipherType cipherType,
    std::vector<BYTE>* pvbDecrypted);

std::vector<BYTE> ReverseByteOrder(const std::vector<BYTE>* pvb);

HRESULT PrintByteVector(const std::vector<BYTE>* pvb);

HRESULT
ImportSymmetricKey(
    const std::vector<BYTE>* pvbKey,
    ALG_ID algID,
    KeyAndProv* pKey);

}
