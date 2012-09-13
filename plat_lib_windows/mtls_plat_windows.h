#ifndef MTLS_PLAT_LIB_WINDOWS_MTLS_PLAT_WINDOWS_H
#define MTLS_PLAT_LIB_WINDOWS_MTLS_PLAT_WINDOWS_H
#include <windows.h>
#include <wincrypt.h>
#include <memory>
#include <vector>
#include "MungeTLS.h"
#include "MungeCrypto.h"

namespace MungeTLS
{

class KeyAndProv
{
    public:
    KeyAndProv();
    ~KeyAndProv();
    KeyAndProv& operator=(const KeyAndProv& rOther);

    void Init(HCRYPTPROV hProv, BOOL fCallerFree = TRUE);
    HCRYPTKEY GetKey() const { return m_hKey; }
    HCRYPTPROV GetProv() const { return m_hProv; }
    void SetKey(HCRYPTKEY hKey);
    void Detach();

    private:
    void Release();

    HCRYPTPROV m_hProv;
    HCRYPTKEY m_hKey;
    BOOL m_fCallerFree;
};

HRESULT
EncryptBuffer(
    const ByteVector* pvbCleartext,
    HCRYPTKEY hKey,
    const CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted);

HRESULT
DecryptBuffer(
    const ByteVector* pvbEncrypted,
    HCRYPTKEY hKey,
    const CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted);

HRESULT
LookupCertificate(
    DWORD dwCertStoreFlags,
    PCWSTR wszStoreName,
    PCWSTR wszSubjectName,
    PCCERT_CHAIN_CONTEXT* ppCertChain);

HRESULT
GetPrivateKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPrivateKey);

HRESULT
GetPublicKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPublicKey);

HRESULT
MTCertChainFromWinChain(
    PCCERT_CHAIN_CONTEXT pWinChain,
    MT_CertificateList* pMTChain);

HRESULT
ImportSymmetricKey(
    const ByteVector* pvbKey,
    ALG_ID algID,
    KeyAndProv* pKey);



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

class WindowsSymmetricCipherer : public SymmetricCipherer
{
    public:
    WindowsSymmetricCipherer();
    ~WindowsSymmetricCipherer() { }

    HRESULT
    SetCipherInfo(
        const ByteVector* pvbKey,
        const CipherInfo* pCipherInfo);

    HRESULT
    EncryptBuffer(
        const ByteVector* pvbCleartext,
        const ByteVector* pvbIV,
        ByteVector* pvbEncrypted);

    HRESULT
    DecryptBuffer(
        const ByteVector* pvbEncrypted,
        const ByteVector* pvbIV,
        ByteVector* pvbDecrypted);

    static
    HRESULT
    WindowsCipherAlgFromMTCipherAlg(
        CipherAlg alg,
        ALG_ID* pAlgID);

    private:
    ACCESSORS(std::shared_ptr<KeyAndProv>*, Key, &m_spKey);

    std::shared_ptr<KeyAndProv> m_spKey;
};

class WindowsHasher : public Hasher
{
    public:
    HRESULT
    Hash(
        const HashInfo* pHashInfo,
        const ByteVector* pvbText,
        ByteVector* pvbHash);

    HRESULT
    HMAC(
        const HashInfo* pHashInfo,
        const ByteVector* pvbKey,
        const ByteVector* pvbText,
        ByteVector* pvbHMAC);

    private:
    static
    HRESULT WindowsHashAlgFromMTHashInfo(
        const HashInfo* pHashInfo,
        ALG_ID* pAlg);
};

}
#endif
