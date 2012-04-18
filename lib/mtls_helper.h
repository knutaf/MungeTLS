#pragma once
#include <windows.h>
#include <intsafe.h>
#include <wincrypt.h>
#include <memory>
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

    void Init(HCRYPTPROV hProv, BOOL fCallerFree);
    HCRYPTKEY GetKey() const { return m_hKey; }
    void SetKey(HCRYPTKEY hKey) { m_hKey = hKey; }
    void Detach();

    private:
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

HRESULT
EncryptBuffer(
    const std::vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    std::vector<BYTE>* pvbEncrypted);

HRESULT
DecryptBuffer(
    const std::vector<BYTE>* pvbEncrypted,
    HCRYPTKEY hKey,
    std::vector<BYTE>* pvbDecrypted);

}
