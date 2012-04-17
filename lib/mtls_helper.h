#pragma once
#include <windows.h>
#include <intsafe.h>
#include <wincrypt.h>
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

HRESULT
LookupCertificate(
    DWORD dwCertStoreFlags,
    PCWSTR wszStoreName,
    PCWSTR wszSubjectName,
    PCCERT_CONTEXT* ppCertContext);

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

class WindowsPublicKeyCipherer : public PublicKeyCipherer
{
    public:
    WindowsPublicKeyCipherer(
        std::shared_ptr<KeyAndProv> spPublicKeyProv,
        std::shared_ptr<KeyAndProv> spPrivateKeyProv);

    ~WindowsPublicKeyCipherer() { }

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
    HCRYPTKEY PublicKey() const { return m_spPublicKeyProv->GetKey(); }
    HCRYPTKEY PrivateKey() const { return m_spPrivateKeyProv->GetKey(); }

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
