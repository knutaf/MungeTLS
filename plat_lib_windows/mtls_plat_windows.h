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

MTERR HR2MR(_In_ HRESULT hr);
HRESULT MR2HR(_In_ MTERR mr);

#define CHKNUL(stmt)                                        \
{                                                           \
    if (NULL == (stmt))                                     \
    {                                                       \
        hr = HRESULT_FROM_WIN32(GetLastError());            \
        LOGFAIL(L"NULL", (stmt), hr);                       \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKWINOK(stmt)                                      \
{                                                           \
    hr = (stmt);                                            \
    if (hr != S_OK)                                         \
    {                                                       \
        LOGFAIL(L"!= S_OK", (stmt), hr);                    \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKWINOKM(stmt)                                     \
{                                                           \
    hr = (stmt);                                            \
    mr = HR2MR(hr);                                         \
    if (hr != S_OK)                                         \
    {                                                       \
        LOGFAIL(L"!= S_OK", (stmt), hr);                    \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKWIN(stmt)                                        \
{                                                           \
    if (!(stmt))                                            \
    {                                                       \
        hr = HRESULT_FROM_WIN32(GetLastError());            \
        LOGFAIL(L"FALSE", (stmt), hr);                      \
        goto error;                                         \
    }                                                       \
}                                                           \

#define CHKWINM(stmt)                                       \
{                                                           \
    if (!(stmt))                                            \
    {                                                       \
        hr = HRESULT_FROM_WIN32(GetLastError());            \
        mr = HR2MR(hr);                                     \
        LOGFAIL(L"FALSE", (stmt), hr);                      \
        goto error;                                         \
    }                                                       \
}                                                           \

class KeyAndProv
{
    public:
    KeyAndProv();
    ~KeyAndProv();

    KeyAndProv&
    operator=(
        _In_ const KeyAndProv& rOther);

    void Init(_In_ HCRYPTPROV hProv, _In_ BOOL fCallerFree = TRUE);

    _Check_return_
    _Ret_notnull_
    HCRYPTKEY
    GetKey() const
    {
        return m_hKey;
    }

    _Check_return_
    _Ret_notnull_
    HCRYPTPROV
    GetProv() const
    {
        return m_hProv;
    }

    void SetKey(_In_ HCRYPTKEY hKey);
    void Detach();

    private:
    void Release();

    HCRYPTPROV m_hProv;
    HCRYPTKEY m_hKey;
    BOOL m_fCallerFree;
};

HRESULT
EncryptBuffer(
    _In_ const ByteVector* pvbCleartext,
    _In_ HCRYPTKEY hKey,
    _In_ const CipherInfo* pCipherInfo,
    _In_opt_ const ByteVector* pvbIV,
    _Out_ ByteVector* pvbEncrypted);

HRESULT
DecryptBuffer(
    _In_ const ByteVector* pvbEncrypted,
    _In_ HCRYPTKEY hKey,
    _In_ const CipherInfo* pCipherInfo,
    _In_opt_ const ByteVector* pvbIV,
    _Out_ ByteVector* pvbDecrypted);

HRESULT
LookupCertificate(
    _In_ DWORD dwCertStoreFlags,
    _In_ PCWSTR wszStoreName,
    _In_ PCWSTR wszSubjectName,
    _Outptr_ PCCERT_CHAIN_CONTEXT* ppCertChain);

HRESULT
GetPrivateKeyFromCertificate(
    _In_ PCCERT_CONTEXT pCertContext,
    _Out_ KeyAndProv* pPrivateKey);

HRESULT
GetPublicKeyFromCertificate(
    _In_ PCCERT_CONTEXT pCertContext,
    _Out_ KeyAndProv* pPublicKey);

HRESULT
MTCertChainFromWinChain(
    _In_ PCCERT_CHAIN_CONTEXT pWinChain,
    _Out_ MT_CertificateList* pMTChain);

HRESULT
ImportSymmetricKey(
    _In_ const ByteVector* pvbKey,
    _In_ ALG_ID algID,
    _Out_ KeyAndProv* pKey);



class WindowsPublicKeyCipherer : public PublicKeyCipherer
{
    public:
    WindowsPublicKeyCipherer();
    ~WindowsPublicKeyCipherer() { }

    HRESULT
    Initialize(
        _In_ std::shared_ptr<KeyAndProv> spPublicKeyProv,
        _In_ std::shared_ptr<KeyAndProv> spPrivateKeyProv);

    HRESULT
    Initialize(_In_ PCCERT_CONTEXT pCertCContext);

    MTERR
    EncryptBufferWithPublicKey(
        _In_ const ByteVector* pvbCleartext,
        _Out_ ByteVector* pvbEncrypted) const;

    MTERR
    DecryptBufferWithPrivateKey(
        _In_ const ByteVector* pvbEncrypted,
        _Out_ ByteVector* pvbDecrypted) const;

    MTERR
    EncryptBufferWithPrivateKey(
        _In_ const ByteVector* pvbCleartext,
        _Out_ ByteVector* pvbEncrypted) const;

    private:
    _Check_return_
    _Ret_notnull_
    HCRYPTKEY
    GetPublicKey() const
    {
        return GetPublicKeyAndProv()->GetKey();
    }

    _Check_return_
    _Ret_notnull_
    HCRYPTKEY
    GetPrivateKey() const
    {
        return GetPrivateKeyAndProv()->GetKey();
    }

    _Check_return_
    _Ret_notnull_
    std::shared_ptr<KeyAndProv>
    GetPrivateKeyAndProv() const
    {
        return m_spPrivateKeyProv;
    }

    _Check_return_
    _Ret_notnull_
    std::shared_ptr<KeyAndProv>
    GetPublicKeyAndProv() const
    {
        return m_spPublicKeyProv;
    }

    std::shared_ptr<KeyAndProv> m_spPublicKeyProv;
    std::shared_ptr<KeyAndProv> m_spPrivateKeyProv;
};

class WindowsSymmetricCipherer : public SymmetricCipherer
{
    public:
    WindowsSymmetricCipherer();
    ~WindowsSymmetricCipherer() { }

    MTERR
    SetCipherInfo(
        _In_ const ByteVector* pvbKey,
        _In_ const CipherInfo* pCipherInfo);

    MTERR
    EncryptBuffer(
        _In_ const ByteVector* pvbCleartext,
        _In_opt_ const ByteVector* pvbIV,
        _Out_ ByteVector* pvbEncrypted);

    MTERR
    DecryptBuffer(
        _In_ const ByteVector* pvbEncrypted,
        _In_opt_ const ByteVector* pvbIV,
        _Out_ ByteVector* pvbDecrypted);

    static
    HRESULT
    WindowsCipherAlgFromMTCipherAlg(
        _In_ CipherAlg alg,
        _Out_ ALG_ID* pAlgID);

    private:
    ACCESSORS_SP(KeyAndProv, Key, m_spKey);

    std::shared_ptr<KeyAndProv> m_spKey;
};

class WindowsHasher : public Hasher
{
    public:
    MTERR
    Hash(
        _In_ const HashInfo* pHashInfo,
        _In_ const ByteVector* pvbText,
        _Out_ ByteVector* pvbHash);

    MTERR
    HMAC(
        _In_ const HashInfo* pHashInfo,
        _In_ const ByteVector* pvbKey,
        _In_ const ByteVector* pvbText,
        _Out_ ByteVector* pvbHMAC);

    private:
    static
    HRESULT
    WindowsHashAlgFromMTHashInfo(
        _In_ const HashInfo* pHashInfo,
        _Out_ ALG_ID* pAlg);
};

}
#endif
