#include "precomp.h"

#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>

#include "MungeTLS.h"
#include "mtls_helper.h"

namespace MungeTLS
{

using namespace std;

HRESULT
LookupCertificate(
    DWORD dwCertStoreFlags,
    PCWSTR wszStoreName,
    PCWSTR wszSubjectName,
    PCCERT_CONTEXT* ppCertContext)
{
    HRESULT hr = S_OK;
    PCCERT_CONTEXT pCertContext = NULL;

    HCERTSTORE hCertStore = CertOpenStore(
                                CERT_STORE_PROV_SYSTEM_W,
                                0,
                                NULL,
                                dwCertStoreFlags,
                                wszStoreName);

    if (hCertStore == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done openstore\n");

    pCertContext = CertFindCertificateInStore(
                       hCertStore,
                       X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       0,
                       CERT_FIND_SUBJECT_STR_W,
                       wszSubjectName,
                       NULL);

    if (pCertContext == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    *ppCertContext = pCertContext;

done:
    if (hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
        hCertStore = NULL;
    }

    return hr;

error:
    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    goto done;
} // end function LookupCertificate

HRESULT
EncryptBuffer(
    const vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbEncrypted)
{
    HRESULT hr = S_OK;
    DWORD cb = 0;
    DWORD dwBufLen = 0;

    wprintf(L"encrypting\n");

    hr = SizeTToDWord(pvbCleartext->size(), &cb);
    if (hr != S_OK)
    {
        goto error;
    }

    CryptEncrypt(
             hKey,
             NULL,
             TRUE,
             0,
             NULL, // to get size
             &cb,
             1);

    wprintf(L"found we need %d bytes for ciphertext\n", cb);
    if (pvbCleartext->size() > cb)
    {
        wprintf(L"currently don't support cleartext bigger than one block\n");
        hr = E_NOTIMPL;
        goto error;
    }

    pvbEncrypted->assign(pvbCleartext->begin(), pvbCleartext->end());
    pvbEncrypted->resize(cb, 0x23);

    hr = SizeTToDWord(pvbCleartext->size(), &cb);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = SizeTToDWord(pvbEncrypted->size(), &dwBufLen);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptEncrypt(
             hKey,
             NULL,
             TRUE,
             0,
             &pvbEncrypted->front(),
             &cb,
             dwBufLen))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done encrypt\n");

    pvbEncrypted->resize(cb);

done:
    return hr;

error:
    pvbEncrypted->clear();
    goto done;
} // end function EncryptBuffer

HRESULT
DecryptBuffer(
    const vector<BYTE>* pvbEncrypted,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbDecrypted)
{
    HRESULT hr = S_OK;
    DWORD cb;

    wprintf(L"decrypting\n");

    pvbDecrypted->assign(pvbEncrypted->begin(), pvbEncrypted->end());

    hr = SizeTToDWord(pvbDecrypted->size(), &cb);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptDecrypt(
             hKey,
             0,
             TRUE,
             0,
             &pvbDecrypted->front(),
             &cb))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done decrypt: cb=%d, size=%d\n", cb, pvbDecrypted->size());

    assert(cb <= pvbDecrypted->size());
    pvbDecrypted->resize(cb);

done:
    return hr;

error:
    pvbDecrypted->clear();
    goto done;
} // end function DecryptBuffer


/*********** KeyAndProv *****************/

KeyAndProv::KeyAndProv()
    : m_hProv(NULL),
      m_fCallerFree(FALSE),
      m_hKey(NULL)
{
} // end ctor KeyAndProv

void
KeyAndProv::Init(
    HCRYPTPROV hProv,
    BOOL fCallerFree)
{
    m_hProv = hProv;
    m_fCallerFree = fCallerFree;
} // end function Init

KeyAndProv::~KeyAndProv()
{
    if (m_fCallerFree && m_hProv != NULL)
    {
        CryptReleaseContext(m_hProv, 0);
        m_hProv = NULL;
    }

    if (m_hKey != NULL)
    {
        CryptDestroyKey(m_hKey);
        m_hKey = NULL;
    }
} // end dtor KeyAndProv

void KeyAndProv::Detach()
{
    m_hProv = NULL;
    m_hKey = NULL;
    m_fCallerFree = FALSE;
} // end function Detach



/*********** WindowsPublicKeyCipherer *****************/

WindowsPublicKeyCipherer::WindowsPublicKeyCipherer(
    shared_ptr<KeyAndProv> spPublicKeyProv,
    shared_ptr<KeyAndProv> spPrivateKeyProv
)
    : m_spPublicKeyProv(spPublicKeyProv),
      m_spPrivateKeyProv(spPrivateKeyProv)
{
} // end ctor WindowsPublicKeyCipherer

HRESULT
WindowsPublicKeyCipherer::EncryptBufferWithPublicKey(
    const vector<BYTE>* pvbCleartext,
    vector<BYTE>* pvbEncrypted
) const
{
    return MungeTLS::EncryptBuffer(
               pvbCleartext,
               PublicKey(),
               pvbEncrypted);
} // end function EncryptBufferWithPublicKey

HRESULT
WindowsPublicKeyCipherer::DecryptBufferWithPrivateKey(
    const vector<BYTE>* pvbEncrypted,
    vector<BYTE>* pvbDecrypted
) const
{
    return MungeTLS::DecryptBuffer(
               pvbEncrypted,
               PrivateKey(),
               pvbDecrypted);
} // end function DecryptBufferWithPrivateKey

HRESULT
WindowsPublicKeyCipherer::EncryptBufferWithPrivateKey(
    const vector<BYTE>* pvbCleartext,
    vector<BYTE>* pvbEncrypted
) const
{
    return MungeTLS::EncryptBuffer(
               pvbCleartext,
               PrivateKey(),
               pvbEncrypted);
} // end function EncryptBufferWithPrivateKey

}
