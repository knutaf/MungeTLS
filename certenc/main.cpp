#define UNICODE 1
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <process.h>
#include <fcntl.h>
#include <errno.h>
#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <algorithm>
#include <assert.h>
#include <wincrypt.h>

using namespace std;

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

KeyAndProv::KeyAndProv()
    : m_hProv(NULL),
      m_fCallerFree(FALSE),
      m_hKey(NULL)
{
}

void
KeyAndProv::Init(
    HCRYPTPROV hProv,
    BOOL fCallerFree)
{
    m_hProv = hProv;
    m_fCallerFree = fCallerFree;
}

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
}

void KeyAndProv::Detach()
{
    m_hProv = NULL;
    m_hKey = NULL;
    m_fCallerFree = FALSE;
}

HRESULT PrintByteVector(const vector<BYTE>* pvb);

HRESULT
EncryptBuffer(
    const vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbEncrypted);

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

HRESULT
DecryptBuffer(
    const vector<BYTE>* pvbEncrypted,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbDecrypted);

void Usage()
{
    printf("Usage: certenc.exe text\n");
}

HRESULT PrintByteVector(const vector<BYTE>* pvb)
{
     HRESULT hr = S_OK;

     for_each(pvb->begin(), pvb->end(),
     [](BYTE b)
     {
         wprintf(L"%02X ", b);
     });

     wprintf(L"\n");

     return hr;
} // end function PrintByteVector

HRESULT
EncryptBuffer(
    const vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbEncrypted)
{
    HRESULT hr = S_OK;
    DWORD cb = 0;

    wprintf(L"encrypting\n");

    cb = pvbCleartext->size();
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
    cb = pvbCleartext->size();

    if (!CryptEncrypt(
             hKey,
             NULL,
             TRUE,
             0,
             &pvbEncrypted->front(),
             &cb,
             pvbEncrypted->size()))
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
GetPrivateKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPrivateKey)
{
    HRESULT hr = S_OK;
    HCRYPTKEY hKey = NULL;
    KeyAndProv kp;

    HCRYPTPROV hProv = NULL;
    DWORD keySpec = 0;
    BOOL fCallerFree = FALSE;

    wprintf(L"get private\n");

    if (!CryptAcquireCertificatePrivateKey(
             pCertContext,
             CRYPT_ACQUIRE_SILENT_FLAG,
             NULL,
             &hProv,
             &keySpec,
             &fCallerFree))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    kp.Init(hProv, fCallerFree);

    if (keySpec != AT_KEYEXCHANGE)
    {
        wprintf(L"got unexpected keyspec: %u\n", keySpec);
        hr = E_FAIL;
        goto error;
    }

    wprintf(L"done privkey\n");

    // gets the actual private key handle
    if (!CryptGetUserKey(
             hProv,
             AT_KEYEXCHANGE,
             &hKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    kp.SetKey(hKey);

    *pPrivateKey = kp;
    kp.Detach();

    wprintf(L"done getuserkey\n");

done:
    return hr;

error:
    goto done;
} // end function GetPrivateKeyFromCertificate

HRESULT
GetPublicKeyFromCertificate(
    PCCERT_CONTEXT pCertContext,
    KeyAndProv* pPublicKey)
{
    HRESULT hr = S_OK;
    HCRYPTPROV hProv = NULL;
    HCRYPTPROV hPubProv = NULL;
    BOOL fCallerFree = FALSE;
    HCRYPTKEY hPubKey = NULL;
    vector<BYTE> vbPublicKeyInfo;
    KeyAndProv kp;

    wprintf(L"get public\n");

    DWORD keySpec;
    if (!CryptAcquireCertificatePrivateKey(
             pCertContext,
             CRYPT_ACQUIRE_SILENT_FLAG,
             NULL,
             &hProv,
             &keySpec,
             &fCallerFree))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    kp.Init(hProv, fCallerFree);

    if (keySpec != AT_KEYEXCHANGE)
    {
        wprintf(L"got unexpected keyspec: %u\n", keySpec);
        hr = E_FAIL;
        goto error;
    }

    wprintf(L"done privkey\n");

    DWORD cbPublicKeyInfo = 0;
    if (!CryptExportPublicKeyInfoEx(
             hProv,
             AT_KEYEXCHANGE,
             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
             szOID_RSA_RSA,
             0,
             NULL,
             NULL,
             &cbPublicKeyInfo))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"found we need %d bytes for public key info\n", cbPublicKeyInfo);

    vbPublicKeyInfo.resize(cbPublicKeyInfo, 0x24);
    if (!CryptExportPublicKeyInfoEx(
             hProv,
             AT_KEYEXCHANGE,
             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
             szOID_RSA_RSA,
             0,
             NULL,
             reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(&vbPublicKeyInfo.front()),
             &cbPublicKeyInfo))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done export pub\n");

    if (!CryptAcquireContextW(
             &hPubProv,
             L"pub_key",
             MS_ENHANCED_PROV,
             PROV_RSA_FULL,
             0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContextW(
                     &hPubProv,
                     L"pub_key",
                     MS_ENHANCED_PROV,
                     PROV_RSA_FULL,
                     CRYPT_NEWKEYSET))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto error;
            }

            wprintf(L"done acquire pub creatnew\n");
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }
    }

    wprintf(L"done acquire pub\n");

    if (!CryptImportPublicKeyInfo(
             hPubProv,
             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
             reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(&vbPublicKeyInfo.front()),
             &hPubKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done import pub\n");

    kp.SetKey(hPubKey);

    *pPublicKey = kp;
    kp.Detach();

done:
    if (fCallerFree && hProv != NULL)
    {
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
    }

    return hr;

error:
    goto done;
} // end function GetPublicKeyFromCertificate

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

    cb = pvbDecrypted->size();

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

HRESULT
EncryptDecryptTest(
    const vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKeyEncrypt,
    HCRYPTKEY hKeyDecrypt)
{
    HRESULT hr = S_OK;
    vector<BYTE> vbEncrypted;
    vector<BYTE> vbDecrypted;

    wprintf(L"cleartext:\n");
    PrintByteVector(pvbCleartext);

    hr = EncryptBuffer(
             pvbCleartext,
             hKeyEncrypt,
             &vbEncrypted);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"encrypted:\n");
    PrintByteVector(&vbEncrypted);

    hr = DecryptBuffer(
             &vbEncrypted,
             hKeyDecrypt,
             &vbDecrypted);

    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"decrypted:\n");
    PrintByteVector(&vbDecrypted);

    if (*pvbCleartext == vbDecrypted)
    {
        wprintf(L"cleartext and decrypted are the same\n");
        hr = S_OK;
    }
    else
    {
        wprintf(L"cleartext and decrypted didn't match\n");
        hr = S_FALSE;
    }

done:
    return hr;

error:
    goto done;
} // end function EncryptDecryptTest

int
__cdecl
wmain(
    int argc,
    wchar_t* argv[])
{
    if (argc > 1)
    {
        HRESULT hr = S_OK;
        PCCERT_CONTEXT pCertContext = NULL;
        KeyAndProv kpPublic;
        KeyAndProv kpPrivate;
        vector<BYTE> vbCleartext;

        hr = LookupCertificate(
                 CERT_SYSTEM_STORE_CURRENT_USER,
                 L"my",
                 L"mtls-test",
                 &pCertContext);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = GetPrivateKeyFromCertificate(
                 pCertContext,
                 &kpPrivate);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = GetPublicKeyFromCertificate(
                 pCertContext,
                 &kpPublic);

        if (hr != S_OK)
        {
            goto error;
        }

        vbCleartext.assign(reinterpret_cast<BYTE*>(argv[1]), reinterpret_cast<BYTE*>(argv[1] + wcslen(argv[1])));

        wprintf(L"\n\n");

        wprintf(L"encrypt with public, decrypt with private:\n");
        hr = EncryptDecryptTest(&vbCleartext, kpPublic.GetKey(), kpPrivate.GetKey());

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"\n\n");

        wprintf(L"encrypt with private, decrypt with public:\n");
        hr = EncryptDecryptTest(&vbCleartext, kpPrivate.GetKey(), kpPublic.GetKey());

        if (hr != S_OK)
        {
            goto error;
        }

error:
        if (pCertContext != NULL)
        {
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
        }

        wprintf(L"error? %08LX\n", hr);
        return hr;
    }
    else
    {
        Usage();
    }

    return 0;
}

