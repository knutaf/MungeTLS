#include "precomp.h"

#include <windows.h>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <numeric>
#include <intsafe.h>
#include <memory>

#include "MungeTLS.h"
#include "MungeCrypto.h"
#include "wincrypt_help.h"

namespace MungeTLS
{

using namespace std;

struct PlaintextKey
{
    BLOBHEADER hdr;
    DWORD cbKeySize;
    BYTE rgbKeyData[1];
};

HRESULT
LookupCertificate(
    DWORD dwCertStoreFlags,
    PCWSTR wszStoreName,
    PCWSTR wszSubjectName,
    PCCERT_CHAIN_CONTEXT* ppCertChain)
{
    HRESULT hr = S_OK;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CHAIN_CONTEXT pCertChain = NULL;
    CERT_CHAIN_PARA chainPara = {0};

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

    chainPara.cbSize = sizeof(chainPara);
    // indicates not to use this member
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;

    if (!CertGetCertificateChain(
             NULL,
             pCertContext,
             NULL,
             NULL,
             &chainPara,
             0,
             NULL,
             &pCertChain))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    *ppCertChain = pCertChain;

done:
    if (pCertContext != NULL)
    {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    if (hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
        hCertStore = NULL;
    }

    return hr;

error:
    if (pCertChain != NULL)
    {
        CertFreeCertificateChain(pCertChain);
        pCertChain = NULL;
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
    ByteVector vbPublicKeyInfo;
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

    ResizeVector(&vbPublicKeyInfo, cbPublicKeyInfo);
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

    wprintf(L"done export pub:\n");

    PrintByteVector(&vbPublicKeyInfo);

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
EncryptBuffer(
    const ByteVector* pvbCleartext,
    HCRYPTKEY hKey,
    const CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted)
{
    HRESULT hr = S_OK;
    DWORD cb = 0;
    DWORD dwBufLen = 0;
    BOOL fFinal = TRUE;
    HCRYPTKEY hKeyNew = hKey;
    const CipherType cipherType = pCipherInfo->type;

    wprintf(L"encrypting\n");

    if (cipherType == CipherType_Asymmetric_Block)
    {
        fFinal = TRUE;
    }
    else if (cipherType == CipherType_Block)
    {
        fFinal = FALSE;

        wprintf(L"setting IV to:\n");
        PrintByteVector(pvbIV);

        if (!CryptSetKeyParam(
                 hKey,
                 KP_IV,
                 &pvbIV->front(),
                 0))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        wprintf(L"duplicating key\n");
        if (!CryptDuplicateKey(
                 hKey,
                 NULL,
                 0,
                 &hKeyNew))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }
    }
    else if (cipherType == CipherType_Stream)
    {
        fFinal = FALSE;
    }
    else
    {
        assert(false);
    }

    hr = SizeTToDWord(pvbCleartext->size(), &cb);
    if (hr != S_OK)
    {
        goto error;
    }

    CryptEncrypt(
             hKeyNew,
             NULL,
             fFinal,
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

    *pvbEncrypted = *pvbCleartext;
    ResizeVector(pvbEncrypted, cb);

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
             hKeyNew,
             NULL,
             fFinal,
             0,
             &pvbEncrypted->front(),
             &cb,
             dwBufLen))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done encrypt\n");

    assert(cb == pvbEncrypted->size());

    if (cipherType == CipherType_Asymmetric_Block)
    {
        // CryptEncrypt returns in little-endian
        *pvbEncrypted = ReverseByteOrder(pvbEncrypted);
    }

done:
    return hr;

error:
    pvbEncrypted->clear();
    goto done;
} // end function EncryptBuffer

HRESULT
DecryptBuffer(
    const ByteVector* pvbEncrypted,
    HCRYPTKEY hKey,
    const CipherInfo* pCipherInfo,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted)
{
    HRESULT hr = S_OK;
    DWORD cb;
    BOOL fFinal;
    HCRYPTKEY hKeyNew = hKey;

    wprintf(L"decrypting. ciphertext (%d bytes):\n", pvbEncrypted->size());
    PrintByteVector(pvbEncrypted);

    if (pCipherInfo->type == CipherType_Asymmetric_Block)
    {
        assert(pvbIV == nullptr);

        // CryptDecrypt expects input in little endian
        *pvbDecrypted = ReverseByteOrder(pvbEncrypted);
        fFinal = TRUE;
    }
    else if (pCipherInfo->type == CipherType_Block)
    {
        fFinal = TRUE;
        *pvbDecrypted = *pvbEncrypted;

        assert(pvbIV != nullptr);

        wprintf(L"setting IV to:\n");
        PrintByteVector(pvbIV);

        if (!CryptSetKeyParam(
                 hKey,
                 KP_IV,
                 &pvbIV->front(),
                 0))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        wprintf(L"duplicating key\n");
        if (!CryptDuplicateKey(
                 hKey,
                 NULL,
                 0,
                 &hKeyNew))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }
    }
    else
    {
        assert(pCipherInfo->type == CipherType_Stream);

        *pvbDecrypted = *pvbEncrypted;
        fFinal = FALSE;
    }

    hr = SizeTToDWord(pvbDecrypted->size(), &cb);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"actual decrypt\n");

    if (!CryptDecrypt(
             hKeyNew,
             0,
             fFinal,
             0,
             &pvbDecrypted->front(),
             &cb))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done initial decrypt: cb=%d, size=%d\n", cb, pvbDecrypted->size());
    ResizeVector(pvbDecrypted, cb);

    PrintByteVector(pvbDecrypted);

    /*
    ** for some reason, CryptDecrypt will return the correct plaintext block,
    ** but truncate the padding bytes to a single byte at the end. To expose
    ** a consistent view to our TLS protocol implementation that calls into
    ** this, we'll manually reconstruct the padding bytes here.
    */
    if (pCipherInfo->type == CipherType_Block)
    {
        BYTE cbPaddingLength = 0;
        hr = SizeTToByte(pCipherInfo->cbBlockSize - (cb % pCipherInfo->cbBlockSize), &cbPaddingLength);
        if (hr != S_OK)
        {
            goto error;
        }

        assert(pvbDecrypted->back() == cbPaddingLength);

        // repeat "padding length" number of bytes filled with padding length
        pvbDecrypted->insert(pvbDecrypted->end(), cbPaddingLength, cbPaddingLength);

        assert((pvbDecrypted->size() % pCipherInfo->cbBlockSize) == 0);

        wprintf(L"after padding fix: (%d)\n", pvbDecrypted->size());
        PrintByteVector(pvbDecrypted);
    }

done:
    if (hKeyNew != hKey)
    {
        CryptDestroyKey(hKeyNew);
        hKeyNew = NULL;
    }

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

KeyAndProv& KeyAndProv::operator=(const KeyAndProv& rOther)
{
    Clear();
    m_hProv = rOther.m_hProv;
    m_fCallerFree = rOther.m_fCallerFree;
    m_hKey = rOther.m_hKey;
    return *this;
} // end operator=

void
KeyAndProv::Init(
    HCRYPTPROV hProv,
    BOOL fCallerFree)
{
    Clear();

    m_hProv = hProv;
    m_fCallerFree = fCallerFree;
} // end function Init

void KeyAndProv::Clear()
{
    if (m_hKey != NULL)
    {
        CryptDestroyKey(m_hKey);
        m_hKey = NULL;
    }

    if (m_fCallerFree && m_hProv != NULL)
    {
        CryptReleaseContext(m_hProv, 0);
        m_hProv = NULL;
    }
} // end function Clear

KeyAndProv::~KeyAndProv()
{
    Clear();
} // end dtor KeyAndProv

void KeyAndProv::Detach()
{
    m_hProv = NULL;
    m_hKey = NULL;
    m_fCallerFree = FALSE;
} // end function Detach

void KeyAndProv::SetKey(HCRYPTKEY hKey)
{
    assert(GetProv());
    m_hKey = hKey;
} // end function SetKey


/*********** WindowsPublicKeyCipherer *****************/

WindowsPublicKeyCipherer::WindowsPublicKeyCipherer(
)
    : m_spPublicKeyProv(),
      m_spPrivateKeyProv()
{
} // end ctor WindowsPublicKeyCipherer

HRESULT
WindowsPublicKeyCipherer::Initialize(
    shared_ptr<KeyAndProv> spPublicKeyProv,
    shared_ptr<KeyAndProv> spPrivateKeyProv
)
{
    m_spPublicKeyProv = spPublicKeyProv;
    m_spPrivateKeyProv = spPrivateKeyProv;
    return S_OK;
} // end function Initialize

HRESULT
WindowsPublicKeyCipherer::Initialize(
    PCCERT_CONTEXT pCertContext
)
{
    HRESULT hr = S_OK;

    assert(m_spPrivateKeyProv.get() == nullptr);
    m_spPrivateKeyProv.reset(new KeyAndProv());

    hr = GetPrivateKeyFromCertificate(
             pCertContext,
             PrivateKeyAndProv().get());

    if (hr != S_OK)
    {
        goto error;
    }


    assert(PublicKeyAndProv().get() == nullptr);
    m_spPublicKeyProv.reset(new KeyAndProv());

    hr = GetPublicKeyFromCertificate(
             pCertContext,
             PublicKeyAndProv().get());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Initialize

HRESULT
WindowsPublicKeyCipherer::EncryptBufferWithPublicKey(
    const ByteVector* pvbCleartext,
    ByteVector* pvbEncrypted
) const
{
    HRESULT hr = S_OK;

    hr = MungeTLS::EncryptBuffer(
             pvbCleartext,
             PublicKey(),
             &c_CipherInfo_RSA,
             nullptr,
             pvbEncrypted);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EncryptBufferWithPublicKey

HRESULT
WindowsPublicKeyCipherer::DecryptBufferWithPrivateKey(
    const ByteVector* pvbEncrypted,
    ByteVector* pvbDecrypted
) const
{
    HRESULT hr = S_OK;

    hr = MungeTLS::DecryptBuffer(
             pvbEncrypted,
             PrivateKey(),
             &c_CipherInfo_RSA,
             nullptr,
             pvbDecrypted);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function DecryptBufferWithPrivateKey

HRESULT
WindowsPublicKeyCipherer::EncryptBufferWithPrivateKey(
    const ByteVector* pvbCleartext,
    ByteVector* pvbEncrypted
) const
{
    HRESULT hr = S_OK;

    hr = MungeTLS::EncryptBuffer(
             pvbCleartext,
             PrivateKey(),
             &c_CipherInfo_RSA,
             nullptr,
             pvbEncrypted);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EncryptBufferWithPrivateKey

/*********** WindowsPublicKeyCipherer *****************/

HRESULT
WindowsHasher::Hash(
    const HashInfo* pHashInfo,
    const ByteVector* pvbText,
    ByteVector* pvbHash
)
{
    HRESULT hr = S_OK;
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    DWORD cbText = 0;
    ALG_ID algID;

    hr = WindowsHashAlgFromMTHashInfo(pHashInfo, &algID);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptAcquireContextW(
             &hProv,
             L"some_hash",
             MS_ENH_RSA_AES_PROV_W,
             PROV_RSA_AES,
             0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContextW(
                     &hProv,
                     L"some_hash",
                     MS_ENH_RSA_AES_PROV_W,
                     PROV_RSA_AES,
                     CRYPT_NEWKEYSET))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto error;
            }

            wprintf(L"done acquire creatnew\n");
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }
    }

    if (!CryptCreateHash(
             hProv,
             algID,
             0,
             0,
             &hHash))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    hr = SizeTToDWord(pvbText->size(), &cbText);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptHashData(
             hHash,
             &pvbText->front(),
             cbText,
             0))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    {
        DWORD cbHashValue = 0;
        CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            NULL,
            &cbHashValue,
            0);

        if (GetLastError() != ERROR_MORE_DATA &&
            GetLastError() != ERROR_SUCCESS)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        ResizeVector(pvbHash, cbHashValue);

        if (!CryptGetHashParam(
                 hHash,
                 HP_HASHVAL,
                 &pvbHash->front(),
                 &cbHashValue,
                 0))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        assert(cbHashValue == pvbHash->size());
    }

done:
    if (hHash != NULL)
    {
        CryptDestroyHash(hHash);
        hHash = NULL;
    }

    return hr;

error:
    pvbHash->clear();
    goto done;
} // end function Hash

HRESULT
WindowsHasher::HMAC(
    const HashInfo* pHashInfo,
    const ByteVector* pvbKey,
    const ByteVector* pvbText,
    ByteVector* pvbHMAC
)
{
    HRESULT hr = S_OK;

    HCRYPTHASH hHash = NULL;
    DWORD cbHashValue = 0;
    DWORD cbTextSize = 0;
    KeyAndProv kp;
    HMAC_INFO hinfo = {0};

    hr = WindowsHashAlgFromMTHashInfo(pHashInfo, &hinfo.HashAlgid);
    if (hr != S_OK)
    {
        goto error;
    }

    // according to MSDN, keys imported for HMAC use RC2
    hr = ImportSymmetricKey(pvbKey, CALG_RC2, &kp);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptCreateHash(
             kp.GetProv(),
             CALG_HMAC,
             kp.GetKey(),
             0,
             &hHash))
    {
        wprintf(L"CryptCreateHash\n");
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    if (!CryptSetHashParam(
             hHash,
             HP_HMAC_INFO,
             reinterpret_cast<const BYTE*>(&hinfo),
             NULL))
    {
        wprintf(L"CryptSetHashParam\n");
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    hr = SizeTToDWord(pvbText->size(), &cbTextSize);
    if (hr != S_OK)
    {
        goto error;
    }

    if (!CryptHashData(
             hHash,
             &pvbText->front(),
             cbTextSize,
             0))
    {
        wprintf(L"CryptHashData\n");
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    CryptGetHashParam(
        hHash,
        HP_HASHVAL,
        NULL,
        &cbHashValue,
        0);

    if (GetLastError() != ERROR_MORE_DATA &&
        GetLastError() != ERROR_SUCCESS)
    {
        wprintf(L"CryptGetHashParam 1\n");
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    ResizeVector(pvbHMAC, cbHashValue);

    if (!CryptGetHashParam(
             hHash,
             HP_HASHVAL,
             &pvbHMAC->front(),
             &cbHashValue,
             0))
    {
        wprintf(L"CryptGetHashParam 2\n");
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

done:
    return hr;

error:
    pvbHMAC->clear();
    goto done;
} // end function HMAC

HRESULT
WindowsHasher::WindowsHashAlgFromMTHashInfo(
    const HashInfo* pHashInfo,
    ALG_ID* pAlg
)
{
    HRESULT hr = S_OK;

    if (pHashInfo->alg == HashAlg_MD5)
    {
        *pAlg = CALG_MD5;
    }
    else if (pHashInfo->alg == HashAlg_SHA1)
    {
        *pAlg = CALG_SHA1;
    }
    else if (pHashInfo->alg == HashAlg_SHA256)
    {
        *pAlg = CALG_SHA_256;
    }
    else
    {
        hr = MT_E_UNSUPPORTED_HASH;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function WindowsHashAlgFromMTHashInfo

WindowsSymmetricCipherer::WindowsSymmetricCipherer()
    : SymmetricCipherer(),
      m_spKey(nullptr)
{
} // end ctor WindowsSymmetricCipherer

HRESULT
WindowsSymmetricCipherer::Initialize(
    const ByteVector* pvbKey,
    const CipherInfo* pCipherInfo
)
{
    HRESULT hr = S_OK;
    ALG_ID algID;

    hr = SymmetricCipherer::Initialize(pvbKey, pCipherInfo);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = WindowsCipherAlgFromMTCipherAlg(
             pCipherInfo->alg,
             &algID);

    if (hr != S_OK)
    {
        goto error;
    }

    m_spKey = shared_ptr<KeyAndProv>(new KeyAndProv());

    hr = ImportSymmetricKey(
             pvbKey,
             algID,
             m_spKey.get());

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function Initialize

HRESULT
WindowsSymmetricCipherer::EncryptBuffer(
    const ByteVector* pvbCleartext,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted
)
{
    HRESULT hr = S_OK;

    hr = SymmetricCipherer::EncryptBuffer(
             pvbCleartext,
             pvbIV,
             pvbEncrypted);

    if (hr == E_NOTIMPL)
    {
        hr = MungeTLS::EncryptBuffer(
                 pvbCleartext,
                 (*Key())->GetKey(),
                 Cipher(),
                 pvbIV,
                 pvbEncrypted);
    }

    return hr;
} // end function EncryptBuffer

HRESULT
WindowsSymmetricCipherer::DecryptBuffer(
    const ByteVector* pvbEncrypted,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted
)
{
    HRESULT hr = S_OK;

    hr = SymmetricCipherer::DecryptBuffer(
             pvbEncrypted,
             pvbIV,
             pvbDecrypted);

    if (hr == E_NOTIMPL)
    {
        hr = MungeTLS::DecryptBuffer(
                 pvbEncrypted,
                 (*Key())->GetKey(),
                 Cipher(),
                 pvbIV,
                 pvbDecrypted);
    }

    return hr;
} // end function DecryptBuffer

HRESULT
WindowsSymmetricCipherer::WindowsCipherAlgFromMTCipherAlg(
    CipherAlg alg,
    ALG_ID* pAlgID
)
{
    HRESULT hr = S_OK;

    if (alg == CipherAlg_RC4_128)
    {
        *pAlgID = CALG_RC4;
    }
    else if (alg == CipherAlg_AES_128)
    {
        *pAlgID = CALG_AES_128;
    }
    else if (alg == CipherAlg_AES_256)
    {
        *pAlgID = CALG_AES_256;
    }
    else
    {
        hr = MT_E_UNSUPPORTED_CIPHER;
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function WindowsCipherAlgFromMTCipherAlg

HRESULT
ImportSymmetricKey(
    const ByteVector* pvbKey,
    ALG_ID algID,
    KeyAndProv* pKey
)
{
    HRESULT hr = S_OK;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    KeyAndProv kp;
    ByteVector vbPlaintextKey;
    PlaintextKey* pPlaintextKey;
    DWORD cbKeySize = 0;

    wprintf(L"import key\n");

    if (!CryptAcquireContextW(
             &hProv,
             NULL,
             MS_ENH_RSA_AES_PROV_W,
             PROV_RSA_AES,
             CRYPT_VERIFYCONTEXT))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    kp.Init(hProv, TRUE);

    ResizeVector(&vbPlaintextKey, sizeof(PlaintextKey) + pvbKey->size());

    pPlaintextKey = reinterpret_cast<PlaintextKey*>(&vbPlaintextKey.front());
    pPlaintextKey->hdr.bType = PLAINTEXTKEYBLOB;
    pPlaintextKey->hdr.bVersion = CUR_BLOB_VERSION;
    pPlaintextKey->hdr.aiKeyAlg = algID;

    hr = SizeTToDWord(pvbKey->size(), &(pPlaintextKey->cbKeySize));
    if (hr != S_OK)
    {
        goto error;
    }

    copy(pvbKey->begin(), pvbKey->end(), pPlaintextKey->rgbKeyData);

    hr = SizeTToDWord(vbPlaintextKey.size(), &cbKeySize);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"importing key of size %d\n", cbKeySize);

    if (!CryptImportKey(
             hProv,
             reinterpret_cast<const BYTE*>(pPlaintextKey),
             cbKeySize,
             NULL,
             CRYPT_IPSEC_HMAC_KEY,
             &hKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        wprintf(L"failed CryptImportKey: %08LX\n", hr);
        goto error;
    }

    kp.SetKey(hKey);

    *pKey = kp;
    kp.Detach();

done:
    return hr;

error:
    goto done;
} // end function ImportSymmetricKey

HRESULT
MTCertChainFromWinChain(
    PCCERT_CHAIN_CONTEXT pWinChain,
    MT_CertificateList* pMTChain
)
{
    // what does it mean to have 2 simple chains? no support for now
    assert(pWinChain->cChain == 1);

    // might relax this restriction later, but for now make sure we don't
    assert(pMTChain->Data()->empty());

    PCERT_SIMPLE_CHAIN pSimpleChain = pWinChain->rgpChain[0];

    for (DWORD i = 0; i < pSimpleChain->cElement; i++)
    {
        MT_ASN1Cert cert;

        cert.Data()->assign(
                 pSimpleChain->rgpElement[i]->pCertContext->pbCertEncoded,
                 pSimpleChain->rgpElement[i]->pCertContext->pbCertEncoded +
                   pSimpleChain->rgpElement[i]->pCertContext->cbCertEncoded);

        pMTChain->Data()->push_back(cert);
    }

    return S_OK;
} // end function MTCertChainFromWinChain

ByteVector
ReverseByteOrder(
    const ByteVector* pvb
)
{
    return ByteVector(pvb->rbegin(), pvb->rend());
} // end function ReverseByteOrder

}
