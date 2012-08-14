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

/*
** All the functions in this file are Windows implementations/wrappers of
** crypto related functions needed for TLS. MungeTLS as a whole abstracts the
** platform-specific portions so that none of these structures or functions are
** called directly in the code
*/

namespace MungeTLS
{

using namespace std;

/*
** taken from the comments for CryptImportKey (http://msdn.microsoft.com/en-us/library/windows/desktop/aa380207(v=vs.85).aspx)
** and is used to pass data to and from key import/export functions. hdr.type
** is PLAINTEXTKEYBLOB
*/
struct PlaintextKey
{
    BLOBHEADER hdr;
    DWORD cbKeySize;
    BYTE rgbKeyData[1];
};

/*
** dwCertStoreFlags tells user/machine store, like
** CERT_SYSTEM_STORE_CURRENT_USER
**
** wszStoreName is like "my"
** wszSubjectName is the subject the certificat is issued to
**
** I'm not sure this handles multiple certificates with the same subject well.
** from this, you get the whole cert chain that can be walked up to the root.
*/
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

/*
** given a cert context, fetch a crypto provider + the private key. Of course,
** you have to have imported the private key previously for this to work.
*/
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

    // this gets the crypto provider for the private key, not the key itself
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

    // signature keys not supported here
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

/*
** the hoops this function has to jump through to get the public key are just
** silly.
**
** 1. acquire the private key provider
** 2. use that to get the public key (???)
** 3. export the public key as a blob
** 4. import the public key into an ephemeral key container
**
** why can't we just get at the public key directly? I don't get it.
*/
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
    KeyAndProv kpPub;

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

    // fetch size needed for public key
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

    /*
    ** CRYPT_VERIFYCONTEXT, intuitively (/sarcasm), creates an ephemeral key
    ** container, perfect for holding these temporary keys for the lifetime of
    ** just this process
    */
    if (!CryptAcquireContextW(
             &hPubProv,
             NULL,
             MS_ENHANCED_PROV,
             PROV_RSA_FULL,
             CRYPT_VERIFYCONTEXT))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done acquire pub\n");

    kpPub.Init(hPubProv);

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

    kpPub.SetKey(hPubKey);
    *pPublicKey = kpPub;
    kpPub.Detach();

done:
    assert(kp.GetProv() == hProv);
    assert(kpPub.GetProv() == hPubProv || pPublicKey->GetProv() == hPubProv);
    return hr;

error:
    goto done;
} // end function GetPublicKeyFromCertificate

/*
** due to the massive amount of configuration and setup required in CryptAPI,
** the functions to encrypt and decrypt data, once you actually get to this
** point, are the same for pretty much all cipher types
*/
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

    /*
    ** asymmetric block, e.g. RSA public key encryption. we encypt one block,
    ** and that's it, so we set fFinal to true
    */
    if (cipherType == CipherType_Asymmetric_Block)
    {
        fFinal = TRUE;
    }

    /*
    ** block ciphers, e.g. AES-128. Unfortunately, I have no idea why you need
    ** to set fFinal to false for this. I figured it out through trial and
    ** error.
    **
    ** we have to do a trick for setting the IV that's documented along with
    ** CryptEncryptBuffer (http://msdn.microsoft.com/en-us/library/windows/desktop/aa379924(v=vs.85).aspx)
    **
    ** that is, the state of the key with respect to IV is not set until a
    ** "final" block has been encrypted, normally. to get around this, we can
    ** set the IV, then duplicate the key, which copies all pending changes
    ** into the new key.
    */
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

    /*
    ** stream ciphers, by definition, won't have any "final" data. we set this
    ** to false to keep the stream from resetting any internal state.
    */
    else if (cipherType == CipherType_Stream)
    {
        fFinal = FALSE;
    }

    // no other cipher types supported
    else
    {
        assert(false);
        hr = MT_E_UNSUPPORTED_CIPHER;
        goto error;
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

    /*
    ** pvbEncrypted is used as an in-out parameter that, ironically, starts as
    ** the cleartext on input and ends up as the ciphertext on output
    */
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

    // the actual encryption, finally
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

    /*
    ** CryptEncrypt returns in little-endian. not sure why we don't need to do
    ** this for regular block ciphers, but I guess maybe it has something to do
    ** with fFinal being FALSE for them? I've experimented, but I'm not sure.
    ** All I know is this happens to work. Ugh.
    */
    if (cipherType == CipherType_Asymmetric_Block)
    {
        *pvbEncrypted = ReverseByteOrder(pvbEncrypted);
    }

done:
    return hr;

error:
    pvbEncrypted->clear();
    goto done;
} // end function EncryptBuffer

// see notes above from EncryptBuffer
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

    /*
    ** what really makes me rage is that fFinal is TRUE for *decrypting* block
    ** ciphers, but FALSE for *encrypting* them. what is going on!?
    */
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
    else if (pCipherInfo->type == CipherType_Stream)
    {
        assert(pvbIV == nullptr);
        *pvbDecrypted = *pvbEncrypted;
        fFinal = FALSE;
    }
    else
    {
        assert(false);
        hr = MT_E_UNSUPPORTED_CIPHER;
        goto error;
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

    // resize in case our input vector was larger than needed
    assert(pvbDecrypted->size() >= cb);
    ResizeVector(pvbDecrypted, cb);

    PrintByteVector(pvbDecrypted);

    /*
    ** for some reason, CryptDecrypt will return the correct plaintext block,
    ** but truncate the padding bytes to a single byte at the end. To expose
    ** a consistent view to our TLS protocol implementation that calls into
    ** this, we'll manually reconstruct the padding bytes here.
    **
    ** As a reminder, the padding format is for the *value* of each padding
    ** byte to be the *number* of padding bytes needed, e.g. if 7 bytes of
    ** padding are needed, each of those padding bytes will contain the value 7
    */
    if (pCipherInfo->type == CipherType_Block)
    {
        BYTE cbPaddingLength = 0;

        /*
        ** the returned plaintext is comprised of one or more contiguous
        ** blocks, each of size pCipherInfo->cbBlockSize.
        **
        ** (cb % pCipherInfo->cbBlockSize) is the amount of data "sticking out"
        ** into the last, partial block. We subtract this from the block size
        ** to get the number of bytes of padding needed.
        **
        ** Example:
        **   pCipherInfo->cbBlockSize = 8
        **   cb = 13
        ** 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16
        **  J  K  L  M  N  O  P  Q  R  S  T  U 05 __ __ __ __
        **                                      ^
        **                                      +-- 5 bytes of padding needed
        ** (cb % pCipherInfo->cbBlockSize) == 3
        ** pCipherInfo->cbBlockSize - (cb % pCipherInfo->cbBlockSize) == 5
        ** confirmed: 5 bytes of padding needed.
        */
        hr = SizeTToByte(pCipherInfo->cbBlockSize - (cb % pCipherInfo->cbBlockSize), &cbPaddingLength);
        if (hr != S_OK)
        {
            goto error;
        }

        if (pvbDecrypted->back() != cbPaddingLength)
        {
            hr = MT_E_BAD_PADDING;
            goto error;
        }

        // repeat "padding length" number of bytes filled with padding length
        pvbDecrypted->insert(pvbDecrypted->end(), cbPaddingLength, cbPaddingLength);

        // final size should ALWAYS be a multiple of block length
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
    Release();
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
    Release();

    m_hProv = hProv;
    m_fCallerFree = fCallerFree;
} // end function Init

void KeyAndProv::Release()
{
    if (m_hKey != NULL)
    {
        CryptDestroyKey(m_hKey);
        m_hKey = NULL;
    }

    if (m_fCallerFree && m_hProv != NULL)
    {
        CryptReleaseContext(m_hProv, 0);
    }

    m_hProv = NULL;
} // end function Release

KeyAndProv::~KeyAndProv()
{
    Release();
} // end dtor KeyAndProv

void KeyAndProv::Detach()
{
    m_hProv = NULL;
    m_hKey = NULL;
    m_fCallerFree = FALSE;
} // end function Detach

void KeyAndProv::SetKey(HCRYPTKEY hKey)
{
    // only support tracking a key if we also track a provider
    assert(GetProv() != NULL);
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

    assert(m_spPrivateKeyProv == nullptr);
    m_spPrivateKeyProv.reset(new KeyAndProv());

    hr = GetPrivateKeyFromCertificate(
             pCertContext,
             PrivateKeyAndProv().get());

    if (hr != S_OK)
    {
        goto error;
    }


    assert(m_spPublicKeyProv == nullptr);
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


/*********** WindowsHasher *****************/

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
    KeyAndProv kp;

    // gotta call superclass implementation first. it might handle it
    hr = Hasher::Hash(pHashInfo, pvbText, pvbHash);
    if (hr == S_OK)
    {
        goto done;
    }

    hr = WindowsHashAlgFromMTHashInfo(pHashInfo, &algID);
    if (hr != S_OK)
    {
        goto error;
    }

    /*
    ** use the RSA/AES provider, the most fully featured one, and an ephemeral
    ** key container (as specified by CRYPT_VERIFYCONTEXT).
    */
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

    kp.Init(hProv);

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

    // actually adds the data to the hash
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
        // this is how to get the value of the hash. kinda roundabout. get size
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

        // gets the actual hash value
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

    // check if superclass handles the hash
    hr = Hasher::HMAC(pHashInfo, pvbKey, pvbText, pvbHMAC);
    if (hr == S_OK)
    {
        goto done;
    }

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

// maps between MungeTLS platform-agnostic hash alg values and windows ones
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


/*********** WindowsSymmetricCipherer *****************/

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

    if (hr == S_FALSE)
    {
        hr = S_OK;
        goto done;
    }
    else if (hr != S_OK)
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

    // check if superclass handles it
    hr = SymmetricCipherer::EncryptBuffer(
             pvbCleartext,
             pvbIV,
             pvbEncrypted);

    if (hr == S_OK)
    {
        goto done;
    }
    else if (hr != E_NOTIMPL)
    {
        goto error;
    }

    hr = MungeTLS::EncryptBuffer(
             pvbCleartext,
             (*Key())->GetKey(),
             Cipher(),
             pvbIV,
             pvbEncrypted);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function EncryptBuffer

HRESULT
WindowsSymmetricCipherer::DecryptBuffer(
    const ByteVector* pvbEncrypted,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted
)
{
    HRESULT hr = S_OK;

    // check if superclas handles it
    hr = SymmetricCipherer::DecryptBuffer(
             pvbEncrypted,
             pvbIV,
             pvbDecrypted);
    if (hr == S_OK)
    {
        goto done;
    }
    else if (hr != E_NOTIMPL)
    {
        goto error;
    }

    hr = MungeTLS::DecryptBuffer(
             pvbEncrypted,
             (*Key())->GetKey(),
             Cipher(),
             pvbIV,
             pvbDecrypted);

    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    goto done;
} // end function DecryptBuffer

// maps between MungeTLS platform-agnostic cipher alg values and windows ones
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
    else if (alg == CipherAlg_NULL)
    {
        hr = S_FALSE;
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

    // store key in ephemeral container (per CRYPT_VERIFYCONTEXT)
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

    kp.Init(hProv);

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

    // need to pass CRYPT_IPSEC_HMAC_KEY to allow long key lengths, per MSDN
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

// convert between windows specific type and MungeTLS platform agnostic one
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

        // copy out the value of each cert in the chain
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
