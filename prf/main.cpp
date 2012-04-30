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
#include <intsafe.h>

using namespace std;

struct PlaintextKey
{
    BLOBHEADER hdr;
    DWORD cbKeySize;
    BYTE rgbKeyData[1];
};

class KeyAndProv
{
    public:
    KeyAndProv();
    ~KeyAndProv();

    void Init(HCRYPTPROV hProv, BOOL fCallerFree);
    HCRYPTKEY GetKey() const { return m_hKey; }
    void SetKey(HCRYPTKEY hKey) { m_hKey = hKey; }
    HCRYPTPROV GetProv() const { return m_hProv; }
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
Hash(
    const std::vector<BYTE>* pvbText,
    std::vector<BYTE>* pvbHash);

HRESULT
ComputeHMAC(
    const std::vector<BYTE>* pvbKey,
    const std::vector<BYTE>* pvbText,
    std::vector<BYTE>* pvbHMAC);

HRESULT
WindowsHMAC(
    const KeyAndProv* pKP,
    const std::vector<BYTE>* pvbText,
    std::vector<BYTE>* pvbHMAC);

HRESULT
CreateFixedSymmetricKey(
    const vector<BYTE>* pvbBaseData,
    KeyAndProv* pKey);

HRESULT
ExportSymmetricKey(
    HCRYPTKEY hKey,
    vector<BYTE>* pvbKey);

HRESULT PrintByteVector(const vector<BYTE>* pvb)
{
     HRESULT hr = S_OK;
     ULONG cNum = 0;

     for_each(pvb->begin(), pvb->end(),
     [&cNum](BYTE b)
     {
         if ((cNum % 16) == 0 && cNum > 0)
         {
             wprintf(L"\n");
         }

         wprintf(L"%02X ", b);
         cNum++;
     });

     wprintf(L"\n");

     return hr;
} // end function PrintByteVector

HRESULT
CreateFixedSymmetricKey(
    const vector<BYTE>* pvbBaseData,
    KeyAndProv* pKey)
{
    HRESULT hr = S_OK;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;
    KeyAndProv kp;

    wprintf(L"create key\n");

    if (!CryptAcquireContextW(
             &hProv,
             L"symenc_key",
             MS_ENH_RSA_AES_PROV_W,
             PROV_RSA_FULL,
             0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContextW(
                     &hProv,
                     L"symenc_key",
                     MS_ENH_RSA_AES_PROV_W,
                     PROV_RSA_FULL,
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

    wprintf(L"done acquire\n");

    kp.Init(hProv, TRUE);

    if (!CryptCreateHash(
             hProv,
             CALG_SHA_256,
             0,
             0,
             &hHash))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done create hash\n");

    // hard coded to use just the first byte of base data for the hash
    if (!CryptHashData(
             hHash,
             &pvbBaseData->front(),
             1,
             0))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    {
        vector<BYTE> vbHashValue;

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

        vbHashValue.resize(cbHashValue, 0x30);

        if (!CryptGetHashParam(
                 hHash,
                 HP_HASHVAL,
                 &vbHashValue.front(),
                 &cbHashValue,
                 0))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto error;
        }

        wprintf(L"hash value:\n");
        PrintByteVector(&vbHashValue);
    }

    if (!CryptDeriveKey(
             hProv,
             CALG_AES_128,
             hHash,
             CRYPT_EXPORTABLE,
             &hKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done derive\n");

    kp.SetKey(hKey);

    *pKey = kp;
    kp.Detach();

done:
    if (hHash != NULL)
    {
        CryptDestroyHash(hHash);
        hHash = NULL;
    }

    return hr;

error:
    goto done;
} // end function CreateFixedSymmetricKey

HRESULT
ExportSymmetricKey(
    HCRYPTKEY hKey,
    vector<BYTE>* pvbKey)
{
    HRESULT hr = S_OK;
    vector<BYTE> vbPlaintextKey;

    wprintf(L"export\n");

    DWORD cbKey = 0;
    CryptExportKey(
        hKey,
        0,
        PLAINTEXTKEYBLOB,
        0,
        NULL,
        &cbKey);

    if (GetLastError() != ERROR_MORE_DATA && GetLastError() != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"found we need %d bytes for exported key\n", cbKey);
    vbPlaintextKey.resize(cbKey, 0x28);

    if (!CryptExportKey(
            hKey,
            0,
            PLAINTEXTKEYBLOB,
            0,
            &vbPlaintextKey.front(),
            &cbKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    assert(vbPlaintextKey.size() == cbKey);

    PlaintextKey* pKeyInfo = reinterpret_cast<PlaintextKey*>(&vbPlaintextKey.front());

    wprintf(L"key size within blob is %d\n", pKeyInfo->cbKeySize);

    pvbKey->resize(pKeyInfo->cbKeySize, 0x23);
    pvbKey->assign(pKeyInfo->rgbKeyData, pKeyInfo->rgbKeyData + pKeyInfo->cbKeySize);

done:
    return hr;

error:
    pvbKey->clear();
    goto done;
} // end function ExportSymmetricKey

HRESULT
Hash(
    const vector<BYTE>* pvbText,
    vector<BYTE>* pvbHash
)
{
    HRESULT hr = S_OK;
    ALG_ID algID = CALG_SHA1;
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    DWORD cbText = 0;

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

        pvbHash->resize(cbHashValue, 0x30);

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
ComputeHMAC(
    const vector<BYTE>* pvbKey,
    const vector<BYTE>* pvbText,
    vector<BYTE>* pvbHMAC
)
{
    const size_t B = 64;
    const vector<BYTE> ipad(B, 0x36);
    const vector<BYTE> opad(B, 0x5C);

    HRESULT hr = S_OK;

    wprintf(L"compute hmac\n");

    vector<BYTE> vbInner;
    vector<BYTE> vbInnerHash;
    vector<BYTE> vbOuter;

    vector<BYTE> vbIpad_xor_K;
    vector<BYTE> vbOpad_xor_K;

    vector<BYTE> vbPaddedKey(*pvbKey);
    assert(pvbKey->size() <= B);

    vbPaddedKey.resize(B, 0);

    wprintf(L"padded key:\n");
    PrintByteVector(&vbPaddedKey);

    wprintf(L"ipad:\n");
    PrintByteVector(&ipad);

    wprintf(L"opad:\n");
    PrintByteVector(&opad);

    assert(vbPaddedKey.size() == ipad.size());
    vbIpad_xor_K.resize(vbPaddedKey.size());
    transform(ipad.begin(), ipad.end(), vbPaddedKey.begin(), vbIpad_xor_K.begin(), bit_xor<BYTE>());

    vbInner = vbIpad_xor_K;
    vbInner.insert(vbInner.end(), pvbText->begin(), pvbText->end());
    assert(vbInner.size() == vbIpad_xor_K.size() + pvbText->size());

    wprintf(L"inner:\n");
    PrintByteVector(&vbInner);

    hr = Hash(&vbInner, &vbInnerHash);
    if (hr != S_OK)
    {
        goto error;
    }

    assert(vbPaddedKey.size() == opad.size());
    vbOpad_xor_K.resize(vbPaddedKey.size());
    transform(opad.begin(), opad.end(), vbPaddedKey.begin(), vbOpad_xor_K.begin(), bit_xor<BYTE>());

    vbOuter = vbOpad_xor_K;
    vbOuter.insert(vbOuter.end(), vbInnerHash.begin(), vbInnerHash.end());

    wprintf(L"outer:\n");
    PrintByteVector(&vbOuter);

    hr = Hash(&vbOuter, pvbHMAC);
    if (hr != S_OK)
    {
        goto error;
    }

done:
    return hr;

error:
    pvbHMAC->clear();
    goto done;
} // end function ComputeHMAC

HRESULT
WindowsHMAC(
    const KeyAndProv* pKP,
    const std::vector<BYTE>* pvbText,
    std::vector<BYTE>* pvbHMAC
)
{
    HRESULT hr = S_OK;

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    DWORD cbHashValue = 0;

    HMAC_INFO hinfo = {0};

    hProv = pKP->GetProv();

    hinfo.HashAlgid = CALG_SHA1;

    if (!CryptCreateHash(
             hProv,
             CALG_HMAC,
             pKP->GetKey(),
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

    if (!CryptHashData(
             hHash,
             &pvbText->front(),
             pvbText->size(),
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

    pvbHMAC->resize(cbHashValue, 0x30);

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
    if (hProv != NULL)
    {
        CryptReleaseContext(hProv, 0);
        hProv = NULL;
    }

    return hr;

error:
    pvbHMAC->clear();
    goto done;
} // end function WindowsHMAC

HRESULT
TestHMAC()
{
    HRESULT hr = S_OK;

    vector<BYTE> vbBaseData(7, 0x23);
    vector<BYTE> vbText(5, 0x23);
    vector<BYTE> vbKey;
    vector<BYTE> vbHMAC;
    vector<BYTE> vbWinHMAC;
    KeyAndProv kp;

    hr = CreateFixedSymmetricKey(&vbBaseData, &kp);
    if (hr != S_OK)
    {
        goto error;
    }

    hr = ExportSymmetricKey(kp.GetKey(), &vbKey);

    wprintf(L"key:\n");
    PrintByteVector(&vbKey);

    hr = ComputeHMAC(&vbKey, &vbText, &vbHMAC);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"my hmac:\n");
    PrintByteVector(&vbHMAC);

    hr = WindowsHMAC(&kp, &vbText, &vbWinHMAC);
    if (hr != S_OK)
    {
        goto error;
    }

    wprintf(L"their hmac:\n");
    PrintByteVector(&vbWinHMAC);

    if (vbHMAC != vbWinHMAC)
    {
        wprintf(L"hmacs don't match\n");
        hr = S_FALSE;
    }

done:
    return hr;

error:
    goto done;
}

int
__cdecl
wmain(
    int argc,
    wchar_t* argv[])
{
    HRESULT hr = S_OK;

    vector<BYTE> vbText(5, 0x23);

    {
        wprintf(L"\n\n--------- hash ---------------\n");

        vector<BYTE> vbHash;

        PrintByteVector(&vbText);

        wprintf(L"\n\n");

        hr = Hash(&vbText, &vbHash);
        if (hr != S_OK)
        {
            goto error;
        }
    }

    {
        wprintf(L"\n\n--------- hmac ---------------\n");

        hr = TestHMAC();
    }

error:
    wprintf(L"error? %08LX\n", hr);
    return hr;
}

