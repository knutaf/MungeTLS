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
CreateRandomSymmetricKey(
    KeyAndProv* pKey);

HRESULT
CreateFixedSymmetricKey(
    const vector<BYTE>* pvbBaseData,
    KeyAndProv* pKey);

HRESULT
ExportSymmetricKey(
    HCRYPTKEY hKey,
    vector<BYTE>* pvbKey);

HRESULT
EncryptBuffer(
    const vector<BYTE>* pvbCleartext,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbEncrypted);

HRESULT
DecryptBuffer(
    const vector<BYTE>* pvbEncrypted,
    HCRYPTKEY hKey,
    vector<BYTE>* pvbDecrypted);

void Usage()
{
    printf("Usage: symenc.exe text\n");
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
CreateRandomSymmetricKey(
    KeyAndProv* pKey)
{
    HRESULT hr = S_OK;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    KeyAndProv kp;

    wprintf(L"create key\n");

    if (!CryptAcquireContextW(
             &hProv,
             L"symenc_key",
             MS_ENH_RSA_AES_PROV_W,
             PROV_RSA_AES,
             0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContextW(
                     &hProv,
                     L"symenc_key",
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

    wprintf(L"done acquire\n");

    if (!CryptGenKey(
             hProv,
             CALG_AES_128,
             CRYPT_EXPORTABLE,
             &hKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto error;
    }

    wprintf(L"done gen\n");

    kp.SetKey(hKey);

    *pKey = kp;
    kp.Detach();

done:
    return hr;

error:
    goto done;
} // end function CreateRandomSymmetricKey

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
             PROV_RSA_AES,
             0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContextW(
                     &hProv,
                     L"symenc_key",
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

    wprintf(L"done acquire\n");

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
TestEncryptDecrypt(
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
        wprintf(L"PASS: cleartext and decrypted are the same\n");
        hr = S_OK;
    }
    else
    {
        wprintf(L"FAIL: cleartext and decrypted didn't match\n");
        hr = S_FALSE;
    }

done:
    return hr;

error:
    goto done;
} // end function TestEncryptDecrypt

HRESULT
TestKeyGeneration()
{
    HRESULT hr = S_OK;
    HRESULT hrResult = S_OK;

    {
        KeyAndProv kp1;
        KeyAndProv kp2;
        vector<BYTE> vbKey1;
        vector<BYTE> vbKey2;

        wprintf(L"\n\n------------- Testing Random Key Generation ------------\n");

        hr = CreateRandomSymmetricKey(&kp1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp1.GetKey(), &vbKey1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = CreateRandomSymmetricKey(&kp2);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp2.GetKey(), &vbKey2);
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"random keys:\n");
        PrintByteVector(&vbKey1);
        wprintf(L"\n");
        PrintByteVector(&vbKey2);

        if (vbKey1 == vbKey2)
        {
            hrResult = S_FALSE;
            wprintf(L"FAIL: random keys are the same:\n");
        }
        else
        {
            wprintf(L"PASS: random keys are different\n");
        }
    }



    {
        vector<BYTE> vbBaseData(10, 0x29);
        KeyAndProv kp1;
        KeyAndProv kp2;
        vector<BYTE> vbKey1;
        vector<BYTE> vbKey2;
        wprintf(L"\n\n------------- Testing Same Fixed Key Generation ------------\n");

        hr = CreateFixedSymmetricKey(&vbBaseData, &kp1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp1.GetKey(), &vbKey1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = CreateFixedSymmetricKey(&vbBaseData, &kp2);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp2.GetKey(), &vbKey2);
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"fixed keys:\n");
        PrintByteVector(&vbKey1);
        wprintf(L"\n");
        PrintByteVector(&vbKey2);

        if (vbKey1 == vbKey2)
        {
            wprintf(L"PASS: fixed keys are the same\n");
        }
        else
        {
            wprintf(L"FAIL: fixed keys are different\n");
            hrResult = S_FALSE;
        }
    }

    {
        vector<BYTE> vbBaseData1(10, 0xd);
        vector<BYTE> vbBaseData2(10, 0xe);
        KeyAndProv kp1;
        KeyAndProv kp2;
        vector<BYTE> vbKey1;
        vector<BYTE> vbKey2;
        wprintf(L"\n\n------------- Testing Different Fixed Key Generation ------------\n");

        hr = CreateFixedSymmetricKey(&vbBaseData1, &kp1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp1.GetKey(), &vbKey1);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = CreateFixedSymmetricKey(&vbBaseData2, &kp2);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kp2.GetKey(), &vbKey2);
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"fixed keys:\n");
        PrintByteVector(&vbKey1);
        wprintf(L"\n");
        PrintByteVector(&vbKey2);

        if (vbKey1 == vbKey2)
        {
            wprintf(L"FAIL: fixed keys are the same\n");
            hrResult = S_FALSE;
        }
        else
        {
            wprintf(L"PASS: fixed keys are different\n");
        }
    }

done:
    return hrResult;

error:
    hrResult = hr;
    goto done;
} // end function TestKeyGeneration

int
__cdecl
wmain(
    int argc,
    wchar_t* argv[])
{
    if (argc > 1)
    {
        HRESULT hr = S_OK;
        KeyAndProv kpRandom;
        KeyAndProv kpFixed;
        vector<BYTE> vbCleartext;
        vector<BYTE> vbExportedKey;

        hr = TestKeyGeneration();
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"\n\n--------- random key - encrypt and decrypt ---------------\n");
        hr = CreateRandomSymmetricKey(&kpRandom);

        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kpRandom.GetKey(), &vbExportedKey);
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"exported random key:\n");
        PrintByteVector(&vbExportedKey);

        vbCleartext.assign(reinterpret_cast<BYTE*>(argv[1]), reinterpret_cast<BYTE*>(argv[1] + wcslen(argv[1])));

        hr = TestEncryptDecrypt(&vbCleartext, kpRandom.GetKey(), kpRandom.GetKey());
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"\n\n--------- fixed key - encrypt and decrypt ---------------\n");
        hr = CreateFixedSymmetricKey(&vbCleartext, &kpFixed);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ExportSymmetricKey(kpFixed.GetKey(), &vbExportedKey);
        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"exported fixed key:\n");
        PrintByteVector(&vbExportedKey);

        hr = TestEncryptDecrypt(&vbCleartext, kpRandom.GetKey(), kpRandom.GetKey());

        if (hr != S_OK)
        {
            goto error;
        }


        wprintf(L"\n\n--------- mismatched keys - encrypt and decrypt ---------------\n");
        hr = TestEncryptDecrypt(&vbCleartext, kpRandom.GetKey(), kpFixed.GetKey());

        if (hr != NTE_BAD_DATA)
        {
            wprintf(L"FAIL: didn't get expected hr NTE_BAD DATA for decryption; got %08LX\n", hr);
            goto error;
        }
        else
        {
            wprintf(L"PASS: got expected hr %08LX for bad decryption\n", hr);
            hr = S_OK;
        }

error:
        wprintf(L"error? %08LX\n", hr);
        return hr;
    }
    else
    {
        Usage();
    }

    return 0;
}

