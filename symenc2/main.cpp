#define UNICODE 1
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <process.h>
#include <errno.h>
#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <algorithm>
#include <assert.h>
#include <wincrypt.h>
#include "mungetls.h"
#include "mtls_plat_windows.h"

using namespace std;
using namespace MungeTLS;

HRESULT PrintByteVector(const ByteVector* pvb)
{
     for_each(pvb->begin(), pvb->end(),
     [](BYTE b)
     {
         wprintf(L"%02X ", b);
     });

     wprintf(L"\n");

     return S_OK;
} // end function PrintByteVector

BYTE c_pvKey[] = { 0x52, 0x28, 0x35, 0x64, 0xD4, 0x17, 0x30, 0x88, 0x2E, 0x73, 0x7C, 0x88, 0x0C, 0x53, 0xEB, 0x95 };

BYTE c_pvPlaintext[] = {
0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
0x11, 0x12, 0x13, 0x14, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

int
__cdecl
wmain(
    int argc,
    wchar_t* argv[])
{
    HRESULT hr = S_OK;

    ByteVector vbKey(c_pvKey, c_pvKey + ARRAYSIZE(c_pvKey));

    ByteVector vbCleartext(c_pvPlaintext, c_pvPlaintext + ARRAYSIZE(c_pvPlaintext));

    {
        ByteVector vbEnc;
        KeyAndProv kp;
        ByteVector vbIV(c_CipherInfo_AES_128.cbIVSize, 0x01);

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kp);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV,
                 &vbEnc);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"encrypted:\n");
        PrintByteVector(&vbEnc);
    }

    wprintf(L"\n\n");

    {
        ByteVector vbEnc;
        KeyAndProv kp;
        ByteVector vbIV(c_CipherInfo_AES_128.cbIVSize, 0x01);

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kp);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV,
                 &vbEnc);
        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV,
                 &vbEnc);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"encrypted:\n");
        PrintByteVector(&vbEnc);
    }

    wprintf(L"\n\n");

    {
        ByteVector vbEnc;
        ByteVector vbDec;
        KeyAndProv kp;
        KeyAndProv kpDec;
        ByteVector vbIV(c_CipherInfo_AES_128.cbIVSize, 0x01);
        ByteVector vbIV2(c_CipherInfo_AES_128.cbIVSize, 0x02);
        ByteVector vbIV3(c_CipherInfo_AES_128.cbIVSize, 0x03);

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kp);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kpDec);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV,
                 &vbEnc);
        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV2,
                 &vbEnc);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"encrypted:\n");
        PrintByteVector(&vbEnc);

        hr = DecryptBuffer(
                 &vbEnc,
                 kpDec.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV2,
                 &vbDec);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"decrypted:\n");
        PrintByteVector(&vbDec);
    }

    wprintf(L"\n\n");

    {
        ByteVector vbEnc;
        ByteVector vbDec;
        KeyAndProv kp;
        KeyAndProv kpDec;
        ByteVector vbIV(c_CipherInfo_AES_128.cbIVSize, 0x01);
        ByteVector vbIV2(c_CipherInfo_AES_128.cbIVSize, 0x02);
        ByteVector vbIV3(c_CipherInfo_AES_128.cbIVSize, 0x03);

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kp);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = ImportSymmetricKey(&vbKey, CALG_AES_128, &kpDec);
        if (hr != S_OK)
        {
            goto error;
        }

        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV,
                 &vbEnc);
        hr = EncryptBuffer(
                 &vbCleartext,
                 kp.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV2,
                 &vbEnc);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"encrypted:\n");
        PrintByteVector(&vbEnc);

        hr = DecryptBuffer(
                 &vbEnc,
                 kpDec.GetKey(),
                 &c_CipherInfo_AES_128,
                 &vbIV3,
                 &vbDec);

        if (hr != S_OK)
        {
            goto error;
        }

        wprintf(L"decrypted:\n");
        PrintByteVector(&vbDec);
    }

done:
    wprintf(L"exiting with %08LX\n", hr);
    return hr;

error:
    goto done;
}

