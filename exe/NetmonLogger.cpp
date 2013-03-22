#include "precomp.h"
#include <windows.h>
#include <objbase.h>
#include <Ntddndis.h>
#include <nmapi.h>
#include "MungeTLS.h"

using namespace std;
using namespace MungeTLS;

const NDIS_MEDIUM MediumMungeTLS = static_cast<NDIS_MEDIUM>(0x2323);

NetmonLogger::NetmonLogger()
    : m_hCapture(NULL),
      m_cFrames(0)
{
} // end ctor NetmonLogger

NetmonLogger::~NetmonLogger()
{
    if (m_hCapture != NULL)
    {
        NmCloseHandle(m_hCapture);
        m_hCapture = NULL;
    }
} // end dtor NetmonLogger

_Use_decl_annotations_
HRESULT
NetmonLogger::Initialize(
    PCWSTR wszPath
)
{
    HRESULT hr = S_OK;
    ULONG cbReturnSize = 0;

    if (m_hCapture != NULL)
    {
        hr = E_FAIL;
        goto error;
    }

    CHKWINERROR(NmCreateCaptureFile(
                    wszPath,
                    5000000,
                    0,
                    &m_hCapture,
                    &cbReturnSize));

done:
    return hr;

error:
    goto done;
} // end function Initialize

_Use_decl_annotations_
HRESULT
NetmonLogger::LogTraffic(
    bool fClientToServer,
    bool fActuallyEncrypted,
    const ByteVector* pvbPayload)
{
    const BYTE c_bFlags_ClientToServer = 0x0;
    const BYTE c_bFlags_ServerToClient = 0x1;
    const BYTE c_bFlags_Encrypted = 0x2;

    HRESULT hr = S_OK;

    HANDLE hFrame = NULL;
    BYTE bFrameFlags = 0;
    ByteVector vbFrame;
    ULONG cbFrameSize;

    if (fClientToServer)
    {
        bFrameFlags |= c_bFlags_ClientToServer;
    }
    else
    {
        bFrameFlags |= c_bFlags_ServerToClient;
    }

    if (fActuallyEncrypted)
    {
        bFrameFlags |= c_bFlags_Encrypted;
    }

    //
    // the special Netmon frame is composed of some metadata flags followed by
    // the payload
    //
    vbFrame.insert(vbFrame.begin(), bFrameFlags);
    vbFrame.insert(vbFrame.end(), pvbPayload->begin(), pvbPayload->end());

    CHKWINOK(SizeTToULong(vbFrame.size(), &cbFrameSize));

    CHKWINERROR(NmBuildRawFrameFromBuffer(
                    &vbFrame.front(),
                    static_cast<ULONG>(vbFrame.size()),
                    MediumMungeTLS,
                    m_cFrames,
                    &hFrame));

    CHKWINERROR(NmAddFrame(m_hCapture, hFrame));

    m_cFrames++;

done:
    if (hFrame != NULL)
    {
        NmCloseHandle(hFrame);
        hFrame = NULL;
    }

    return hr;

error:
    goto done;
} // end function LogTraffic
