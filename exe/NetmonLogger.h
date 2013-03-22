#ifndef MTLS_EXE_NETMONLOGGER_H
#define MTLS_EXE_NETMONLOGGER_H
#include <windows.h>
#include "MungeTLS.h"

class NetmonLogger
{
    public:
    NetmonLogger();
    virtual ~NetmonLogger();

    HRESULT
    Initialize(
        _In_ PCWSTR wszPath);

    virtual
    HRESULT
    LogTraffic(
        _In_ bool fClientToServer,
        _In_ bool fActuallyEncrypted,
        _In_ const MungeTLS::ByteVector* pvbPayload);

    private:
    HANDLE m_hCapture;
    int m_cFrames;
};
#endif
