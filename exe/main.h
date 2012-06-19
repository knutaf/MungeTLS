#pragma once
#include <windows.h>
#include <string>
#include "MungeTLS.h"

using namespace MungeTLS;

class DummyServer : public ITLSListener
{
    public:
    DummyServer()
        : m_vbPendingSends(),
          m_con(this),
          m_sPendingRequest("")
    { }

    ~DummyServer() { }

    HRESULT ProcessConnections();
    HRESULT OnSend(const ByteVector* pvb);
    HRESULT OnApplicationData(const ByteVector* pvb);

    ACCESSORS(ByteVector*, PendingSends, &m_vbPendingSends);

    private:
    ACCESSORS(TLSConnection*, Connection, &m_con);
    ACCESSORS(std::string*, PendingRequest, &m_sPendingRequest);

    ByteVector m_vbPendingSends;
    TLSConnection m_con;
    std::string m_sPendingRequest;
};
