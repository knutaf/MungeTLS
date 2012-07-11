#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>
#include "MungeTLS.h"
#include "wincrypt_help.h"

using namespace MungeTLS;

class DummyServer : public ITLSListener
{
    public:
    DummyServer()
        : m_vbPendingSends(),
          m_con(this), // not a copy ctor; taking this as an ITLSListener
          m_sPendingRequest(""),
          m_pCertChain(nullptr),
          m_spPubKeyCipherer(),
          m_spClientSymCipherer(),
          m_spServerSymCipherer(),
          m_spHasher()
    { }

    ~DummyServer();

    HRESULT ProcessConnections();
    HRESULT OnSend(const ByteVector* pvb);
    HRESULT OnApplicationData(const ByteVector* pvb);
    HRESULT OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion);
    HRESULT OnSelectCipherSuite(MT_CipherSuite* pCipherSuite);
    HRESULT GetCertificateChain(MT_CertificateList* pCertChain);

    ACCESSORS(ByteVector*, PendingSends, &m_vbPendingSends);

    private:
    ACCESSORS(TLSConnection*, Connection, &m_con);
    ACCESSORS(std::string*, PendingRequest, &m_sPendingRequest);
    ACCESSORS(PCCERT_CHAIN_CONTEXT*, CertChain, &m_pCertChain);

    ACCESSORS(std::shared_ptr<WindowsPublicKeyCipherer>*, PubKeyCipherer, &m_spPubKeyCipherer);
    ACCESSORS(std::shared_ptr<WindowsSymmetricCipherer>*, ClientSymCipherer, &m_spClientSymCipherer);
    ACCESSORS(std::shared_ptr<WindowsSymmetricCipherer>*, ServerSymCipherer, &m_spServerSymCipherer);
    ACCESSORS(std::shared_ptr<WindowsHasher>*, HashInst, &m_spHasher);

    ByteVector m_vbPendingSends;
    TLSConnection m_con;
    std::string m_sPendingRequest;
    PCCERT_CHAIN_CONTEXT m_pCertChain;

    std::shared_ptr<WindowsPublicKeyCipherer> m_spPubKeyCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spClientSymCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spServerSymCipherer;
    std::shared_ptr<WindowsHasher> m_spHasher;
};
