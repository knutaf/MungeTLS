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
        : m_vPendingSends(),
          m_con(this), // not a copy ctor; taking this as an ITLSListener
          m_sPendingRequest(""),
          m_iCipherSelected(0),
          m_cMessages(0),
          m_cAppDataReceived(0),
          m_vbPendingAppData()
    { }

    ~DummyServer() { }

    HRESULT ProcessConnections();
    HRESULT OnSend(const ByteVector* pvb);
    HRESULT OnApplicationData(const ByteVector* pvb);
    HRESULT OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion);
    HRESULT OnSelectCipherSuite(MT_CipherSuite* pCipherSuite);
    HRESULT OnCreatingHandshakeMessage(MT_Handshake* pHandshake, DWORD* pfFlags);
    HRESULT OnEnqueuePlaintext(const MT_TLSPlaintext* pPlaintext);
    HRESULT OnReceivingPlaintext(const MT_TLSPlaintext* pPlaintext);
    HRESULT OnHandshakeComplete();

    HRESULT
    OnInitializeCrypto(
        MT_CertificateList* pCertChain,
        std::shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
        std::shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
        std::shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
        std::shared_ptr<Hasher>* pspHasher);

    ACCESSORS(std::vector<ByteVector>*, PendingSends, &m_vPendingSends);
    ACCESSORS(ByteVector*, PendingAppData, &m_vbPendingAppData);

    private:
    static const MT_CipherSuiteValue c_rgCipherSuites[];

    ACCESSORS(TLSConnection*, Connection, &m_con);
    ACCESSORS(std::string*, PendingRequest, &m_sPendingRequest);
    ACCESSORS(PCCERT_CHAIN_CONTEXT*, CertChain, &m_pCertChain);

    ACCESSORS(std::shared_ptr<WindowsPublicKeyCipherer>*, PubKeyCipherer, &m_spPubKeyCipherer);
    ACCESSORS(std::shared_ptr<WindowsSymmetricCipherer>*, ClientSymCipherer, &m_spClientSymCipherer);
    ACCESSORS(std::shared_ptr<WindowsSymmetricCipherer>*, ServerSymCipherer, &m_spServerSymCipherer);
    ACCESSORS(std::shared_ptr<WindowsHasher>*, HashInst, &m_spHasher);

    std::vector<ByteVector> m_vPendingSends;
    TLSConnection m_con;
    std::string m_sPendingRequest;
    PCCERT_CHAIN_CONTEXT m_pCertChain;
    ULONG m_iCipherSelected;
    ULONG m_cMessages;
    ULONG m_cAppDataReceived;
    ByteVector m_vbPendingAppData;

    std::shared_ptr<WindowsPublicKeyCipherer> m_spPubKeyCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spClientSymCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spServerSymCipherer;
    std::shared_ptr<WindowsHasher> m_spHasher;
};
