#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>
#include "MungeTLS.h"
#include "wincrypt_help.h"

using namespace MungeTLS;

class SimpleHTTPServer : public ITLSListener
{
    public:
    SimpleHTTPServer()
        : m_vPendingSends(),
          m_con(this), // not a copy ctor; taking this as an ITLSListener
          m_sPendingRequest(""),
          m_iCipherSelected(0),
          m_cMessages(0),
          m_cRequestsReceived(0),
          m_vbPendingAppData()
    { }

    ~SimpleHTTPServer() { }

    HRESULT ProcessConnections();
    HRESULT OnSend(const ByteVector* pvb);
    HRESULT OnReceivedApplicationData(const ByteVector* pvb);
    HRESULT OnSelectProtocolVersion(MT_ProtocolVersion* pProtocolVersion);
    HRESULT OnSelectCipherSuite(const MT_ClientHello* pClientHello, MT_CipherSuite* pCipherSuite);
    HRESULT OnCreatingHandshakeMessage(MT_Handshake* pHandshake, DWORD* pfFlags);
    HRESULT OnEnqueuePlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted);
    HRESULT OnReceivingPlaintext(const MT_TLSPlaintext* pPlaintext, bool fActuallyEncrypted);
    HRESULT OnHandshakeComplete();

    HRESULT
    OnInitializeCrypto(
        MT_CertificateList* pCertChain,
        std::shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
        std::shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
        std::shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
        std::shared_ptr<Hasher>* pspHasher);

    HRESULT
    OnReconcileSecurityVersion(
        MT_TLSCiphertext* pCiphertext,
        MT_ProtocolVersion::MTPV_Version connVersion,
        MT_ProtocolVersion::MTPV_Version recordVersion,
        MT_ProtocolVersion::MTPV_Version* pOverrideVersion);

    ACCESSORS(std::vector<ByteVector>*, PendingSends, &m_vPendingSends);
    ACCESSORS(ByteVector*, PendingResponse, &m_vbPendingAppData);

    private:
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
    ULONG m_cRequestsReceived;
    ByteVector m_vbPendingAppData;

    std::shared_ptr<WindowsPublicKeyCipherer> m_spPubKeyCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spClientSymCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spServerSymCipherer;
    std::shared_ptr<WindowsHasher> m_spHasher;
};
