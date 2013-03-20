#ifndef MTLS_EXE_MAIN_H
#define MTLS_EXE_MAIN_H
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <memory>
#include "MungeTLS.h"
#include "mtls_plat_windows.h"

using namespace MungeTLS;

class SimpleHTTPServer : public ITLSServerListener
{
    public:
    SimpleHTTPServer(_In_ SOCKET sockClient)
        : m_vPendingSends(),
          m_con(this), // not a copy ctor; taking this as an ITLSServerListener
          m_sPendingRequest(""),
          m_iCipherSelected(0),
          m_cMessages(0),
          m_cRequestsReceived(0),
          m_vbPendingAppData(),
          m_sockClient(sockClient)
    { }

    ~SimpleHTTPServer() { }

    HRESULT ProcessConnection();
    HRESULT EnqueueSendApplicationData(_In_ const ByteVector* pvb);

    MTERR OnSend(_In_ const ByteVector* pvb);

    MTERR OnReceivedApplicationData(_In_ const ByteVector* pvb);

    MTERR
    OnInitializeCrypto(
        _Out_ MT_CertificateList* pCertChain,
        _Out_ std::shared_ptr<PublicKeyCipherer>* pspPubKeyCipherer,
        _Out_ std::shared_ptr<SymmetricCipherer>* pspClientSymCipherer,
        _Out_ std::shared_ptr<SymmetricCipherer>* pspServerSymCipherer,
        _Out_ std::shared_ptr<Hasher>* pspClientHasher,
        _Out_ std::shared_ptr<Hasher>* pspServerHasher);

    MTERR
    OnSelectProtocolVersion(
        _Inout_ MT_ProtocolVersion* pProtocolVersion);

    MTERR
    OnSelectCipherSuite(
        _In_ const MT_ClientHello* pClientHello,
        _Out_ MT_CipherSuite* pCipherSuite);

    MTERR
    OnCreatingHandshakeMessage(
        _Inout_ MT_Handshake* pHandshake,
        _Inout_ MT_UINT32* pfFlags);

    MTERR OnHandshakeComplete();

    MTERR
    OnEnqueuePlaintext(
        _Inout_ MT_TLSPlaintext* pPlaintext,
        _In_ bool fActuallyEncrypted);

    MTERR
    OnReceivingPlaintext(
        _Inout_ MT_TLSPlaintext* pPlaintext,
        _In_ bool fActuallyEncrypted);

    MTERR
    OnReconcileSecurityVersion(
        _In_ const MT_TLSCiphertext* pCiphertext,
        _In_ MT_ProtocolVersion::MTPV_Version connVersion,
        _In_ MT_ProtocolVersion::MTPV_Version recordVersion,
        _Out_ MT_ProtocolVersion::MTPV_Version* pOverrideVersion);

    ACCESSORS(std::vector<ByteVector>, PendingSends, m_vPendingSends);
    ACCESSORS(ByteVector, PendingResponse, m_vbPendingAppData);

    private:
    ACCESSORS(TLSConnection, Connection, m_con);
    ACCESSORS(std::string, PendingRequest, m_sPendingRequest);
    ACCESSORS(PCCERT_CHAIN_CONTEXT, CertChain, m_pCertChain);
    ACCESSORS(SOCKET, SockClient, m_sockClient);

    ACCESSORS_SP(WindowsPublicKeyCipherer, PubKeyCipherer, m_spPubKeyCipherer);
    ACCESSORS_SP(WindowsSymmetricCipherer, ClientSymCipherer, m_spClientSymCipherer);
    ACCESSORS_SP(WindowsSymmetricCipherer, ServerSymCipherer, m_spServerSymCipherer);
    ACCESSORS_SP(WindowsHasher, HashInst, m_spHasher);

    std::vector<ByteVector> m_vPendingSends;
    TLSConnection m_con;
    std::string m_sPendingRequest;
    PCCERT_CHAIN_CONTEXT m_pCertChain;
    ULONG m_iCipherSelected;
    ULONG m_cMessages;
    ULONG m_cRequestsReceived;
    ByteVector m_vbPendingAppData;
    SOCKET m_sockClient;

    std::shared_ptr<WindowsPublicKeyCipherer> m_spPubKeyCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spClientSymCipherer;
    std::shared_ptr<WindowsSymmetricCipherer> m_spServerSymCipherer;
    std::shared_ptr<WindowsHasher> m_spHasher;
};
#endif
