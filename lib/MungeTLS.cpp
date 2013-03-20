#include "precomp.h"
#include <vector>
#include <assert.h>
#include <algorithm>
#include <functional>
#include <stdlib.h>

#include "mtls_defs.h"
#include "MungeTLS.h"
#include "mtls_helper.h"

/*
** this is it. the big file with most of the important TLS implementation in
** it! here are some notes about the coding style
**
** ---------- gotos:
** the code uses gotos heavily in a very structured way. gotos are only used to
** jump to the cleanup block in a function, basically a minimal replacement for
** exceptions. when used, there are two labels: "done" and "error". if the code
** encounters an error, it jumps to the "error" label, under which some
** cleanup can be done, e.g. clearing out out-parameters. then it jumps UP to
** the "done" label, which does any cleanup that would always happen. the done
** label is placed above the goto label so that its cleanup code runs in the
** normal case too.
**
** ---------- parsing/serializing:
** A lot of the parsing and serializing code uses a few formulaic patterns. the
** TLS protocol consists of basically parsing byte fields and variable-length
** vectors. The parsing keeps track of a few variables that are moved along.
**
** - pv: "pointer to void" - always points to the next unparsed byte
** - cb: "count of bytes" - always contains the number of bytes from pv not yet
**     parsed
** - mr: the MTERR with the current success/fail error code
** - cbField: the count of bytes needed for the field currently being parsed
**
** pv and cb obviously always need to be kept in lock-step, which is why they
** are only ever manipulated using the ADVANCE_PARSE macro. in fact, the
** parsing is so formulaic that I've added additional macros that assume the
** presence of pv, cb, mr, cbField, and the goto: and done: labels to very
** succinctly do parsing and serializing tasks with minimal clutter. but yeah,
** they are macros, eww.
**
** ---------- long functions:
** a lot of functions in here are pretty long, and not segmented into many
** smaller functions. I chose to do this for bodies of code that do not have
** smaller parts I'd be likely to reuse. it saves having to test all of the
** smaller functions individually.
*/


namespace MungeTLS
{

using namespace std;

MTERR
ComputePRF_TLS12(
    _In_ Hasher* pHasher,
    _In_ const ByteVector* pvbSecret,
    _In_ const char* szLabel,
    _In_ const ByteVector* pvbSeed,
    _In_ size_t cbLengthDesired,
    _Out_ ByteVector* pvbPRF);

MTERR
ComputePRF_TLS10(
    _In_ Hasher* pHasher,
    _In_ const ByteVector* pvbSecret,
    _In_ const char* szLabel,
    _In_ const ByteVector* pvbSeed,
    _In_ size_t cbLengthDesired,
    _Out_ ByteVector* pvbPRF);

// same PRF used for both 1.0 and 1.1
auto ComputePRF_TLS11 = ComputePRF_TLS10;

// RFC-defined helper function for PRF
MTERR
PRF_P_hash(
    _In_ Hasher* pHasher,
    _In_ const HashInfo* pHashInfo,
    _In_ const ByteVector* pvbSecret,
    _In_ const ByteVector* pvbSeed,
    _In_ size_t cbMinimumLengthDesired,
    _Out_ ByteVector* pvbResult);

// RFC-defined helper function for PRF
MTERR
PRF_A(
    _In_ Hasher* pHasher,
    _In_ const HashInfo* pHashInfo,
    _In_ MT_UINT32 i,
    _In_ const ByteVector* pvbSecret,
    _In_ const ByteVector* pvbSeed,
    _Out_ ByteVector* pvbResult);


/*********** TLSConnection *****************/

_Use_decl_annotations_
TLSConnection::TLSConnection(ITLSServerListener* pServerListener)
    : m_currentConnection(),
      m_nextConnection(),
      m_pendingSends(),
      m_pServerListener(pServerListener)
{
} // end ctor TLSConnection

// one-time initialization for this object
_Use_decl_annotations_
MTERR_T
TLSConnection::Initialize()
{
    MTERR mr = MT_S_OK;

    // ensure we don't try to initialize more than once
    if (GetCurrConn()->GetPubKeyCipherer().get() != nullptr)
    {
        assert(false);
        mr = MT_E_FAIL;
        goto error;
    }

    // the current connection is used for parsing incoming records
    CHKOK(InitializeConnection(GetCurrConn()));

done:
    return mr;

error:
    goto done;
} // end function Initialize

/*
** this is the top-level parsing functionality, one of the most important parts
** of the code. The app calls this when they receive a chunk of data from the
** network, and this results in us doing any or all of the following:
**
** - parse out handshake messages and store internal state about the progress
**   of the handshake
** - queue up handshake messages of our own to be sent back to the client
** - generate one or more synchronous callbacks to the app to request input
**   into the handshake process
** - pass on application data to the app
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::HandleMessage(
    ByteVector* pvb
)
{
    MTERR mr = MT_S_OK;

    MT_TLSCiphertext ciphertext;
    MT_TLSPlaintext plaintext;

    if (pvb->empty())
    {
        mr = MT_S_FALSE;
        goto done;
    }

    /*
    ** absolutely first things first, hook up this message with this overall
    ** connection. the message primarily uses this to invoke ITLSServerListener
    ** functions to get more data from the app
    */
    CHKOK(ciphertext.SetConnection(this));
    CHKOK(ciphertext.SetServerListener(GetServerListener()));

    /*
    ** this first step just parses the record layer portion out of it. at this
    ** point, we assume the message is encrypted (though in actuality we might
    ** be using null-encryption for now), so we don't yet have enough info to
    ** decrypt it.
    */
    CHKOK(ciphertext.ParseFromVect(pvb));

    wprintf(L"successfully parsed TLSCiphertext. CT=%u\n", *ciphertext.GetContentType()->GetType());

    // this supplies the necessary information to decrypt the message
    CHKOK(ciphertext.SetEndpointParams(GetCurrConn()->GetReadParams()));

    CHKOK(ciphertext.Decrypt());

    { // just logging
        ByteVector vbDecryptedFragment;
        wprintf(L"decrypted fragment:\n");
        PrintByteVector(ciphertext.GetCipherFragment()->GetContent());
    }

    /*
    ** verify the integrity of the message using the MAC, if present. we could
    ** choose to present the app with a choice of proceeding despite a MAC
    ** failure, though in practice, when interoperating with any sane TLS
    ** implementation, this means that something has gone horribly wrong on
    ** either the client (their) or server (our) side.
    */
    CHKOK(ciphertext.CheckSecurity());

    // from here on, we operate on the plaintext version of the record
    CHKOK(ciphertext.ToTLSPlaintext(&plaintext));

    /*
    ** allow the app to know about the plaintext reciept, and whether it was
    ** actually encrypted, as opposed to null-encrypted.
    */
    CHKSUC(GetServerListener()->OnReceivingPlaintext(
             &plaintext,
             ciphertext.GetEndpointParams()->IsEncrypted()));

    // app could return "handled" or "ignored" or something non-fail
    mr = MT_S_OK;

    /*
    ** update the next IV, if we're using a block cipher. this can actually be
    ** done any time after we've parsed the ciphertext block (even before
    ** decryption). This only needs to be done for TLS 1.0 block ciphers
    ** because TLS 1.1 and later block ciphers have their IV packaged in
    ** plaintext along with the payload.
    */
    if (GetCurrConn()->GetReadParams()->GetCipher()->type == CipherType_Block)
    {
        switch (*GetCurrConn()->GetReadParams()->GetVersion())
        {
            // for TLS 1.0 next IV is the last block of the previous ciphertext
            case MT_ProtocolVersion::MTPV_TLS10:
            {
                MT_GenericBlockCipher_TLS10* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS10*>(ciphertext.GetCipherFragment().get());
                GetCurrConn()->GetReadParams()->GetIV()->assign(pBlockCipher->GetEncryptedContent()->end() - GetCurrConn()->GetReadParams()->GetCipher()->cbIVSize, pBlockCipher->GetEncryptedContent()->end());
            }
            break;

            /*
            ** for TLS 1.1 and 1.2, we track it just "for fun", since it's
            ** never actually used. we could use it for logging or something
            */
            case MT_ProtocolVersion::MTPV_TLS11:
            {
                MT_GenericBlockCipher_TLS11* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS11*>(ciphertext.GetCipherFragment().get());
                CHKOK(GetCurrConn()->GetReadParams()->SetIV(pBlockCipher->GetIV()));
            }
            break;

            case MT_ProtocolVersion::MTPV_TLS12:
            {
                MT_GenericBlockCipher_TLS12* pBlockCipher = static_cast<MT_GenericBlockCipher_TLS12*>(ciphertext.GetCipherFragment().get());
                CHKOK(GetCurrConn()->GetReadParams()->SetIV(pBlockCipher->GetIV()));
            }
            break;

            default:
            {
                assert(false);
            }
            break;
        }
    }

    // make sure that whatever IV was assigned is correct for the cipher suite
    assert(GetCurrConn()->GetReadParams()->GetIV()->size() == GetCurrConn()->GetReadParams()->GetCipher()->cbIVSize);

    /*
    ** with plaintext in hand, we do content-type specific handling. Most
    ** important for us are Handshake messages and ChangeCipherSpec messages,
    ** which drive the handshake process forward.
    */
    switch (*plaintext.GetContentType()->GetType())
    {
        case MT_ContentType::MTCT_Type_Handshake:
        {
            /*
            ** parse out one or more Handshake messages. A record layer message
            ** with a given content type can contain multiple contiguous
            ** messages of the same type in the fragment, since each inner
            ** message has the fields in place to identify its own length.
            **
            ** ParseStructures is templated by the structure type, e.g.
            ** MT_Handshake
            */
            vector<MT_Handshake> vStructures;
            CHKOK(ParseStructures(plaintext.GetFragment(), &vStructures));

            for (auto it = vStructures.begin(); it != vStructures.end(); it++)
            {
                CHKOK(HandleHandshakeMessage(&(*it)));
            }

            // sequence number is incremented AFTER processing a record
            CHKOK(GetCurrConn()->GetReadParams()->SetSequenceNumber(*GetCurrConn()->GetReadParams()->GetSequenceNumber() + 1));
        }
        break;

        /*
        ** the ChangeCipherSpec message is one of the most important. its
        ** receipt signals that the client is now going to switch to using the
        ** newly negotiated crypto suite for all subsequent messages. At this
        ** point, we copy over all the endpoint-specific data into the active
        ** connection, so this change in decryption will automatically just
        ** work
        */
        case MT_ContentType::MTCT_Type_ChangeCipherSpec:
        {
            // see note on first ParseStructures call about multiple structures
            vector<MT_ChangeCipherSpec> vStructures;
            CHKOK(ParseStructures(plaintext.GetFragment(), &vStructures));

            /*
            ** though we repeat this action for all the CCS messages, it's
            ** totally redundant to have more than one per direction in a
            ** handshake
            */
            if (vStructures.size() > 1)
            {
                wprintf(L"warning: received %Iu ChangeCipherSpec messages in a row\n", vStructures.size());
            }

            for (auto it = vStructures.begin(); it != vStructures.end(); it++)
            {
                wprintf(L"change cipher spec found: %u\n", *it->GetType());
                CHKOK(GetCurrConn()->SetReadParams(GetNextConn()->GetReadParams()));
            }

            /*
            ** after copying the pending endpoint state, which has not been
            ** touched, its sequence number should already be 0 without having
            ** to reset it
            */
            assert(*GetCurrConn()->GetReadParams()->GetSequenceNumber() == 0);
        }
        break;

        /*
        ** alert messages are basically errors and warnings. we don't really do
        ** much with them right now, just print them out.
        */
        case MT_ContentType::MTCT_Type_Alert:
        {
            // see note on first ParseStructures call about multiple structures
            vector<MT_Alert> vStructures;
            CHKOK(ParseStructures(plaintext.GetFragment(), &vStructures));

            for (auto it = vStructures.begin(); it != vStructures.end(); it++)
            {
                wprintf(L"got alert: %s\n", it->ToString().c_str());
            }

            // sequence number is incremented AFTER processing a record
            CHKOK(GetCurrConn()->GetReadParams()->SetSequenceNumber(*GetCurrConn()->GetReadParams()->GetSequenceNumber() + 1));
        }
        break;

        /*
        ** actual data for the application! we don't examine it at all, just
        ** pass it on in a callback to the app
        */
        case MT_ContentType::MTCT_Type_ApplicationData:
        {
            wprintf(L"application data:\n");
            PrintByteVector(plaintext.GetFragment());

            CHKSUC(GetServerListener()->OnReceivedApplicationData(plaintext.GetFragment()));
            mr = MT_S_OK;

            // sequence number is incremented AFTER processing a record
            CHKOK(GetCurrConn()->GetReadParams()->SetSequenceNumber(*GetCurrConn()->GetReadParams()->GetSequenceNumber() + 1));
        }
        break;

        default:
        {
            wprintf(L"unknown content type %02LX\n", *plaintext.GetContentType()->GetType());
            mr = MT_E_UNKNOWN_CONTENT_TYPE;
            goto error;
        }
        break;
    }

    /*
    ** inform the app of any messages we've queued up in the course of handling
    ** this block of data
    */
    CHKOK(SendQueuedMessages());

    /*
    ** the ciphertext object represents the raw data in pvb that we consumed,
    ** so it has to be smaller in size than pvb. also, erase that section from
    ** pvb, which the app is possibly appending data from the client into
    */
    assert(ciphertext.Length() <= pvb->size());
    pvb->erase(pvb->begin(), pvb->begin() + ciphertext.Length());

done:
    return mr;

error:
    goto done;
} // end function HandleMessage

_Use_decl_annotations_
MTERR_T
TLSConnection::HandleHandshakeMessage(
    const MT_Handshake* pHandshakeMessage
)
{
    MTERR mr = MT_S_OK;

    /*
    ** At the end of the handshake, as a security measure, each endpoint sends
    ** the other a hash of all the handshake-layer data it has sent and
    ** received, so we need to make a copy of the message here and archive it.
    ** NB: this archive does NOT contain any of the record-layer message--ONLY
    ** the handshake-layer message.
    */
    shared_ptr<MT_Handshake> spHandshakeMessage(new MT_Handshake());
    *spHandshakeMessage = *pHandshakeMessage;

    wprintf(L"handling Handshake of type=%u\n", *spHandshakeMessage->GetType());

    // handshake messages have their own inner "content type"
    switch (*spHandshakeMessage->GetType())
    {
        /*
        ** initial contact from the client that starts a new handshake. we
        ** parse out a bunch of information about what the client advertises
        ** its capabilities as
        */
        case MT_Handshake::MTH_ClientHello:
        {
            MT_ClientHello clientHello;

            CHKOK(clientHello.ParseFromVect(spHandshakeMessage->GetBody()));

            { // all logging stuff
                wprintf(L"parsed client hello message:\n");
                wprintf(L"version %04LX\n", *clientHello.GetClientVersion()->GetVersion());
                if (clientHello.GetSessionID()->Count() > 0)
                {
                    wprintf(L"session ID %u\n", clientHello.GetSessionID()->GetData()->at(0));
                }
                else
                {
                    wprintf(L"no session ID specified\n");
                }

                wprintf(L"%Iu crypto suites\n", clientHello.GetCipherSuites()->Count());

                wprintf(L"crypto suite 0: %02X %02X\n",
                       *clientHello.GetCipherSuites()->at(0)->at(0),
                       *clientHello.GetCipherSuites()->at(0)->at(1));

                wprintf(L"%Iu compression methods: %u\n",
                       clientHello.GetCompressionMethods()->Count(),
                       *clientHello.GetCompressionMethods()->at(0)->GetMethod());

                wprintf(L"%Iu extensions, taking %Iu bytes\n", clientHello.GetExtensions()->Count(), clientHello.GetExtensions()->Length());

                for (auto it = clientHello.GetExtensions()->GetData()->begin(); it != clientHello.GetExtensions()->GetData()->end(); it++)
                {
                    if (*it->GetExtensionType() == MT_Extension::MTEE_RenegotiationInfo)
                    {
                        wprintf(L"found renegotiation info:\n");
                        PrintByteVector(it->GetExtensionData()->GetData());
                    }
                }
            } // end logging

            CHKOK(StartNextHandshake(&clientHello));

            // archive the message for the Finished hash later
            GetNextConn()->GetHandshakeMessages()->push_back(spHandshakeMessage);

            /*
            ** allow the app to select what protocol version to send in
            ** response to the ClientHello, which has advertised a
            ** particular version already
            */
            {
                MT_ProtocolVersion protocolVersion = *clientHello.GetClientVersion();

                CHKSUC(GetServerListener()->OnSelectProtocolVersion(&protocolVersion));
                mr = MT_S_OK;

                CHKOK(GetNextConn()->GetReadParams()->SetVersion(*protocolVersion.GetVersion()));
                CHKOK(GetNextConn()->GetWriteParams()->SetVersion(*protocolVersion.GetVersion()));
            }

            CHKOK(GetNextConn()->SetClientRandom(clientHello.GetRandom()));

            /*
            ** A particularly important block: allow the app to select the
            ** cipher suite to be used, out of the list given by the
            ** client. if the app ignores the callback, MungeTLS has a way
            ** of picking its preferred choice
            */
            {
                MT_CipherSuite cipherSuite;

                CHKSUC(GetServerListener()->OnSelectCipherSuite(&clientHello, &cipherSuite));

                // pick the library's preference out of the client list
                if (mr == MT_S_LISTENER_IGNORED)
                {
                    MT_CipherSuiteValue ePreferred;
                    vector<MT_CipherSuiteValue> vValues(GetNextConn()->GetClientHello()->GetCipherSuites()->Count());

                    // just extracting the enum value from the raw data
                    transform(
                        GetNextConn()->GetClientHello()->GetCipherSuites()->GetData()->begin(),
                        GetNextConn()->GetClientHello()->GetCipherSuites()->GetData()->end(),
                        vValues.begin(),
                        [&mr](const MT_CipherSuite& rSuite)
                        {
                            if (mr == MT_S_OK)
                            {
                                MT_CipherSuiteValue eValue;
                                mr = rSuite.GetValue(&eValue);
                                return eValue;
                            }
                            else
                            {
                                return MTCS_UNKNOWN;
                            }
                        }
                    );

                    if (mr != MT_S_OK)
                    {
                        goto error;
                    }

                    CHKOK(ChooseBestCipherSuite(
                             &vValues,
                             GetCipherSuitePreference(),
                             &ePreferred));

                    CHKOK(cipherSuite.SetValue(ePreferred));
                }
                else
                {
                    mr = MT_S_OK;
                }

                assert(mr == MT_S_OK);

                /*
                ** same cipher suite is always used for read and write.
                ** it's important to note that setting this value here does
                ** NOT immediately switch over the library to encrypting/
                ** decrypting with this new cipher suite. this is all
                ** *pending* state until we receive and send ChangeCipherSpec
                ** messages.
                */
                CHKOK(GetNextConn()->GetReadParams()->SetCipherSuite(cipherSuite));
                CHKOK(GetNextConn()->GetWriteParams()->SetCipherSuite(cipherSuite));

                { // logging
                    MT_CipherSuiteValue eValue;
                    MTERR mrTemp = cipherSuite.GetValue(&eValue);
                    assert(mrTemp == MT_S_OK);

                    wprintf(L"chosen cipher suite %04LX\n", eValue);
                }
            }

            /*
            ** having recorded all that stuff and made some choices about
            ** protocol version and cipher suite, WELL ALLOW ME TO RETORT
            */
            CHKOK(RespondToClientHello());
        }
        break;

        /*
        ** the ClientKeyExchange message is where the public key
        ** cryptography takes place. the client has encrypted some data
        ** (actually, the Random value it sent earlier) with our public
        ** key, and we have to decrypt it, verify that it matches, and use
        ** it to generate the bulk cipher keys used in the rest of the
        ** connection
        **
        ** in theory, public/private key encryption could just be used for
        ** all traffic in the connection, but it is computationally far
        ** more expensive than symmetric key encryption, so it's merely
        ** used as a bootstrap
        */
        case MT_Handshake::MTH_ClientKeyExchange:
        {
            MT_KeyExchangeAlgorithm keyExchangeAlg;
            MT_ClientKeyExchange<MT_EncryptedPreMasterSecret> keyExchange;
            shared_ptr<MT_EncryptedPreMasterSecret> spExchangeKeys;
            MT_PreMasterSecret* pSecret = nullptr;

            /*
            ** at this point we should have exchanged hellos and therefore
            ** agreed on a single cipher suite, so the following call to
            ** get the key exchange algorithm can use either read or write
            ** params
            */
            assert(*GetNextConn()->GetReadParams()->GetCipherSuite() == *GetNextConn()->GetWriteParams()->GetCipherSuite());

            CHKOK(GetNextConn()->GetReadParams()->GetCipherSuite()->GetKeyExchangeAlgorithm(&keyExchangeAlg));

            if (keyExchangeAlg != MTKEA_rsa)
            {
                wprintf(L"unsupported key exchange type: %u\n", keyExchangeAlg);
                mr = MT_E_UNSUPPORTED_KEY_EXCHANGE;
                goto error;
            }

            CHKOK(keyExchange.ParseFromVect(spHandshakeMessage->GetBody()));

            /*
            ** actually decrypt the structure using our public key
            ** cipherer, which internally should already be primed with the
            ** correct public/private key pair. note that this should be
            ** using NextConn, not CurrConn, since we're handshaking using
            ** potentially a new certificate (and consequently a new key
            ** pair)
            */
            spExchangeKeys = keyExchange.GetExchangeKeys();
            CHKOK(spExchangeKeys->DecryptStructure(GetNextConn()->GetPubKeyCipherer().get()));

            // archive the message since it's good, for the Finished hash
            GetNextConn()->GetHandshakeMessages()->push_back(spHandshakeMessage);

            // got the decrypted premaster secret
            pSecret = spExchangeKeys->GetStructure();
            wprintf(L"version %04LX\n", *pSecret->GetClientVersion()->GetVersion());

            // generate a bunch of crypto material from this
            CHKOK(GetNextConn()->SetKeyMaterial(pSecret));

            wprintf(L"computed master secret and key material:\n");
            PrintByteVector(GetNextConn()->GetMasterSecret());
        }
        break;

        /*
        ** with the Finished message, the client has sent its last
        ** handshake message. In fact, this message has already been
        ** encrypted with the new connection parameters, so parsing this
        ** message is needed only for verifying the integrity of the
        ** client -> server stream.
        **
        ** verifying it involves computing a hash of all handshake messages
        ** received so far (not including this very Finished message) and
        ** comparing it with the decrypted body of this message. this hash
        ** value is known as the "verify data"
        */
        case MT_Handshake::MTH_Finished:
        {
            MT_Finished finishedMessage;
            CHKOK(finishedMessage.ParseFromVect(spHandshakeMessage->GetBody()));

            // used to access GetHandshakeMessages() for the hash calculation
            CHKOK(finishedMessage.SetConnParams(GetNextConn()));

            // used to decrypt the message
            CHKOK(finishedMessage.SetEndpointParams(GetNextConn()->GetReadParams()));

            // do the actual hash check
            CHKOK(finishedMessage.CheckSecurity());

            /*
            ** we have to store the verify data we received here to include
            ** in a renegotiation, if one comes up
            */
            CHKOK(GetNextConn()->SetClientVerifyData(finishedMessage.GetVerifyData()));

            /*
            ** yes, we archive this message, too. when the server sends its
            ** own Finished message, guess what? it has to include all
            ** handshake messages received so far, including the client
            ** finished message
            */
            GetNextConn()->GetHandshakeMessages()->push_back(spHandshakeMessage);

            // go ahead and do that response right now
            CHKOK(RespondToFinished());
        }
        break;

        default:
        {
            wprintf(L"not yet supporting handshake type %u\n", *spHandshakeMessage->GetType());
            mr = MT_E_UNSUPPORTED_HANDSHAKE_TYPE;
            goto error;
        }
        break;
    }

done:
    return mr;

error:
    goto done;
} // end function HandleHandshakeMessage

/*
** having received a client hello, prepare and queue up the messages we should
** respond with to drive the TLS handshake
**
** this ends up being a ServerHello, a Certificate, and a ServerHelloDone
**
** This function is a little complicated because it handles the app's choice of
** whether to package multiple records of the same content type (in this case,
** Handshake) into a single record layer message, or to split them up into
** individual record layer messages.
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::RespondToClientHello()
{
    MTERR mr = MT_S_OK;
    MT_ClientHello* pClientHello = GetNextConn()->GetClientHello();
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    // ServerHello
    {
        MT_ProtocolVersion protocolVersion;
        MT_Random random;
        MT_SessionID sessionID;
        MT_CompressionMethod compressionMethod;
        MT_HelloExtensions extensions;
        MT_ServerHello serverHello;
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());

        // this was previously chosen by calling back to the app
        CHKOK(protocolVersion.SetVersion(*GetNextConn()->GetReadParams()->GetVersion()));

        CHKOK(random.PopulateNow());

        // no compression support for now
        CHKOK(compressionMethod.SetMethod(MT_CompressionMethod::MTCM_Null));

        /*
        ** prepare the renegotiation extension information. if we're doing a
        ** second handshake (renegotiation), then fill in the requisite
        ** Finished verify data from the prior handshake
        **
        ** the MT_RenegotiationInfoExtension object is a standard Extension. it
        ** contains a MT_RenegotiatedConnection object, which has all of the
        ** specific data about this type of extension
        */
        {
            MT_RenegotiationInfoExtension renegotiationExtension;
            MT_RenegotiationInfoExtension::MT_RenegotiatedConnection rc;

            CHKOK(renegotiationExtension.SetExtensionType(MT_Extension::MTEE_RenegotiationInfo));

            // we have previous verify data, so we're renegotiating
            if (!GetCurrConn()->GetServerVerifyData()->GetData()->empty())
            {
                // also need client verify data
                assert(!GetCurrConn()->GetClientVerifyData()->GetData()->empty());

                rc.GetData()->insert(
                    rc.GetData()->end(),
                    GetCurrConn()->GetClientVerifyData()->GetData()->begin(),
                    GetCurrConn()->GetClientVerifyData()->GetData()->end());

                rc.GetData()->insert(
                    rc.GetData()->end(),
                    GetCurrConn()->GetServerVerifyData()->GetData()->begin(),
                    GetCurrConn()->GetServerVerifyData()->GetData()->end());

                if (rc.GetData()->size() != c_cbFinishedVerifyData_Length * 2)
                {
                    wprintf(L"warning: renegotiation verify data is odd length. expected: %Iu, actual: %Iu\n", c_cbFinishedVerifyData_Length * 2, rc.GetData()->size());
                }

                wprintf(L"adding renegotation binding information:\n");
                PrintByteVector(rc.GetData());
            }
            // else, empty renegotiated info

            CHKOK(renegotiationExtension.SetRenegotiatedConnection(&rc));

            extensions.GetData()->push_back(renegotiationExtension);
        }

        CHKOK(serverHello.SetServerVersion(protocolVersion));
        CHKOK(serverHello.SetRandom(random));
        CHKOK(serverHello.SetSessionID(&sessionID));

        // just logging/warning
        if (*GetNextConn()->GetReadParams()->GetCipherSuite() != *GetNextConn()->GetWriteParams()->GetCipherSuite())
        {
            MT_CipherSuiteValue csvRead;
            mr = GetNextConn()->GetReadParams()->GetCipherSuite()->GetValue(&csvRead);
            if (mr == MT_S_OK)
            {
                MT_CipherSuiteValue csvWrite;
                mr = GetNextConn()->GetWriteParams()->GetCipherSuite()->GetValue(&csvWrite);
                if (mr == MT_S_OK)
                {
                    wprintf(L"warning: choosing different read cipher suite (%04LX) and write cipher suite (%04LX)\n", csvRead, csvWrite);
                }
            }

            mr = MT_S_OK;
        }

        CHKOK(serverHello.SetCipherSuite(GetNextConn()->GetReadParams()->GetCipherSuite()));
        CHKOK(serverHello.SetCompressionMethod(compressionMethod));
        CHKOK(serverHello.SetExtensions(&extensions));

        CHKOK(GetNextConn()->SetServerRandom(serverHello.GetRandom()));

        CHKOK(spHandshake->SetType(MT_Handshake::MTH_ServerHello));
        CHKOK(serverHello.SerializeToVect(spHandshake->GetBody()));

        CHKOK(CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 *protocolVersion.GetVersion(),
                 spHandshake.get(),
                 spPlaintext.get()));

        GetNextConn()->GetHandshakeMessages()->push_back(spHandshake);

        /*
        ** don't enqueue or increment sequence number just yet. we may choose
        ** as part of the next handshake message below to tack on another
        ** handshake message to this single record layer message
        */
    }

    assert(mr == MT_S_OK);

    // Certificate
    {
        MT_Certificate certificate;
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_TLSPlaintext* pPlaintextPass = spPlaintext.get();

        CHKOK(certificate.SetCertificateList(GetNextConn()->GetCertChain()));
        CHKOK(spHandshake->SetType(MT_Handshake::MTH_Certificate));

        CHKOK(certificate.SerializeToVect(spHandshake->GetBody()));

        mr = AddHandshakeMessage(
                 spHandshake.get(),
                 *pClientHello->GetClientVersion()->GetVersion(),
                 &pPlaintextPass);

        /*
        ** MT_S_OK -> send the previous record layer message. The app chose to
        ** put this handshake message in a new record layer message, passed
        ** back in pPlaintextPass
        **
        ** MT_S_FALSE -> keep accumulating data for this single plaintext
        ** message.
        */
        if (mr == MT_S_OK)
        {
            CHKOK(EnqueueMessage(spPlaintext));

            // take ownership of memory allocated in AddHandshakeMessage
            spPlaintext.reset(pPlaintextPass);
        }
        else if (mr != MT_S_FALSE)
        {
            goto error;
        }

        GetNextConn()->GetHandshakeMessages()->push_back(spHandshake);

        // could be MT_S_FALSE, so reset
        mr = MT_S_OK;
    }

    assert(mr == MT_S_OK);

    // ServerHelloDone
    {
        MT_ServerHelloDone serverHelloDone;
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_TLSPlaintext* pPlaintextPass = spPlaintext.get();

        CHKOK(spHandshake->SetType(MT_Handshake::MTH_ServerHelloDone));

        CHKOK(serverHelloDone.SerializeToVect(spHandshake->GetBody()));

        mr = AddHandshakeMessage(
                 spHandshake.get(),
                 *pClientHello->GetClientVersion()->GetVersion(),
                 &pPlaintextPass);

        // see above for comments at call to AddHandshakeMessage
        if (mr == MT_S_OK)
        {
            CHKOK(EnqueueMessage(spPlaintext));

            spPlaintext.reset(pPlaintextPass);
        }
        else if (mr != MT_S_FALSE)
        {
            goto error;
        }

        CHKOK(EnqueueMessage(spPlaintext));

        GetNextConn()->GetHandshakeMessages()->push_back(spHandshake);
    }

    assert(mr == MT_S_OK);

done:
    return mr;

error:
    goto done;
} // end function RespondToClientHello

/*
** when sending handshake messages, there are often multiple in a row to send.
** this calls back to the app for the choice of whether to combine these
** messages with the same content type into a single TLSPlaintext message or to
** break them up into separate ones
**
** MT_S_OK means we are returning a new plaintext message
** MT_S_FALSE means we are returning the same plaintext message
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::AddHandshakeMessage(
    MT_Handshake* pHandshake,
    MT_ProtocolVersion::MTPV_Version version,
    MT_TLSPlaintext** ppPlaintext
)
{
    MTERR mr = MT_S_OK;
    MT_UINT32 fCreateFlags = 0;

    mr = GetServerListener()->OnCreatingHandshakeMessage(pHandshake, &fCreateFlags);
    if (mr == MT_S_LISTENER_IGNORED)
    {
        fCreateFlags = MT_CREATINGHANDSHAKE_SEPARATE_HANDSHAKE;
    }
    else if (mr != MT_S_LISTENER_HANDLED)
    {
        goto error;
    }

    if (fCreateFlags & MT_CREATINGHANDSHAKE_COMBINE_HANDSHAKE)
    {
        CHKOK(pHandshake->SerializeAppendToVect((*ppPlaintext)->GetFragment()));

        // indicates that we reused the existing plaintext message
        mr = MT_S_FALSE;
    }
    else
    {
        *ppPlaintext = new MT_TLSPlaintext();

        CHKOK(CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 version,
                 pHandshake,
                 *ppPlaintext));
    }

done:
    return mr;

error:
    goto done;
} // end function AddHandshakeMessage

/*
** once we receive a Finished message from the client, we have to construct our
** own Finished message and send it back, which completes the handshake. first
** we send a ChangeCipherSpec, which enables the pending cipher suite, so that
** Finished message we send is encrypted with the new security parameters.
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::RespondToFinished()
{
    MTERR mr = MT_S_OK;

    // ChangeCipherSpec
    {
        MT_ChangeCipherSpec changeCipherSpec;
        shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

        CHKOK(changeCipherSpec.SetType(MT_ChangeCipherSpec::MTCCS_ChangeCipherSpec));

        assert(*GetNextConn()->GetReadParams()->GetVersion() == *GetNextConn()->GetWriteParams()->GetVersion());

        CHKOK(CreatePlaintext(
                 MT_ContentType::MTCT_Type_ChangeCipherSpec,
                 *GetNextConn()->GetReadParams()->GetVersion(),
                 &changeCipherSpec,
                 spPlaintext.get()));

        CHKOK(EnqueueMessage(spPlaintext));

        CHKOK(GetCurrConn()->SetWriteParams(GetNextConn()->GetWriteParams()));

        /*
        ** newly copied new connection state should have its initial value of
        ** 0 for sequence number, since it hasn't been touched yet
        */
        assert(*GetCurrConn()->GetWriteParams()->GetSequenceNumber() == 0);
    }

    // Finished
    {
        shared_ptr<MT_Handshake> spHandshake(new MT_Handshake());
        MT_Finished finished;
        shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

        CHKOK(finished.SetConnParams(GetNextConn()));

        CHKOK(finished.SetEndpointParams(GetCurrConn()->GetWriteParams()));

        // the payload is a hash of all of the handshake messages seen so far
        CHKOK(finished.ComputeVerifyData(c_szServerFinished_PRFLabel, finished.GetVerifyData()->GetData()));

        CHKOK(spHandshake->SetType(MT_Handshake::MTH_Finished));
        CHKOK(finished.SerializeToVect(spHandshake->GetBody()));

        assert(*GetCurrConn()->GetReadParams()->GetVersion() == *GetCurrConn()->GetWriteParams()->GetVersion());

        CHKOK(CreatePlaintext(
                 MT_ContentType::MTCT_Type_Handshake,
                 *GetCurrConn()->GetWriteParams()->GetVersion(),
                 spHandshake.get(),
                 spPlaintext.get()));

        CHKOK(EnqueueMessage(spPlaintext));

        // we archive the handshake message just cause, though it won't be used
        GetNextConn()->GetHandshakeMessages()->push_back(spHandshake);

        CHKOK(GetNextConn()->SetServerVerifyData(finished.GetVerifyData()));
    }

    CHKOK(FinishNextHandshake());

done:
    return mr;

error:
    goto done;
} // end function RespondToFinished

_Use_decl_annotations_
MTERR_T
TLSConnection::CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    MT_TLSPlaintext* pPlaintext)
{
    MTERR mr = MT_S_OK;
    MT_ContentType contentType;
    MT_ProtocolVersion protocolVersion;

    CHKOK(contentType.SetType(&eContentType));
    CHKOK(pPlaintext->SetContentType(&contentType));

    CHKOK(protocolVersion.SetVersion(eProtocolVersion));
    CHKOK(pPlaintext->SetProtocolVersion(protocolVersion));

    CHKOK(pPlaintext->SetFragment(pvbFragment));

    CHKOK(pPlaintext->SetConnection(this));

done:
    return mr;

error:
    goto done;
} // end function CreatePlaintext

_Use_decl_annotations_
MTERR_T
TLSConnection::CreatePlaintext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    MT_TLSPlaintext* pPlaintext)
{
    MTERR mr = MT_S_OK;

    ByteVector vbFragment;
    CHKOK(pFragment->SerializeToVect(&vbFragment));

    CHKOK(CreatePlaintext(
             eContentType,
             eProtocolVersion,
             &vbFragment,
             pPlaintext));

done:
    return mr;

error:
    goto done;
} // end function CreatePlaintext

_Use_decl_annotations_
MTERR_T
TLSConnection::CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const ByteVector* pvbFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext)
{
    MTERR mr = MT_S_OK;

    MT_ContentType contentType;
    MT_ProtocolVersion protocolVersion;

    CHKOK(pCiphertext->SetConnection(this));
    CHKOK(pCiphertext->SetServerListener(GetServerListener()));

    CHKOK(pCiphertext->SetEndpointParams(pEndParams));

    CHKOK(contentType.SetType(&eContentType));
    CHKOK(pCiphertext->SetContentType(&contentType));

    CHKOK(protocolVersion.SetVersion(eProtocolVersion));
    CHKOK(pCiphertext->SetProtocolVersion(protocolVersion));
    CHKOK(pCiphertext->GetCipherFragment()->SetContent(*pvbFragment));

    CHKOK(pCiphertext->Protect());

done:
    return mr;

error:
    goto done;
} // end function CreateCiphertext

_Use_decl_annotations_
MTERR_T
TLSConnection::CreateCiphertext(
    MT_ContentType::MTCT_Type eContentType,
    MT_ProtocolVersion::MTPV_Version eProtocolVersion,
    const MT_Structure* pFragment,
    EndpointParameters* pEndParams,
    MT_TLSCiphertext* pCiphertext)
{
    MTERR mr = MT_S_OK;
    ByteVector vbFragment;

    CHKOK(pFragment->SerializeToVect(&vbFragment));

    CHKOK(CreateCiphertext(
             eContentType,
             eProtocolVersion,
             &vbFragment,
             pEndParams,
             pCiphertext));

done:
    return mr;

error:
    goto done;
} // end function CreateCiphertext

// called when we receive a ClientHello message, to start off a new negotiation
_Use_decl_annotations_
MTERR_T
TLSConnection::StartNextHandshake(MT_ClientHello* pClientHello)
{
    MTERR mr = MT_S_OK;

    if (GetNextConn()->IsHandshakeInProgress())
    {
        // may lift this restriction if it's okay...
        assert(false);
    }

    CHKOK(GetNextConn()->SetClientHello(pClientHello));

    /*
    ** the next connection will be used for collecting information about the
    ** pending security negotation, but is not used for parsing any incoming
    ** records; the current connection does that.
    */
    CHKOK(InitializeConnection(GetNextConn()));

done:
    return mr;

error:
    goto done;
} // end function StartNextHandshake

/*
** basically consists of calling the app to provide platform-specific crypto
** objects that will be attached only to this connection. in practice, a few
** of these objects probably don't need to be connection-specific (e.g. hasher)
** but I don't want to make platform assumptions.
**
** it's painfully obvious how much of an intermediary we are between the conn
** and the listener here. but that's okay
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::InitializeConnection(
    ConnectionParameters* pParams
)
{
    MTERR mr = MT_S_OK;

    MT_CertificateList certChain;
    shared_ptr<PublicKeyCipherer> spPubKeyCipherer;
    shared_ptr<SymmetricCipherer> spClientSymCipherer;
    shared_ptr<SymmetricCipherer> spServerSymCipherer;
    shared_ptr<Hasher> spClientHasher;
    shared_ptr<Hasher> spServerHasher;

    CHKOK(GetServerListener()->OnInitializeCrypto(
             &certChain,
             &spPubKeyCipherer,
             &spClientSymCipherer,
             &spServerSymCipherer,
             &spClientHasher,
             &spServerHasher));

    CHKOK(pParams->Initialize(
             &certChain,
             spPubKeyCipherer,
             spClientSymCipherer,
             spServerSymCipherer,
             spClientHasher,
             spServerHasher));

done:
    return mr;

error:
    goto done;
} // end function InitializeConnection

/*
** called when we have sent the Finished message, signaling the end of the
** handshake/negotiation. at this point our current connection already has the
** endpoint-specific parameters needed to parse or send messages, but we still
** need to copy few miscellaneous pieces of data we've accumulated in NextConn.
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::FinishNextHandshake()
{
    MTERR mr = MT_S_OK;

    assert(GetNextConn()->IsHandshakeInProgress());

    // copy last bits of state
    CHKOK(GetNextConn()->CopyCommonParamsTo(GetCurrConn()));

    // reset it to blank, ready for the next handshake to start whenever
    CHKOK(SetNextConn(ConnectionParameters()));
    assert(!GetNextConn()->IsHandshakeInProgress());

    // lets the app know it can start sending app data
    CHKSUC(GetServerListener()->OnHandshakeComplete());
    mr = MT_S_OK;

done:
    return mr;

error:
    goto done;
} // end function FinishNextHandshake

/*
** this function is called whenever we have a structure to send to the client.
** it converts a plaintext object into a properly encrypted ciphertext object
** according to the current connection's negotiated cipher suite.
**
** the ciphertext message isn't exactly sent yet, but it's in the queue to be
** sent, so effectively committed in terms of updates to the IV and sequence
** number.
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::EnqueueMessage(
    shared_ptr<MT_TLSPlaintext> spPlaintext
)
{
    MTERR mr = MT_S_OK;

    shared_ptr<MT_TLSCiphertext> spCiphertext;

    CHKOK(MT_TLSCiphertext::FromTLSPlaintext(
             spPlaintext.get(),
             GetCurrConn()->GetWriteParams(),
             &spCiphertext));

    /*
    ** after the ciphertext is created, update the IV to be used on the next
    ** ciphertext. in practice, this is either the last block of the ciphertext
    ** or a new, "random" value.
    */
    if (GetCurrConn()->GetWriteParams()->GetCipher()->type == CipherType_Block)
    {
        CHKOK(spCiphertext->GenerateNextIV(GetCurrConn()->GetWriteParams()->GetIV()));
        wprintf(L"next IV for writing:\n");
        PrintByteVector(GetCurrConn()->GetWriteParams()->GetIV());
    }

    assert(GetCurrConn()->GetWriteParams()->GetIV()->size() == GetCurrConn()->GetWriteParams()->GetCipher()->cbIVSize);

    GetPendingSends()->push_back(spCiphertext);
    CHKOK(GetCurrConn()->GetWriteParams()->SetSequenceNumber(*GetCurrConn()->GetWriteParams()->GetSequenceNumber() + 1));

    wprintf(L"write seq num is now %I64u\n", *GetCurrConn()->GetWriteParams()->GetSequenceNumber());

    // primarily used for logging by the app
    CHKOK(GetServerListener()->OnEnqueuePlaintext(
             spPlaintext.get(),
             spCiphertext->GetEndpointParams()->IsEncrypted()));

done:
    return mr;

error:
    goto done;
} // end function EnqueueMessage

// alert the app about each message's raw bytes that need to be sent
_Use_decl_annotations_
MTERR_T
TLSConnection::SendQueuedMessages()
{
    MTERR mr = MT_S_OK;

    if (!GetPendingSends()->empty())
    {
        { // only logging
            wprintf(L"sending %Iu messages\n", GetPendingSends()->size());

            for_each(GetPendingSends()->begin(), GetPendingSends()->end(),
            [](shared_ptr<const MT_RecordLayerMessage> spStructure)
            {
                wprintf(L"    %s\n", spStructure->GetContentType()->ToString().c_str());
            });
        }

        for_each(GetPendingSends()->begin(), GetPendingSends()->end(),
        [&mr, this](shared_ptr<const MT_RecordLayerMessage> spStructure)
        {
            if (mr == MT_S_OK)
            {
                ByteVector vbRecord;

                mr = spStructure->SerializeToVect(&vbRecord);
                if (mr == MT_S_OK)
                {
                    mr = GetServerListener()->OnSend(&vbRecord);
                    if (MT_Failed(mr))
                    {
                        wprintf(L"warning: error in OnSend with listener: %08LX\n", mr);
                    }
                }
                else
                {
                    wprintf(L"failed to serialize message: %08LX\n", mr);
                }
            }
        });

        if (mr != MT_S_OK)
        {
            goto error;
        }

        GetPendingSends()->clear();
    }

done:
    return mr;

error:
    goto done;
} // end function SendQueuedMessages

/*
** this is how the app calls the connection to send some application data. we
** package it up, encrypt it, and queue it for sending
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::EnqueueSendApplicationData(
    const ByteVector* pvb
)
{
    MTERR mr = MT_S_OK;
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    assert(*GetCurrConn()->GetReadParams()->GetVersion() == *GetCurrConn()->GetWriteParams()->GetVersion());

    CHKOK(CreatePlaintext(
             MT_ContentType::MTCT_Type_ApplicationData,
             *GetCurrConn()->GetWriteParams()->GetVersion(),
             pvb,
             spPlaintext.get()));

    CHKOK(EnqueueMessage(spPlaintext));

done:
    return mr;

error:
    goto done;
} // end function EnqueueSendApplicationData

/*
** this lets the app start a renegotiation by queueing up a HelloRequest
** message. Actually, this doesn't start a renegotiation; it just *requests*
** that the client start a renegotiation, since they are always initiated from
** the client
*/
_Use_decl_annotations_
MTERR_T
TLSConnection::EnqueueStartRenegotiation()
{
    MTERR mr = MT_S_OK;
    MT_HelloRequest helloRequest;
    MT_Handshake handshake;
    shared_ptr<MT_TLSPlaintext> spPlaintext(new MT_TLSPlaintext());

    wprintf(L"starting renegotiation\n");

    CHKOK(handshake.SetType(MT_Handshake::MTH_HelloRequest));
    CHKOK(helloRequest.SerializeToVect(handshake.GetBody()));

    assert(*GetCurrConn()->GetReadParams()->GetVersion() == *GetCurrConn()->GetWriteParams()->GetVersion());

    CHKOK(CreatePlaintext(
             MT_ContentType::MTCT_Type_Handshake,
             *GetCurrConn()->GetWriteParams()->GetVersion(),
             &handshake,
             spPlaintext.get()));

    CHKOK(EnqueueMessage(spPlaintext));

done:
    return mr;

error:
    goto done;
} // end function EnqueueStartRenegotiation


/*********** Utility functions *****************/

_Use_decl_annotations_
bool
MT_Succeeded(
    MTERR_T mr
)
{
    return (mr & 0x80000000) == 0;
} // end function MT_Succeeded

_Use_decl_annotations_
bool
MT_Failed(
    MTERR_T mr
)
{
    return !MT_Succeeded(mr);
} // end function MT_Failed
_Use_decl_annotations_
MTERR_T
WriteRandomBytes(
    MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_FALSE;
    int r = 0;
    size_t cbR = 0;

    while (cb > 0)
    {
        mr = MT_S_OK;

        if (cbR == 0)
        {
            r = rand();
            cbR = sizeof(r);
        }

        pv[0] = r & 0xFF;

        pv++;
        cb--;
        cbR--;
        r >>= 8;
    }

    return mr;
} // end function WriteRandomBytes


// specialization of above, for bytes
template <>
_Use_decl_annotations_
void
ResizeVector<MT_BYTE>(
    ByteVector* pv,
    typename ByteVector::size_type cb
)
{
    // arbitrary filler value
    pv->resize(cb, 0x23);
} // end function ResizeVector<MT_BYTE>

_Use_decl_annotations_
MTERR_T
ParseByteVector(
    size_t cbField,
    const MT_BYTE* pv,
    size_t cb,
    ByteVector* pvb
)
{
    MTERR mr = MT_S_OK;

    if (cbField > cb)
    {
        mr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    pvb->assign(pv, pv + cbField);

done:
    return mr;

error:
    goto done;
} // end function ParseByteVector

_Use_decl_annotations_
MTERR_T
SerializeByteVector(
    const ByteVector* pvb,
    MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;

    size_t cbField = pvb->size();
    if (cbField > cb)
    {
        mr = MT_E_INSUFFICIENT_BUFFER;
        goto error;
    }

    std::copy(pvb->begin(), pvb->end(), pv);

done:
    return mr;

error:
    goto done;
} // end function SerializeByteVector

_Use_decl_annotations_
MTERR_T
PrintByteVector(
    const ByteVector* pvb)
{
     for_each(pvb->begin(), pvb->end(),
     [](MT_BYTE b)
     {
         wprintf(L"%02X ", b);
     });

     wprintf(L"\n");

     return MT_S_OK;
} // end function PrintByteVector


/*********** EndpointParameters *****************/

EndpointParameters::EndpointParameters()
    : m_cipherSuite(MTCS_TLS_RSA_WITH_NULL_NULL),
      m_spHasher(),
      m_eVersion(MT_ProtocolVersion::MTPV_Unknown),
      m_vbKey(),
      m_vbMACKey(),
      m_vbIV(),
      m_seqNum(0)
{
} // end ctor EndpointParameters

_Use_decl_annotations_
MTERR_T
EndpointParameters::Initialize(
    shared_ptr<SymmetricCipherer> spSymCipherer,
    shared_ptr<Hasher> spHasher
)
{
    m_spSymCipherer = spSymCipherer;
    m_spHasher = spHasher;
    return MT_S_OK;
} // end function Initialize

/*
** cache the answer internally and return it after the first time. this allows
** us to return a const pointer to it without requiring that the caller also
** free it
*/
_Use_decl_annotations_
const CipherInfo*
EndpointParameters::GetCipher() const
{
    static CipherInfo cipherInfo =
    {
        CipherAlg_Unknown,
        CipherType_Stream,
        0,
        0,
        0
    };

    MTERR mr = CryptoInfoFromCipherSuite(GetCipherSuite(), &cipherInfo, nullptr);
    assert(mr == MT_S_OK);

    return &cipherInfo;
} // end function GetCipher

// same comment as for GetCipher()
_Use_decl_annotations_
const HashInfo*
EndpointParameters::GetHash() const
{
    static HashInfo hashInfo =
    {
        HashAlg_Unknown,
        0,
        0
    };

    MTERR mr = CryptoInfoFromCipherSuite(GetCipherSuite(), nullptr, &hashInfo);
    assert(mr == MT_S_OK);

    return &hashInfo;
} // end function GetHash

_Use_decl_annotations_
bool
EndpointParameters::IsEncrypted() const
{
    return (GetCipher()->alg != CipherAlg_NULL);
} // end function IsEncrypted


/*********** ConnectionParameters *****************/

ConnectionParameters::ConnectionParameters()
    : m_certChain(),
      m_spPubKeyCipherer(),
      m_clientHello(),
      m_clientRandom(),
      m_serverRandom(),
      m_clientVerifyData(),
      m_serverVerifyData(),
      m_vbMasterSecret(),
      m_readParams(),
      m_writeParams(),
      m_vHandshakeMessages()
{
} // end ctor ConnectionParameters

/*
** this can be called at three different times:
** - early, before any messages arrive
** - after receiving a ClientHello, to prep the new connection for handshake
** - after receiving a ClientHello when there is already an active, secure
**   connection, when starting a renegotiation
**
** in all cases, this is a fresh connection, so is basically pretty blank
** aside from the objects passed in here
*/
_Use_decl_annotations_
MTERR_T
ConnectionParameters::Initialize(
    const MT_CertificateList* pCertChain,
    shared_ptr<PublicKeyCipherer> spPubKeyCipherer,
    shared_ptr<SymmetricCipherer> spClientSymCipherer,
    shared_ptr<SymmetricCipherer> spServerSymCipherer,
    shared_ptr<Hasher> spClientHasher,
    shared_ptr<Hasher> spServerHasher
)
{
    MTERR mr = MT_S_OK;

    if (!GetCertChain()->GetData()->empty())
    {
        assert(false);
        mr = MT_E_FAIL;
        goto error;
    }

    CHKOK(SetCertChain(pCertChain));
    m_spPubKeyCipherer = spPubKeyCipherer;


    assert(GetReadParams()->GetCipher()->alg == CipherAlg_NULL);

    CHKOK(spClientSymCipherer->SetCipherInfo(
             GetReadParams()->GetKey(),
             GetReadParams()->GetCipher()));


    assert(GetWriteParams()->GetCipher()->alg == CipherAlg_NULL);

    CHKOK(spServerSymCipherer->SetCipherInfo(
             GetWriteParams()->GetKey(),
             GetWriteParams()->GetCipher()));


    CHKOK(GetReadParams()->Initialize(spClientSymCipherer, spClientHasher));

    CHKOK(GetWriteParams()->Initialize(spServerSymCipherer, spServerHasher));

done:
    return mr;

error:
    goto done;
} // end function Initialize

/*
** multiplex to run the TLS pseudorandom function appropriate to the current
** protocol version.
*/
_Use_decl_annotations_
MTERR_T
ConnectionParameters::ComputePRF(
    const ByteVector* pvbSecret,
    const char* szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    MTERR mr = MT_S_OK;

    /*
    ** PRF should only be called at times after the version and cipher suite
    ** are finalized
    */
    assert(*GetReadParams()->GetVersion() == *GetWriteParams()->GetVersion());
    assert(*GetReadParams()->GetHash() == *GetWriteParams()->GetHash());

    wprintf(L"protocol version for PRF algorithm: %04LX\n", *GetReadParams()->GetVersion());

    switch (*GetReadParams()->GetVersion())
    {
        case MT_ProtocolVersion::MTPV_TLS10:
        {
            mr = ComputePRF_TLS10(
                     GetReadParams()->GetHasher().get(),
                     pvbSecret,
                     szLabel,
                     pvbSeed,
                     cbLengthDesired,
                     pvbPRF);
        }
        break;

        case MT_ProtocolVersion::MTPV_TLS11:
        {
            mr = ComputePRF_TLS11(
                     GetReadParams()->GetHasher().get(),
                     pvbSecret,
                     szLabel,
                     pvbSeed,
                     cbLengthDesired,
                     pvbPRF);
        }
        break;

        case MT_ProtocolVersion::MTPV_TLS12:
        {
            mr = ComputePRF_TLS12(
                     GetReadParams()->GetHasher().get(),
                     pvbSecret,
                     szLabel,
                     pvbSeed,
                     cbLengthDesired,
                     pvbPRF);
        }
        break;

        default:
        {
            assert(false);
            mr = MT_E_UNKNOWN_PROTOCOL_VERSION;
        }
        break;
    }

    if (mr != MT_S_OK)
    {
        goto error;
    }

    assert(pvbPRF->size() == cbLengthDesired);

done:
    return mr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF

/*
** TLS 1.0
** master_secret = PRF(pre_master_secret, "master secret",
**                     ClientHello.random + ServerHello.random)
** [0..47];
*/
_Use_decl_annotations_
MTERR_T
ConnectionParameters::SetMasterSecret(
    const MT_PreMasterSecret* pPreMasterSecret
)
{
    MTERR mr = MT_S_OK;

    ByteVector vbPreMasterSecret;
    ByteVector vbRandoms;

    CHKOK(pPreMasterSecret->SerializeToVect(&vbPreMasterSecret));

    wprintf(L"premaster secret:\n");
    PrintByteVector(&vbPreMasterSecret);

    CHKOK(GetClientRandom()->SerializeToVect(&vbRandoms));

    assert(vbRandoms.size() == GetClientRandom()->Length());

    CHKOK(GetServerRandom()->SerializeAppendToVect(&vbRandoms));

    assert(vbRandoms.size() == GetClientRandom()->Length() + GetServerRandom()->Length());

    CHKOK(ComputePRF(
             &vbPreMasterSecret,
             c_szMasterSecret_PRFLabel,
             &vbRandoms,
             c_cbMasterSecret_Length,
             GetMasterSecret()));

    assert(GetMasterSecret()->size() == c_cbMasterSecret_Length);

done:
    return mr;

error:
    goto done;
} // end function SetMasterSecret

/*
** the key_block is a chunk of data produced by the PRF that is partitioned
** into the various pieces of cryptographic material needed in the connection.
**
** TLS 1.0
** To generate the key material, compute

** key_block = PRF(SecurityParameters.master_secret,
**                    "key expansion",
**                    SecurityParameters.server_random +
**                    SecurityParameters.client_random);
**
** until enough output has been generated. Then the key_block is
** partitioned as follows:
**
** client_write_MAC_secret[SecurityParameters.hash_size]
** server_write_MAC_secret[SecurityParameters.hash_size]
** client_write_key[SecurityParameters.key_material_length]
** server_write_key[SecurityParameters.key_material_length]
** client_write_IV[SecurityParameters.IV_size]
** server_write_IV[SecurityParameters.IV_size]
*/
_Use_decl_annotations_
MTERR_T
ConnectionParameters::SetKeyMaterial(
    const MT_PreMasterSecret* pPreMasterSecret
)
{
    MTERR mr = MT_S_OK;

    size_t cbKeyBlock;
    ByteVector vbRandoms;
    ByteVector vbKeyBlock;

    wprintf(L"gen key material\n");

    CHKOK(SetMasterSecret(pPreMasterSecret));

    // should only be called when cipher and hash are finalized
    assert(*GetReadParams()->GetCipher() == *GetWriteParams()->GetCipher());
    assert(*GetReadParams()->GetHash() == *GetWriteParams()->GetHash());

    /*
    ** client and server hash keys
    ** client and server keys
    ** client and server IVs
    */
    cbKeyBlock = (GetReadParams()->GetHash()->cbMACKeySize * 2) +
                 (GetReadParams()->GetCipher()->cbKeyMaterialSize * 2) +
                 (GetReadParams()->GetCipher()->cbIVSize * 2);

    wprintf(L"need %Iu bytes for key block (%Iu * 2) + (%Iu * 2) + (%Iu * 2)\n",
        cbKeyBlock,
        GetReadParams()->GetHash()->cbMACKeySize,
        GetReadParams()->GetCipher()->cbKeyMaterialSize,
        GetReadParams()->GetCipher()->cbIVSize);

    CHKOK(GetServerRandom()->SerializeToVect(&vbRandoms));

    CHKOK(GetClientRandom()->SerializeAppendToVect(&vbRandoms));

    wprintf(L"randoms: (%Iu bytes)\n", vbRandoms.size());
    PrintByteVector(&vbRandoms);

    CHKOK(ComputePRF(
             GetMasterSecret(),
             c_szKeyExpansion_PRFLabel,
             &vbRandoms,
             cbKeyBlock,
             &vbKeyBlock));

    wprintf(L"key block:\n");
    PrintByteVector(&vbKeyBlock);

    {
        // iterate through the key material, splitting into the various parts
        auto itKeyBlock = vbKeyBlock.begin();

        // grabs the next chunk into the specified byte vector
        auto fnPartitionBlock =
            [&itKeyBlock, &vbKeyBlock, this]
            (ByteVector* pvb, size_t cbField, const wchar_t* wszLabel)
            {
                assert(itKeyBlock <= vbKeyBlock.end() - cbField);
                pvb->assign(itKeyBlock, itKeyBlock + cbField);
                itKeyBlock += cbField;

                wprintf(L"%s\n", wszLabel);
                PrintByteVector(pvb);
            };

        fnPartitionBlock(
            GetReadParams()->GetMACKey(),
            GetReadParams()->GetHash()->cbMACKeySize,
            L"GetReadParams()->GetMACKey()");

        fnPartitionBlock(
            GetWriteParams()->GetMACKey(),
            GetWriteParams()->GetHash()->cbMACKeySize,
            L"GetWriteParams()->GetMACKey()");


        fnPartitionBlock(
            GetReadParams()->GetKey(),
            GetReadParams()->GetCipher()->cbKeyMaterialSize,
            L"GetReadParams()->GetKey()");

        fnPartitionBlock(
            GetWriteParams()->GetKey(),
            GetWriteParams()->GetCipher()->cbKeyMaterialSize,
            L"GetWriteParams()->GetKey()");


        fnPartitionBlock(
            GetReadParams()->GetIV(),
            GetReadParams()->GetCipher()->cbIVSize,
            L"GetReadParams()->GetIV()");

        fnPartitionBlock(
            GetWriteParams()->GetIV(),
            GetWriteParams()->GetCipher()->cbIVSize,
            L"GetWriteParams()->GetIV()");

        // we should have consumed all the data
        assert(itKeyBlock == vbKeyBlock.end());


        CHKOK(GetReadParams()->GetSymCipherer()->SetCipherInfo(
                 GetReadParams()->GetKey(),
                 GetReadParams()->GetCipher()));

        CHKOK(GetWriteParams()->GetSymCipherer()->SetCipherInfo(
                 GetWriteParams()->GetKey(),
                 GetWriteParams()->GetCipher()));
    }

done:
    return mr;

error:
    GetReadParams()->GetMACKey()->clear();
    GetWriteParams()->GetMACKey()->clear();
    GetReadParams()->GetKey()->clear();
    GetWriteParams()->GetKey()->clear();
    GetReadParams()->GetIV()->clear();
    GetWriteParams()->GetIV()->clear();
    goto done;
} // end function SetKeyMaterial

/*
** copies leftover parameters aside from endpoint-specific ones to another
** connection parameters object. this is used in the last stage of finalizing
** a handshake, to make a connection the active one
*/
_Use_decl_annotations_
MTERR_T
ConnectionParameters::CopyCommonParamsTo(
    ConnectionParameters* pDest
)
{
    MTERR mr = MT_S_OK;

    CHKOK(pDest->SetCertChain(GetCertChain()));
    CHKOK(pDest->SetPubKeyCipherer(GetPubKeyCipherer()));
    CHKOK(pDest->SetClientHello(GetClientHello()));
    CHKOK(pDest->SetClientRandom(GetClientRandom()));
    CHKOK(pDest->SetServerRandom(GetServerRandom()));
    CHKOK(pDest->SetClientVerifyData(GetClientVerifyData()));
    CHKOK(pDest->SetServerVerifyData(GetServerVerifyData()));
    CHKOK(pDest->SetHandshakeMessages(GetHandshakeMessages()));
    CHKOK(pDest->SetMasterSecret(GetMasterSecret()));

done:
    return mr;

error:
    goto done;
} // end function CopyCommonParamsTo

_Use_decl_annotations_
bool
ConnectionParameters::IsHandshakeInProgress() const
{
    return !GetHandshakeMessages()->empty();
} // end function IsHandshakeInProgress


/*********** crypto stuff *****************/

/*
** TLS 1.2
** PRF(secret, label, seed) = P_<hash>(secret, label + seed)
*/
_Use_decl_annotations_
MTERR_T
ComputePRF_TLS12(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    const char* szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    MTERR mr = MT_S_OK;

    ByteVector vbLabelAndSeed;
    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(vbLabelAndSeed.end(), pvbSeed->begin(), pvbSeed->end());

    CHKOK(PRF_P_hash(
             pHasher,
             &c_HashInfo_SHA256,
             pvbSecret,
             &vbLabelAndSeed,
             cbLengthDesired,
             pvbPRF));

    assert(pvbPRF->size() >= cbLengthDesired);
    ResizeVector(pvbPRF, cbLengthDesired);

done:
    return mr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF_TLS12

/*
** TLS 1.0
** "
** TLS's PRF is created by splitting the secret into two halves and
** using one half to generate data with P_MD5 and the other half to
** generate data with P_SHA-1, then exclusive-or'ing the outputs of
** these two expansion functions together.
**
** S1 and S2 are the two halves of the secret and each is the same
** length. S1 is taken from the first half of the secret, S2 from the
** second half. Their length is created by rounding up the length of the
** overall secret divided by two; thus, if the original secret is an odd
** number of bytes long, the last byte of S1 will be the same as the
** first byte of S2.
**
**     L_S = length in bytes of secret;
**     L_S1 = L_S2 = ceil(L_S / 2);
**
** The secret is partitioned into two halves (with the possibility of
** one shared byte) as described above, S1 taking the first L_S1 bytes
** and S2 the last L_S2 bytes.
**
** The PRF is then defined as the result of mixing the two pseudorandom
** streams by exclusive-or'ing them together.
**
**     PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
**                                P_SHA-1(S2, label + seed);
** "
*/
_Use_decl_annotations_
MTERR_T
ComputePRF_TLS10(
    Hasher* pHasher,
    const ByteVector* pvbSecret,
    const char* szLabel,
    const ByteVector* pvbSeed,
    size_t cbLengthDesired,
    ByteVector* pvbPRF
)
{
    MTERR mr = MT_S_OK;
    wprintf(L"PRF 1.0\n");

    ByteVector vbLabelAndSeed;
    ByteVector vbS1;
    ByteVector vbS2;
    ByteVector vbS1_Expanded;
    ByteVector vbS2_Expanded;

    // label + seed, to be used later
    vbLabelAndSeed.assign(szLabel, szLabel + strlen(szLabel));
    vbLabelAndSeed.insert(
        vbLabelAndSeed.end(),
        pvbSeed->begin(),
        pvbSeed->end());

    wprintf(L"label + seed = (%Iu)\n", vbLabelAndSeed.size());
    PrintByteVector(&vbLabelAndSeed);

    // ceil(size / 2)
    size_t cbL_S1 = (pvbSecret->size() + 1) / 2;

    wprintf(L"L_S = %Iu, L_S1 = L_S2 = %Iu\n", pvbSecret->size(), cbL_S1);

    auto itSecretMidpoint = pvbSecret->begin() + cbL_S1;

    vbS1.assign(pvbSecret->begin(), itSecretMidpoint);

    wprintf(L"S1:\n");
    PrintByteVector(&vbS1);

    // makes the two halves overlap by one byte, as required in RFC
    if ((pvbSecret->size() % 2) != 0)
    {
        itSecretMidpoint--;
    }

    vbS2.assign(itSecretMidpoint, pvbSecret->end());

    wprintf(L"S2:\n");
    PrintByteVector(&vbS2);

    assert(vbS1.size() == vbS2.size());

    // get the MD5 hash
    CHKOK(PRF_P_hash(
             pHasher,
             &c_HashInfo_MD5,
             &vbS1,
             &vbLabelAndSeed,
             cbLengthDesired,
             &vbS1_Expanded));

    // get the SHA1 hash
    CHKOK(PRF_P_hash(
             pHasher,
             &c_HashInfo_SHA1,
             &vbS2,
             &vbLabelAndSeed,
             cbLengthDesired,
             &vbS2_Expanded));

    // PRF_P_hash can return more than we asked for. trim it down
    assert(vbS1_Expanded.size() >= cbLengthDesired);
    assert(vbS2_Expanded.size() >= cbLengthDesired);
    ResizeVector(pvbPRF, cbLengthDesired);

    // XOR the MD5 and SHA1 hashes together
    transform(
        vbS1_Expanded.begin(),
        vbS1_Expanded.begin() + cbLengthDesired,
        vbS2_Expanded.begin(),
        pvbPRF->begin(),
        bit_xor<MT_BYTE>());

done:
    return mr;

error:
    pvbPRF->clear();
    goto done;
} // end function ComputePRF_TLS10

/*
** TLS 1.0
** A() is defined as:
**     A(0) = seed
**     A(i) = HMAC_hash(secret, A(i-1))
*/
_Use_decl_annotations_
MTERR_T
PRF_A(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    MT_UINT32 i,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    ByteVector* pvbResult
)
{
    MTERR mr = MT_S_OK;
    ByteVector vbTemp;

    // A(0) = seed
    *pvbResult = *pvbSeed;

    // hash "i" number of times
    while (i > 0)
    {
        vbTemp = *pvbResult;

        CHKOK(pHasher->HMAC(
                          pHashInfo,
                          pvbSecret,
                          &vbTemp,
                          pvbResult));

        i--;
    }

done:
    return mr;

error:
    pvbResult->clear();
    goto done;
} // end function PRF_A

/*
** TLS 1.0
** "
** First, we define a data expansion function, P_hash(secret, data)
** which uses a single hash function to expand a secret and seed into an
** arbitrary quantity of output:
**
**     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
**                            HMAC_hash(secret, A(2) + seed) +
**                            HMAC_hash(secret, A(3) + seed) + ...
** "
**
** this returns >= cbMinimumLengthDesired bytes. the calling function is
** responsible for throwing away any excess
*/
_Use_decl_annotations_
MTERR_T
PRF_P_hash(
    Hasher* pHasher,
    const HashInfo* pHashInfo,
    const ByteVector* pvbSecret,
    const ByteVector* pvbSeed,
    size_t cbMinimumLengthDesired,
    ByteVector* pvbResult
)
{
    MTERR mr = MT_S_OK;

    pvbResult->clear();

    // starts from A(1), not A(0). keep expanding until we have enough output
    for (MT_UINT32 i = 1; pvbResult->size() < cbMinimumLengthDesired; i++)
    {
        wprintf(L"PRF_P generated %Iu out of %Iu bytes\n", pvbResult->size(), cbMinimumLengthDesired);

        ByteVector vbIteration;
        ByteVector vbInnerSeed;

        CHKOK(PRF_A(
                 pHasher,
                 pHashInfo,
                 i,
                 pvbSecret,
                 pvbSeed,
                 &vbInnerSeed));

        // A(i) + seed
        vbInnerSeed.insert(vbInnerSeed.end(), pvbSeed->begin(), pvbSeed->end());

        CHKOK(pHasher->HMAC(
                          pHashInfo,
                          pvbSecret,
                          &vbInnerSeed,
                          &vbIteration));

        // append each iteration's new data
        pvbResult->insert(pvbResult->end(), vbIteration.begin(), vbIteration.end());
    }

done:
    return mr;

error:
    pvbResult->clear();
    goto done;
} // end function PRF_P_hash

/*
** turns a cipher suite value from the wire (like 0x0005) into a cipher suite
** info object that has all of the parameters of it, like key length and so on
**
** caller can ask for the cipher info, hash info, or both
*/
_Use_decl_annotations_
MTERR_T
CryptoInfoFromCipherSuite(
    const MT_CipherSuite* pCipherSuite,
    CipherInfo* pCipherInfo,
    HashInfo* pHashInfo
)
{
    MTERR mr = MT_S_OK;
    MT_CipherSuiteValue eCSV;

    if (pHashInfo == nullptr && pCipherInfo == nullptr)
    {
        mr = MT_E_INVALIDARG;
        goto error;
    }

    CHKOK(pCipherSuite->GetValue(&eCSV));

    if (pHashInfo != nullptr)
    {
        switch (eCSV)
        {
            case MTCS_TLS_RSA_WITH_NULL_NULL:
            {
                *pHashInfo = c_HashInfo_NULL;
            }
            break;

            case MTCS_TLS_RSA_WITH_NULL_SHA:
            case MTCS_TLS_RSA_WITH_RC4_128_SHA:
            case MTCS_TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA:
            case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA:
            {
                *pHashInfo = c_HashInfo_SHA1;
            }
            break;

            case MTCS_TLS_RSA_WITH_NULL_SHA256:
            case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256:
            case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256:
            {
                *pHashInfo = c_HashInfo_SHA256;
            }
            break;

            default:
            {
                mr = MT_E_UNSUPPORTED_HASH;
                goto error;
            }
            break;
        }
    }

    if (pCipherInfo != nullptr)
    {
        switch (eCSV)
        {
            case MTCS_TLS_RSA_WITH_NULL_NULL:
            case MTCS_TLS_RSA_WITH_NULL_MD5:
            case MTCS_TLS_RSA_WITH_NULL_SHA:
            case MTCS_TLS_RSA_WITH_NULL_SHA256:
            {
                *pCipherInfo = c_CipherInfo_NULL;
            }
            break;

            case MTCS_TLS_RSA_WITH_RC4_128_MD5:
            case MTCS_TLS_RSA_WITH_RC4_128_SHA:
            {
                *pCipherInfo = c_CipherInfo_RC4_128;
            }
            break;

            case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA:
            case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256:
            {
                *pCipherInfo = c_CipherInfo_AES_128;
            }
            break;

            case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA:
            case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256:
            {
                *pCipherInfo = c_CipherInfo_AES_256;
            }
            break;

            default:
            {
                mr = MT_E_UNSUPPORTED_CIPHER;
                goto error;
            }
            break;
        }
    }

done:
    return mr;

error:
    goto done;
} // end function CryptoInfoFromCipherSuite


/*********** MT_Structure *****************/

_Use_decl_annotations_
MTERR_T
MT_Structure::ParseFrom(
    const MT_BYTE* pv,
    size_t cb
)
{
    return ParseFromPriv(pv, cb);
} // end function ParseFrom

_Use_decl_annotations_
MTERR_T
MT_Structure::ParseFromVect(
    const ByteVector* pvb
)
{
    return ParseFrom(&(pvb->front()), pvb->size());
} // end function ParseFromVect

_Use_decl_annotations_
MTERR_T
MT_Structure::Serialize(
    MT_BYTE* pv,
    size_t cb
) const
{
    return SerializePriv(pv, cb);
} // end function Serialize

_Use_decl_annotations_
MTERR_T
MT_Structure::SerializeToVect(
    ByteVector* pvb
) const
{
    pvb->clear();
    return SerializeAppendToVect(pvb);
} // end function SerializeToVect

/*
** make the vector big enough to also hold this object's serialized contents,
** but remember the original end. serialize this object just after the original
** end
*/
_Use_decl_annotations_
MTERR_T
MT_Structure::SerializeAppendToVect(
    ByteVector* pvb
) const
{
    size_t cbSize = pvb->size();
    ResizeVector(pvb, cbSize + Length());

    ByteVector::iterator end = pvb->begin() + cbSize;

    assert(pvb->end() >= (end + Length()));
    return Serialize(&(*end), Length());
} // end function SerializeAppendToVect


/*********** MT_Securable *****************/

MT_Securable::MT_Securable()
    : m_pEndpointParams(nullptr)
{
} // end ctor MT_Securable

_Use_decl_annotations_
MTERR_T
MT_Securable::CheckSecurity()
{
    assert(GetEndpointParams() != nullptr);
    return CheckSecurityPriv();
} // end function CheckSecurity


/*********** MT_RecordLayerMessage *****************/

_Use_decl_annotations_
MTERR_T
MT_ConnectionAware::SetConnection(
    TLSConnection* pConnection
)
{
    assert(m_pConnection == nullptr);
    m_pConnection = pConnection;
    return MT_S_OK;
} // end function SetConnection

/*********** MT_RecordLayerMessage *****************/

MT_RecordLayerMessage::MT_RecordLayerMessage()
    : MT_Structure(),
      MT_ConnectionAware(),
      m_contentType(),
      m_protocolVersion(),
      m_vbFragment()
{
} // end ctor MT_RecordLayerMessage

_Use_decl_annotations_
MTERR_T
MT_RecordLayerMessage::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;
    size_t cbFragmentLength = 0;

    PARSEPSTRUCT(GetContentType());

    PARSEPSTRUCT(GetProtocolVersion());

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    CHKOK(ReadNetworkLong(pv, cb, cbField, &cbFragmentLength));

    ADVANCE_PARSE();

    PARSEVB(cbFragmentLength, GetFragment());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MT_UINT16
MT_RecordLayerMessage::PayloadLength() const
{
    size_t cbLength = GetFragment()->size();
    assert(cbLength <= UINT16_MAX);
    return static_cast<MT_UINT16>(cbLength);
} // end function PayloadLength

_Use_decl_annotations_
size_t
MT_RecordLayerMessage::Length() const
{
    size_t cbLength = GetContentType()->Length() +
                      GetProtocolVersion()->Length() +
                      c_cbRecordLayerMessage_Fragment_LFL +
                      PayloadLength();

    return cbLength;
} // end function Length

_Use_decl_annotations_
MTERR_T
MT_RecordLayerMessage::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPSTRUCT(GetContentType());

    SERIALIZEPSTRUCT(GetProtocolVersion());

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    CHKOK(WriteNetworkLong(PayloadLength(), cbField, pv, cb));

    ADVANCE_PARSE();

    assert(PayloadLength() == GetFragment()->size());
    SERIALIZEPVB(GetFragment());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_Handshake *****************/

MT_Handshake::MT_Handshake()
    : MT_Structure(),
      m_eType(MTH_Unknown),
      m_vbBody()
{
} // end ctor MT_Handshake

_Use_decl_annotations_
MTERR_T
MT_Handshake::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbHandshakeType_Length;
    size_t cbPayloadLength = 0;

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetType())));

    if (!IsKnownType(*GetType()))
    {
        wprintf(L"warning: unknown handshake type: %u\n", *GetType());
    }

    ADVANCE_PARSE();

    cbField = c_cbHandshake_LFL;
    CHKOK(ReadNetworkLong(pv, cb, cbField, &cbPayloadLength));

    ADVANCE_PARSE();

    PARSEVB(cbPayloadLength, GetBody());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
size_t
MT_Handshake::Length() const
{
    return c_cbHandshakeType_Length +
           c_cbHandshake_LFL +
           PayloadLength();
} // end function Length

const MT_Handshake::MTH_HandshakeType MT_Handshake::c_rgeKnownTypes[] =
{
    MTH_HelloRequest,
    MTH_ClientHello,
    MTH_ServerHello,
    MTH_Certificate,
    MTH_ServerKeyExchange,
    MTH_CertificateRequest,
    MTH_ServerHelloDone,
    MTH_CertificateVerify,
    MTH_ClientKeyExchange,
    MTH_Finished,
    MTH_Unknown,
};

_Use_decl_annotations_
bool
MT_Handshake::IsKnownType(
    MTH_HandshakeType eType
)
{
    return (find(c_rgeKnownTypes, c_rgeKnownTypes+_countof(c_rgeKnownTypes), eType) != c_rgeKnownTypes+_countof(c_rgeKnownTypes));
} // end function IsKnownType

_Use_decl_annotations_
MTERR_T
MT_Handshake::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbHandshakeType_Length;

    CHKOK(WriteNetworkLong(static_cast<MT_UINT8>(*GetType()), cbField, pv, cb));

    ADVANCE_PARSE();

    cbField = c_cbHandshake_LFL;
    CHKOK(WriteNetworkLong(PayloadLength(), cbField, pv, cb));

    ADVANCE_PARSE();

    assert(PayloadLength() == GetBody()->size());
    SERIALIZEPVB(GetBody());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
wstring
MT_Handshake::HandshakeTypeString() const
{
    const wchar_t* wszType = nullptr;

    switch (*GetType())
    {
        case MTH_HelloRequest:
        wszType = L"HelloRequest";
        break;

        case MTH_ClientHello:
        wszType = L"ClientHello";
        break;

        case MTH_ServerHello:
        wszType = L"ServerHello";
        break;

        case MTH_Certificate:
        wszType = L"Certificate";
        break;

        case MTH_ServerKeyExchange:
        wszType = L"ServerKeyExchange";
        break;

        case MTH_CertificateRequest:
        wszType = L"CertificateRequest";
        break;

        case MTH_ServerHelloDone:
        wszType = L"ServerHelloDone";
        break;

        case MTH_CertificateVerify:
        wszType = L"CertificateVerify";
        break;

        case MTH_ClientKeyExchange:
        wszType = L"ClientKeyExchange";
        break;

        case MTH_Finished:
        wszType = L"Finished";
        break;

        default:
        wszType = L"Unknown";
        break;
    }

    return wstring(wszType);
} // end function HandshakeTypeString


/*********** MT_ClientHello *****************/

MT_ClientHello::MT_ClientHello()
    : MT_Structure(),
      m_clientVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuites(),
      m_compressionMethods(),
      m_extensions()
{
} // end ctor MT_ClientHello

_Use_decl_annotations_
MTERR_T
MT_ClientHello::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    PARSEPSTRUCT(GetClientVersion());

    PARSEPSTRUCT(GetRandom());

    PARSEPSTRUCT(GetSessionID());

    PARSEPSTRUCT(GetCipherSuites());

    PARSEPSTRUCT(GetCompressionMethods());

    PARSEPSTRUCT(GetExtensions());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
size_t
MT_ClientHello::Length() const
{
    size_t cbLength = GetClientVersion()->Length() +
                      GetRandom()->Length() +
                      GetSessionID()->Length() +
                      GetCipherSuites()->Length() +
                      GetCompressionMethods()->Length() +
                      GetExtensions()->Length();

    return cbLength;
} // end function Length


/*********** MT_ServerHello *****************/

MT_ServerHello::MT_ServerHello()
    : MT_Structure(),
      m_serverVersion(),
      m_random(),
      m_sessionID(),
      m_cipherSuite(),
      m_compressionMethod(),
      m_extensions()
{
} // end ctor MT_ServerHello

_Use_decl_annotations_
size_t
MT_ServerHello::Length() const
{
    size_t cbLength = GetServerVersion()->Length() +
                      GetRandom()->Length() +
                      GetSessionID()->Length() +
                      GetCipherSuite()->Length() +
                      GetCompressionMethod()->Length();

    if (GetExtensions()->Count() > 0)
    {
        cbLength += GetExtensions()->Length();
    }

    return cbLength;
} // end function Length

_Use_decl_annotations_
MTERR_T
MT_ServerHello::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPSTRUCT(GetServerVersion());

    SERIALIZEPSTRUCT(GetRandom());

    SERIALIZEPSTRUCT(GetSessionID());

    SERIALIZEPSTRUCT(GetCipherSuite());

    SERIALIZEPSTRUCT(GetCompressionMethod());

    if (GetExtensions()->Count() > 0)
    {
        SERIALIZEPSTRUCT(GetExtensions());
    }

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_ProtocolVersion *****************/

MT_ProtocolVersion::MT_ProtocolVersion()
    : MT_Structure(),
      m_eVersion(MTPV_Unknown)
{
} // end ctor MT_ProtocolVersion

_Use_decl_annotations_
MTERR_T
MT_ProtocolVersion::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbProtocolVersion_Length);

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT16*>(GetVersion())));

    ADVANCE_PARSE();

    if (!IsKnownVersion(*GetVersion()))
    {
        wprintf(L"warning: unknown protocol version: %04X\n", *GetVersion());
    }

done:
    return mr;

error:
    assert(SetVersion(MTPV_Unknown) == MT_S_OK);
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_ProtocolVersion::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbProtocolVersion_Length);

    CHKOK(WriteNetworkLong(static_cast<MT_UINT16>(*GetVersion()), cbField, pv, cb));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
bool
MT_ProtocolVersion::IsKnownVersion(
    MTPV_Version eVersion
)
{
    return (eVersion == MTPV_TLS10 ||
            eVersion == MTPV_TLS11 ||
            eVersion == MTPV_TLS12);
} // end function IsKnownVersion


/*********** MT_CipherSuite *****************/

MT_CipherSuite::MT_CipherSuite()
    : MT_FixedLengthByteStructure()
{
} // end ctor MT_CipherSuite

_Use_decl_annotations_
MT_CipherSuite::MT_CipherSuite(MT_CipherSuiteValue eValue)
    : MT_FixedLengthByteStructure()
{
    MTERR mr = SetValue(eValue);

    // catch if it's ever okay, because we're not throwing exceptions right now
    assert(mr == MT_S_OK);
} // end ctor MT_CipherSuite

_Use_decl_annotations_
MTERR_T
MT_CipherSuite::GetKeyExchangeAlgorithm(
    MT_KeyExchangeAlgorithm* pAlg
) const
{
    MTERR mr = MT_S_OK;
    MT_CipherSuiteValue eCSV;

    CHKOK(GetValue(&eCSV));

    switch (eCSV)
    {
        case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256:
        case MTCS_TLS_RSA_WITH_AES_256_CBC_SHA:
        case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256:
        case MTCS_TLS_RSA_WITH_AES_128_CBC_SHA:
        case MTCS_TLS_RSA_WITH_RC4_128_SHA:
        case MTCS_TLS_RSA_WITH_RC4_128_MD5:
        {
            *pAlg = MTKEA_rsa;
        }
        break;

        default:
        {
            mr = MT_E_UNKNOWN_CIPHER_SUITE;
            goto error;
        }
        break;
    }

done:
    return mr;

error:
    goto done;
} // end function GetKeyExchangeAlgorithm

_Use_decl_annotations_
MTERR_T
MT_CipherSuite::GetValue(
    MT_CipherSuiteValue* peValue
) const
{
    MTERR mr = MT_S_OK;
    MT_CipherSuiteValue cs;

    assert(GetData()->size() <= sizeof(cs));
    assert(GetData()->size() == c_cbCipherSuite_Length);

    CHKOK(ReadNetworkLong(
                     &GetData()->front(),
                     GetData()->size(),
                     GetData()->size(),
                     reinterpret_cast<MT_UINT16*>(&cs)));

    *peValue = cs;

done:
    return mr;

error:
    goto done;
} // end function GetValue

_Use_decl_annotations_
MTERR_T
MT_CipherSuite::SetValue(
    MT_CipherSuiteValue eValue
)
{
    MTERR mr = MT_S_OK;

    ResizeVector(GetData(), c_cbCipherSuite_Length);

    CHKOK(WriteNetworkLong(
             static_cast<MT_UINT16>(eValue),
             GetData()->size(),
             &GetData()->front(),
             GetData()->size()));

done:
    return mr;

error:
    goto done;
} // end function SetValue

_Use_decl_annotations_
bool
MT_CipherSuite::operator==(
    const MT_CipherSuite& rOther
) const
{
    MTERR mr = MT_S_OK;
    MT_CipherSuiteValue eValue;
    MT_CipherSuiteValue eOtherValue;
    mr = GetValue(&eValue);
    if (mr != MT_S_OK)
    {
        return false;
    }

    mr = rOther.GetValue(&eOtherValue);
    if (mr != MT_S_OK)
    {
        return false;
    }

    return eValue == eOtherValue;
} // end operator==

const MT_CipherSuiteValue c_rgeCipherSuitePreference[] =
{
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA256,
      MTCS_TLS_RSA_WITH_AES_256_CBC_SHA,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA256,
      MTCS_TLS_RSA_WITH_AES_128_CBC_SHA,
      MTCS_TLS_RSA_WITH_RC4_128_SHA,
      MTCS_TLS_RSA_WITH_RC4_128_MD5
};

_Use_decl_annotations_
const vector<MT_CipherSuiteValue>* GetCipherSuitePreference()
{
    static vector<MT_CipherSuiteValue> s_veCipherSuiteValues;

    MT_C_ASSERT(_countof(c_rgeCipherSuitePreference) > 0);

    // first time initialization
    if (s_veCipherSuiteValues.empty())
    {
        s_veCipherSuiteValues.assign(
            c_rgeCipherSuitePreference,
            c_rgeCipherSuitePreference + _countof(c_rgeCipherSuitePreference));
    }

    return &s_veCipherSuiteValues;
} // end function GetCipherSuitePreference

/*
** the client advertises its cipher suite preference in the ClientHello
** message. on the server here, we have an internal ordering of preference, and
** this function puts the two together and picks the server's favorite that the
** client also advertises support for
*/
_Use_decl_annotations_
MTERR_T
ChooseBestCipherSuite(
    const vector<MT_CipherSuiteValue>* pveClientPreference,
    const vector<MT_CipherSuiteValue>* pveServerPreference,
    MT_CipherSuiteValue* pePreferredCipherSuite
)
{
    MTERR mr = MT_S_OK;

    // loop through server supports. if client also supports it, woot
    for (auto itServer = pveServerPreference->begin(); itServer != pveServerPreference->end(); itServer++)
    {
        for (auto itClient = pveClientPreference->begin(); itClient != pveClientPreference->end(); itClient++)
        {
            if (*itClient == *itServer)
            {
                *pePreferredCipherSuite = *itServer;
                goto done;
            }
        }
    }

    mr = MT_E_NO_PREFERRED_CIPHER_SUITE;
    goto error;

done:
    return mr;

error:
    goto done;
} // end function ChooseBestCipherSuite


/*********** MT_ContentType *****************/

MT_ContentType::MT_ContentType()
    : MT_Structure(),
      m_eType(MTCT_Type_Unknown)
{
} // end ctor MT_ContentType

_Use_decl_annotations_
MTERR_T
MT_ContentType::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbContentType_Length);

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetType())));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_ContentType::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;

    size_t cbField = Length();
    assert(Length() == c_cbContentType_Length);

    CHKOK(WriteNetworkLong(static_cast<MT_UINT8>(*GetType()), cbField, pv, cb));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
wstring
MT_ContentType::ToString() const
{
    switch (*GetType())
    {
        case MTCT_Type_ChangeCipherSpec:
            return wstring(L"ChangeCipherSpec");
        break;

        case MTCT_Type_Alert:
            return wstring(L"Alert");
        break;

        case MTCT_Type_Handshake:
            return wstring(L"Handshake");
        break;

        case MTCT_Type_ApplicationData:
            return wstring(L"ApplicationData");
        break;

        default:
            return wstring(L"UnknownContentType");
        break;
    }
} // end function ToString


/*********** MT_Random *****************/

MT_Random::MT_Random()
    : MT_Structure(),
      m_timestamp(0),
      m_randomBytes()
{
} // end ctor MT_Random

_Use_decl_annotations_
MTERR_T
MT_Random::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;

    size_t cbField = c_cbRandomTime_Length;
    CHKOK(ReadNetworkLong(pv, cb, cbField, &m_timestamp));

    ADVANCE_PARSE();

    PARSEPSTRUCT(GetRandomBytes());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_Random::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbRandomTime_Length;

    CHKOK(WriteNetworkLong(*GetGMTUnixTime(), cbField, pv, cb));

    ADVANCE_PARSE();

    SERIALIZEPSTRUCT(GetRandomBytes());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
MTERR_T
MT_Random::PopulateNow()
{
    MTERR mr = MT_S_OK;
    CHKOK(GetCurrentGMTTime(GetGMTUnixTime()));

    // ResizeVector fills with a fixed value, for easier debugging
    ResizeVector(GetRandomBytes()->GetData(), c_cbRandomBytes_Length);

    /* or else could fill with actual random bytes
    CHKOK(WriteRandomBytes(&GetRandomBytes()->front(), GetRandomBytes()->size()));
    */

done:
    return mr;

error:
    goto done;
} // end function PopulateNow


/*********** MT_CompressionMethod *****************/

MT_CompressionMethod::MT_CompressionMethod()
    : MT_Structure(),
      m_eMethod(MTCM_Unknown)
{
} // end ctor MT_CompressionMethod

_Use_decl_annotations_
MTERR_T
MT_CompressionMethod::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbCompressionMethod_Length);

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetMethod())));

    if (*GetMethod() != MTCM_Null)
    {
        wprintf(L"warning: unknown compression method: %u\n", *GetMethod());
    }

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_CompressionMethod::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbCompressionMethod_Length);

    CHKOK(WriteNetworkLong(static_cast<MT_UINT8>(*GetMethod()), cbField, pv, cb));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_Certificate *****************/

MT_Certificate::MT_Certificate()
    : MT_Structure(),
      m_certificateList()
{
} // end ctor MT_Certificate

_Use_decl_annotations_
MTERR_T
MT_Certificate::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPSTRUCT(GetCertificateList());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
MTERR_T
MT_Certificate::AddCertificateFromMemory(
    const MT_BYTE* pvCert,
    size_t cbCert
)
{
    MT_ASN1Cert cert;
    cert.GetData()->assign(pvCert, pvCert + cbCert);
    GetCertificateList()->GetData()->push_back(cert);
    return MT_S_OK;
} // end function AddCertificateFromMemory


/*********** MT_SessionID *****************/

_Use_decl_annotations_
MTERR_T
MT_SessionID::PopulateWithRandom()
{
    MTERR mr = MT_S_OK;

    ResizeVector(GetData(), MaxLength());

    CHKOK(WriteRandomBytes(&GetData()->front(), GetData()->size()));

done:
    return mr;

error:
    goto done;
} // end function PopulateWithRandom


/*********** MT_Extension *****************/

MT_Extension::MT_Extension()
    : MT_Structure(),
      m_extensionType(MTEE_Unknown),
      m_extensionData()
{
} // end ctor MT_Extension

_Use_decl_annotations_
MTERR_T
MT_Extension::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbExtensionType_Length;

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT16*>(GetExtensionType())));

    ADVANCE_PARSE();

    PARSEPSTRUCT(GetExtensionData());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
size_t
MT_Extension::Length() const
{
    size_t cbLength = c_cbExtensionType_Length +
                      GetExtensionData()->Length();
    return cbLength;
} // end function Length

_Use_decl_annotations_
MTERR_T
MT_Extension::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    cbField = c_cbExtensionType_Length;
    CHKOK(WriteNetworkLong(static_cast<MT_UINT16>(*GetExtensionType()), cbField, pv, cb));

    ADVANCE_PARSE();

    SERIALIZEPSTRUCT(GetExtensionData());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_PreMasterSecret *****************/

MT_PreMasterSecret::MT_PreMasterSecret()
    : MT_Structure(),
      m_clientVersion(),
      m_random()
{
} // end ctor MT_PreMasterSecret

_Use_decl_annotations_
MTERR_T
MT_PreMasterSecret::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    PARSEPSTRUCT(GetClientVersion());

    PARSEPSTRUCT(GetRandom());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_PreMasterSecret::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPSTRUCT(GetClientVersion());

    SERIALIZEPSTRUCT(GetRandom());

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
size_t
MT_PreMasterSecret::Length() const
{
    size_t cbLength = GetClientVersion()->Length() +
                      GetRandom()->Length();

    return cbLength;
} // end function Length


/*********** MT_ChangeCipherSpec *****************/

MT_ChangeCipherSpec::MT_ChangeCipherSpec()
    : MT_Structure(),
      m_eType(MTCCS_Unknown)
{
} // end ctor MT_ChangeCipherSpec

_Use_decl_annotations_
MTERR_T
MT_ChangeCipherSpec::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();

    assert(Length() == c_cbChangeCipherSpec_Length);

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetType())));

    if (*GetType() != MTCCS_ChangeCipherSpec)
    {
        wprintf(L"warning: unrecognized change cipher spec type: %u\n", *GetType());
    }

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_ChangeCipherSpec::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = Length();
    assert(Length() == c_cbChangeCipherSpec_Length);

    CHKOK(WriteNetworkLong(static_cast<MT_BYTE>(*GetType()), cbField, pv, cb));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function SerializePriv


/*********** MT_Finished *****************/

MT_Finished::MT_Finished()
    : MT_Structure(),
      MT_Securable(),
      m_verifyData()
{
} // end ctor MT_Finished

_Use_decl_annotations_
MTERR_T
MT_Finished::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    return GetVerifyData()->ParseFrom(pv, cb);
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_Finished::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    return GetVerifyData()->Serialize(pv, cb);
} // end function SerializePriv

/*
** using data gathered across the whole handshake, compute some "verify data"
** that can be used to ensure that the client sent us data encrypted with the
** correct cipher suite. this is basically a hash of all the handshake messages
** involved so far
*/
_Use_decl_annotations_
MTERR_T
MT_Finished::CheckSecurityPriv()
{
    MTERR mr = MT_S_OK;

    ByteVector vbComputedVerifyData;

    CHKOK(ComputeVerifyData(
             c_szClientFinished_PRFLabel,
             &vbComputedVerifyData));

    wprintf(L"Received Finished hash:\n");
    PrintByteVector(GetVerifyData()->GetData());

    if (vbComputedVerifyData != *GetVerifyData()->GetData())
    {
        mr = MT_E_BAD_FINISHED_HASH;
        goto error;
    }

done:
    return mr;

error:
    goto done;
} // end function CheckSecurityPriv

/*
** TLS 1.0
** verify_data
**     PRF(master_secret, finished_label, MD5(handshake_messages) +
**     SHA-1(handshake_messages)) [0..11];
**
** TLS 1.2
** verify_data
**    PRF(master_secret, finished_label, Hash(handshake_messages))
**       [0..verify_data_length-1];
**
** take a hash (or two) of all handshake messages using the master secret
*/
_Use_decl_annotations_
MTERR_T
MT_Finished::ComputeVerifyData(
    const char* szLabel,
    ByteVector* pvbVerifyData
)
{
    MTERR mr = MT_S_OK;

    ByteVector vbHandshakeMessages;
    ByteVector vbHashedHandshakeMessages;

    { // just logging
        wprintf(L"compute verify data: working on the following handshake messages:\n");
        for_each(
            GetConnParams()->GetHandshakeMessages()->begin(),
            GetConnParams()->GetHandshakeMessages()->end(),
            [] (shared_ptr<const MT_Structure> spStructure)
            {
                const MT_Handshake* pHandshakeMessage = static_cast<const MT_Handshake*>(spStructure.get());
                wprintf(L"    %s\n", pHandshakeMessage->HandshakeTypeString().c_str());
            }
        );
    }

    CHKOK(SerializeMessagesToVector<MT_Structure>(
             GetConnParams()->GetHandshakeMessages()->begin(),
             GetConnParams()->GetHandshakeMessages()->end(),
             &vbHandshakeMessages));

    switch (*GetEndpointParams()->GetVersion())
    {
        case MT_ProtocolVersion::MTPV_TLS10:
        case MT_ProtocolVersion::MTPV_TLS11:
        {
            ByteVector vbMD5HandshakeHash;
            ByteVector vbSHA1HandshakeHash;
            ByteVector vbHandshakeHash;

            // MD5 hash
            CHKOK(GetEndpointParams()->GetHasher()->Hash(
                     &c_HashInfo_MD5,
                     &vbHandshakeMessages,
                     &vbMD5HandshakeHash));

            // SHA1 hash
            CHKOK(GetEndpointParams()->GetHasher()->Hash(
                     &c_HashInfo_SHA1,
                     &vbHandshakeMessages,
                     &vbSHA1HandshakeHash));

            // concatenate
            vbHashedHandshakeMessages = vbMD5HandshakeHash;
            vbHashedHandshakeMessages.insert(
                vbHashedHandshakeMessages.end(),
                vbSHA1HandshakeHash.begin(),
                vbSHA1HandshakeHash.end());
        }
        break;

        // TLS 1.2 just uses a SHA-256 hash
        case MT_ProtocolVersion::MTPV_TLS12:
        {
            CHKOK(GetEndpointParams()->GetHasher()->Hash(
                     &c_HashInfo_SHA256,
                     &vbHandshakeMessages,
                     &vbHashedHandshakeMessages));
        }
        break;

        default:
        {
            wprintf(L"unrecognized version: %04LX\n", *GetEndpointParams()->GetVersion());
            mr = MT_E_UNKNOWN_PROTOCOL_VERSION;
            goto error;
        }
        break;
    }

    CHKOK(GetConnParams()->ComputePRF(
             GetConnParams()->GetMasterSecret(),
             szLabel,
             &vbHashedHandshakeMessages,
             c_cbFinishedVerifyData_Length,
             pvbVerifyData));

    printf("Computed Finished hash with label \"%s\":\n", szLabel);
    PrintByteVector(pvbVerifyData);

done:
    return mr;

error:
    goto done;
} // end function ComputeVerifyData


/*********** MT_ServerHelloDone *****************/

MT_ServerHelloDone::MT_ServerHelloDone()
    : MT_Structure()
{
} // end ctor MT_ServerHelloDone

_Use_decl_annotations_
MTERR_T
MT_ServerHelloDone::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MT_UNREFERENCED_PARAMETER(pv);
    MT_UNREFERENCED_PARAMETER(cb);

    // 0-byte structure
    return MT_S_OK;
} // end function SerializePriv


/*********** MT_HelloRequest *****************/

MT_HelloRequest::MT_HelloRequest()
    : MT_Structure()
{
} // end ctor MT_HelloRequest

_Use_decl_annotations_
MTERR_T
MT_HelloRequest::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MT_UNREFERENCED_PARAMETER(pv);
    MT_UNREFERENCED_PARAMETER(cb);

    // 0-byte structure
    return MT_S_OK;
} // end function SerializePriv


/*********** MT_TLSCiphertext *****************/

MT_TLSCiphertext::MT_TLSCiphertext()
    : MT_RecordLayerMessage(),
      MT_Securable(),
      m_pServerListener(nullptr),
      m_spCipherFragment()
{
} // end ctor MT_TLSCiphertext

/*
** this doubles as a factory that knows how to create the right type of cipher
** fragment to use for the payload. this pivots on the cipher type and the
** protocol version
**
** note that we pass in "this" when creating the cipher fragment. it calls back
** up to us to get to the app for questions sometimes
*/
_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::SetEndpointParams(
    EndpointParameters* pEndParams
)
{
    MTERR mr = MT_S_OK;

    CHKOK(MT_Securable::SetEndpointParams(pEndParams));

    switch (GetEndpointParams()->GetCipher()->type)
    {
        case CipherType_Stream:
        {
            CHKOK(SetCipherFragment(shared_ptr<MT_CipherFragment>(new MT_GenericStreamCipher(this))));
        }
        break;

        case CipherType_Block:
        {
            switch (*GetEndpointParams()->GetVersion())
            {
                case MT_ProtocolVersion::MTPV_TLS10:
                {
                    CHKOK(SetCipherFragment(shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS10(this))));
                }
                break;

                case MT_ProtocolVersion::MTPV_TLS11:
                {
                    CHKOK(SetCipherFragment(shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS11(this))));
                }
                break;

                case MT_ProtocolVersion::MTPV_TLS12:
                {
                    CHKOK(SetCipherFragment(shared_ptr<MT_CipherFragment>(new MT_GenericBlockCipher_TLS12(this))));
                }
                break;

                default:
                {
                    // at this point we should've filtered out unknown versions
                    assert(false);
                }
                break;
            }
        }
        break;

        default:
        {
            // indicates we've added a new cipher type without updating here
            assert(false);
        }
        break;
    }

    // propagate down the endpoint parameters to the fragment
    CHKOK(GetCipherFragment()->SetEndpointParams(GetEndpointParams()));

done:
    return mr;

error:
    goto done;
} // end function SetEndpointParams

_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::Decrypt()
{
    MTERR mr = MT_S_OK;

    /*
    ** the resultant ParseFromPriv call does the actual decryption.
    ** it is crucial that this pass in exactly the fragment assigned to this
    ** TLSCiphertext--no more, no less--because CipherFragment itself has no
    ** way to validate the length. it just accepts everything it's given
    */
    CHKOK(GetCipherFragment()->ParseFromVect(GetFragment()));

done:
    return mr;

error:
    goto done;
} // end function Decrypt

_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::ToTLSPlaintext(
    MT_TLSPlaintext* pPlaintext
)
{
    MTERR mr = MT_S_OK;

    // plaintext becomes associated with the same connection as this ciphertext
    CHKOK(pPlaintext->SetConnection(GetConnection()));

    CHKOK(pPlaintext->SetContentType(GetContentType()));
    CHKOK(pPlaintext->SetProtocolVersion(GetProtocolVersion()));

    // assumes the ciphertext has already been decrypted
    CHKOK(pPlaintext->SetFragment(GetCipherFragment()->GetContent()));

done:
    return mr;

error:
    goto done;
} // end function ToTLSPlaintext

_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::FromTLSPlaintext(
    MT_TLSPlaintext* pPlaintext,
    EndpointParameters* pEndParams,
    shared_ptr<MT_TLSCiphertext>* pspCiphertext
)
{
    MTERR mr = MT_S_OK;

    pspCiphertext->reset(new MT_TLSCiphertext());

    CHKOK(pPlaintext->GetConnection()->CreateCiphertext(
             *pPlaintext->GetContentType()->GetType(),
             *pPlaintext->GetProtocolVersion()->GetVersion(),
             pPlaintext->GetFragment(),
             pEndParams,
             pspCiphertext->get()));

done:
    return mr;

error:
    goto done;
} // end function FromTLSPlaintext

// effectively adds a MAC to the payload and encrypts the whole thing
_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::Protect()
{
    MTERR mr = MT_S_OK;

    assert(GetEndpointParams()->GetCipher()->type == CipherType_Stream ||
           (GetEndpointParams()->GetCipher()->type == CipherType_Block &&
            (*GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS10 ||
             *GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS11 ||
             *GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS12)));

    CHKOK(GetCipherFragment()->UpdateWriteSecurity());

    CHKOK(GetCipherFragment()->SerializeToVect(GetFragment()));

done:
    return mr;

error:
    goto done;
} // end function Protect

_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::GetProtocolVersionForSecurity(
    MT_ProtocolVersion* pVersion
)
{
    MTERR mr = MT_S_OK;

    MT_ProtocolVersion hashVersion(*GetProtocolVersion());

    /*
    ** some browsers like chrome and openssl do weird things with version
    ** negotiation, where they specify the wrong version in a ClientHello
    ** message for compatibility reasons.
    **
    ** if we detect such a mismatch here, we ask the app if it wants to
    ** reconcile it. the default behavior is to strictly follow the RFC and use
    ** the record layer version
    */
    if (*GetEndpointParams()->GetVersion() != *hashVersion.GetVersion())
    {
        MT_ProtocolVersion::MTPV_Version ver;

        wprintf(L"reconciling version mismatch between conn:%04LX and record:%04LX\n", *GetEndpointParams()->GetVersion(), *hashVersion.GetVersion());

        mr = GetServerListener()->OnReconcileSecurityVersion(
                 this,
                 *GetEndpointParams()->GetVersion(),
                 *hashVersion.GetVersion(),
                 &ver);

        if (mr == MT_S_LISTENER_HANDLED)
        {
            CHKOK(hashVersion.SetVersion(ver));
        }
        else if (MT_Failed(mr))
        {
            __assume(mr != MT_S_OK);
            goto error;
        }

        // else retain current record's protocol version
        mr = MT_S_OK;
    }

    *pVersion = hashVersion;

done:
    return mr;

error:
    goto done;
} // end function GetProtocolVersionForSecurity

// effectively checks the MAC
_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::CheckSecurityPriv()
{
    MTERR mr = MT_S_OK;

    assert(GetEndpointParams()->GetCipher()->type == CipherType_Stream ||
           (GetEndpointParams()->GetCipher()->type == CipherType_Block &&
            (*GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS10 ||
             *GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS11 ||
             *GetEndpointParams()->GetVersion() == MT_ProtocolVersion::MTPV_TLS12)));

    CHKOK(GetCipherFragment()->CheckSecurity());

done:
    return mr;

error:
    goto done;
} // end function CheckSecurityPriv

// the next IV to use is either the last ciphertext block or a "random" value
_Use_decl_annotations_
MTERR_T
MT_TLSCiphertext::GenerateNextIV(ByteVector* pvbIV)
{
    MTERR mr = MT_S_OK;
    static MT_BYTE iIVSeed = 1;

    switch (*GetEndpointParams()->GetVersion())
    {
        case MT_ProtocolVersion::MTPV_TLS10:
            pvbIV->assign(GetFragment()->end() - GetEndpointParams()->GetCipher()->cbIVSize, GetFragment()->end());
        break;

        case MT_ProtocolVersion::MTPV_TLS11:
        case MT_ProtocolVersion::MTPV_TLS12:
            pvbIV->assign(GetEndpointParams()->GetCipher()->cbIVSize, iIVSeed);
            iIVSeed++;
        break;

        default:
            assert(false);
            mr = MT_E_FAIL;
        break;
    }

    return mr;
} // end function GenerateNextIV


/*********** MT_CipherFragment *****************/

_Use_decl_annotations_
MT_CipherFragment::MT_CipherFragment(
    MT_TLSCiphertext* pCiphertext
)
    : MT_Structure(),
      MT_Securable(),
      m_vbContent(),
      m_vbEncryptedContent(),
      m_pCiphertext(pCiphertext)
{
} // end ctor MT_CipherFragment

/*
** basically just assimilates the whole byte blob. it's important that the
** containing/calling structure pass in exactly the right size here, because at
** this point we have no way of determining what the size should be. this
** EncryptedContent is still ciphered, not plaintext
*/
_Use_decl_annotations_
MTERR_T
MT_CipherFragment::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    PARSEVB(cb, GetEncryptedContent());

    assert(cb == 0);

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

/*
** the ciphering for EncryptedContent needs to have been done separately and
** prior to calling this
*/
_Use_decl_annotations_
MTERR_T
MT_CipherFragment::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPVB(GetEncryptedContent());

    assert(cb == 0);

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
size_t
MT_CipherFragment::Length() const
{
    return GetEncryptedContent()->size();
} // end function Length

/*
** compute the MAC for this message. this is used both for attaching a MAC to
** an outgoing message and for comparing against the MAC found in an incoming
** message.
**
** TLS 1.0
** HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
**               TLSCompressed.version + TLSCompressed.length +
**               TLSCompressed.fragment));
**
** basically just put a bunch of fields together and hash it with the MAC key,
** which was generated back with the master secret
*/
_Use_decl_annotations_
MTERR_T
MT_CipherFragment::ComputeMAC(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC
)
{
    MTERR mr = MT_S_OK;

    ByteVector vbHashText;
    MT_BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;

    const HashInfo* pHashInfo = GetEndpointParams()->GetHash();

    assert(pProtocolVersion->Length() == c_cbProtocolVersion_Length);
    assert(pContentType->Length() == c_cbContentType_Length);

    cb = c_cbSequenceNumber_Length +
         pContentType->Length() +
         pProtocolVersion->Length() +
         c_cbRecordLayerMessage_Fragment_LFL +
         GetContent()->size();

    wprintf(L"MAC text is %Iu bytes\n", cb);

    ResizeVector(&vbHashText, cb);
    pv = &vbHashText.front();

    wprintf(L"sequence number: %I64u\n", sequenceNumber);

    cbField = c_cbSequenceNumber_Length;
    CHKOK(WriteNetworkLong(
             sequenceNumber,
             cbField,
             pv,
             cb));

    ADVANCE_PARSE();

    SERIALIZEPSTRUCT(pContentType);

    SERIALIZEPSTRUCT(pProtocolVersion);

    cbField = c_cbRecordLayerMessage_Fragment_LFL;
    CHKOK(WriteNetworkLong(
             GetContent()->size(),
             cbField,
             pv,
             cb));

    ADVANCE_PARSE();

    SERIALIZEPVB(GetContent());

    assert(cb == 0);

    wprintf(L"MAC hash text:\n");
    PrintByteVector(&vbHashText);

    CHKOK(GetEndpointParams()->GetHasher()->HMAC(
             pHashInfo,
             pvbMACKey,
             &vbHashText,
             pvbMAC));

    assert(pvbMAC->size() == pHashInfo->cbHashSize);

done:
    return mr;

error:
    goto done;
} // end function ComputeMAC


/*********** MT_GenericStreamCipher *****************/

_Use_decl_annotations_
MT_GenericStreamCipher::MT_GenericStreamCipher(
    MT_TLSCiphertext* pCiphertext
)
    : MT_CipherFragment(pCiphertext),
      m_vbMAC()
{
} // end ctor MT_GenericStreamCipher

_Use_decl_annotations_
MTERR_T
MT_GenericStreamCipher::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    const HashInfo* pHashInfo = GetEndpointParams()->GetHash();
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    CHKOK(MT_CipherFragment::ParseFromPriv(pv, cb));

    /*
    ** we have to be careful only to call this when we mean it, or else it
    ** changes the internal state of the cipherer down in cryptapi
    */
    CHKOK(GetEndpointParams()->GetSymCipherer()->DecryptBuffer(
             GetEncryptedContent(),
             nullptr, // no IV for stream ciphers
             &vbDecryptedStruct));

    // once we have the plaintext, start over the parsing
    pv = &vbDecryptedStruct.front();
    cb = vbDecryptedStruct.size();

    /*
    ** allows for 0-length content (i.e. content that is only the hash). if the
    ** subtraction here underflows, the resultant size we try to parse will be
    ** huge, and therefore fail, so it should be safe. Or we could have used
    ** MT_SizeTSub().
    */
    PARSEVB(cb - pHashInfo->cbHashSize, GetContent());

    assert(cb == pHashInfo->cbHashSize);

    PARSEVB(pHashInfo->cbHashSize, GetMAC());

    assert(cb == 0);

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_GenericStreamCipher::UpdateWriteSecurity()
{
    MTERR mr = MT_S_OK;
    MT_BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;
    ByteVector vbPlaintextStruct;

    // get the MAC to attach to this message
    CHKOK(ComputeSecurityInfo(
              *GetEndpointParams()->GetSequenceNumber(),
              GetEndpointParams()->GetMACKey(),
              GetCiphertext()->GetContentType(),
              GetCiphertext()->GetProtocolVersion(),
              GetMAC()));

    assert(GetMAC()->size() == GetEndpointParams()->GetHash()->cbHashSize);

    cb = GetContent()->size() +
         GetMAC()->size();

    ResizeVector(&vbPlaintextStruct, cb);
    pv = &vbPlaintextStruct.front();

    SERIALIZEPVB(GetContent());

    SERIALIZEPVB(GetMAC());

    assert(cb == 0);

    CHKOK(GetEndpointParams()->GetSymCipherer()->EncryptBuffer(
             &vbPlaintextStruct,
             nullptr, // no IV for stream ciphers
             GetEncryptedContent()));

    assert(!GetEncryptedContent()->empty());

done:
    return mr;

error:
    goto done;
} // end function UpdateWriteSecurity

/*
** compute the MAC for this message. this is used both for attaching a MAC to
** an outgoing message and for comparing against the MAC found in an incoming
** message.
**
** TLS 1.0
** HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
**               TLSCompressed.version + TLSCompressed.length +
**               TLSCompressed.fragment));
**
** basically just put a bunch of fields together and hash it with the MAC key,
** which was generated back with the master secret
*/
_Use_decl_annotations_
MTERR_T
MT_GenericStreamCipher::ComputeSecurityInfo(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC
)
{
    return ComputeMAC(
               sequenceNumber,
               pvbMACKey,
               pContentType,
               pProtocolVersion,
               pvbMAC);
} // end function ComputeSecurityInfo

// compare the MAC that we compute to the one received in the message
_Use_decl_annotations_
MTERR_T
MT_GenericStreamCipher::CheckSecurityPriv()
{
    MTERR mr = MT_S_OK;
    ByteVector vbMAC;
    MT_ProtocolVersion hashVersion;

    CHKOK(GetCiphertext()->GetProtocolVersionForSecurity(&hashVersion));

    CHKOK(ComputeSecurityInfo(
              *GetEndpointParams()->GetSequenceNumber(),
              GetEndpointParams()->GetMACKey(),
              GetCiphertext()->GetContentType(),
              &hashVersion,
              &vbMAC));

    wprintf(L"received MAC:\n");
    PrintByteVector(GetMAC());

    wprintf(L"computed MAC:\n");
    PrintByteVector(&vbMAC);

    if (*GetMAC() != vbMAC)
    {
        mr = MT_E_BAD_RECORD_MAC;
        goto error;
    }

done:
    return mr;

error:
    goto done;
} // end function CheckSecurityPriv


/*********** MT_GenericBlockCipher *****************/

_Use_decl_annotations_
MT_GenericBlockCipher::MT_GenericBlockCipher(
    MT_TLSCiphertext* pCiphertext
)
    : MT_CipherFragment(pCiphertext),
      m_vbMAC(),
      m_vbPadding()
{
} // end ctor MT_GenericBlockCipher

// parses and also decrypts... then parses the decrypted part, too
_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    const HashInfo* pHashInfo = GetEndpointParams()->GetHash();
    const MT_BYTE* pvEnd = nullptr;
    MT_UINT8 cbPaddingLength = 0;
    size_t cbField = 0;
    ByteVector vbDecryptedStruct;

    CHKOK(MT_CipherFragment::ParseFromPriv(pv, cb));

    /*
    ** we have to be careful only to call this when we mean it, or else it
    ** changes the internal state of the cipherer
    */
    CHKOK(GetEndpointParams()->GetSymCipherer()->DecryptBuffer(
             GetEncryptedContent(),
             GetIV(),
             &vbDecryptedStruct));

    // now restart the parsing with the decrypted content
    pv = &vbDecryptedStruct.front();
    cb = vbDecryptedStruct.size();

    // parse from the end backwards, starting with the padding
    cbField = c_cbGenericBlockCipher_Padding_LFL;
    pvEnd = &pv[cb - cbField];
    if (cb < cbField)
    {
        mr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    CHKOK(ReadNetworkLong(pvEnd, cbField, cbField, &cbPaddingLength));

    // not advancing pv, only changing cb (how much is left to parse)
    SAFE_SUB(mr, cb, cbField);
    pvEnd -= cbField;

    cbField = cbPaddingLength;
    if (cb < cbField)
    {
        mr = MT_E_INCOMPLETE_MESSAGE;
        goto error;
    }

    /*
    ** example:
    ** cbPaddingLength = cbField = 5
    **
    ** yy yy yy 05 05 05 05 05 05
    **          ^           ^  ^
    **          |           |  padding length
    **          |           |
    **          |           pvEnd
    **          pvEnd -
    **          cbField + 1
    */
    GetPadding()->assign(pvEnd - cbField + 1, pvEnd + 1);

    {
        ByteVector vbExpectedPadding(cbPaddingLength, static_cast<MT_BYTE>(cbPaddingLength));
        if (*GetPadding() != vbExpectedPadding)
        {
            mr = MT_E_BAD_RECORD_PADDING;
            goto error;
        }
    }

    /*
    ** not advancing pv, only subtracting from cb, since we've pulled the
    ** padding off the end
    */
    SAFE_SUB(mr, cb, cbField);
    pvEnd -= cbField;

    /*
    ** at this point we've stripped out the padding. pv points to the start of
    ** the payload, and cb is the number of bytes in the payload plus MAC.
    ** parse out these two things now
    */

    PARSEVB(cb - pHashInfo->cbHashSize, GetContent());

    assert(cb == pHashInfo->cbHashSize);

    PARSEVB(pHashInfo->cbHashSize, GetMAC());

    assert(cb == 0);

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

/*
** this is called to prepare the contents for being serialized. it takes the
** plaintext payload, attaches the MAC to it, and encrypts it
*/
_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher::UpdateWriteSecurity()
{
    MTERR mr = MT_S_OK;
    MT_BYTE* pv = nullptr;
    size_t cb = 0;
    size_t cbField = 0;
    ByteVector vbPlaintextContent;

    CHKOK(ComputeSecurityInfo(
             *GetEndpointParams()->GetSequenceNumber(),
             GetEndpointParams()->GetMACKey(),
             GetCiphertext()->GetContentType(),
             GetCiphertext()->GetProtocolVersion(),
             GetMAC(),
             GetPadding()));

    assert(GetMAC()->size() == GetEndpointParams()->GetHash()->cbHashSize);

    cb = GetContent()->size() +
         GetMAC()->size() +
         GetPadding()->size() +
         c_cbGenericBlockCipher_Padding_LFL;

    {
        const CipherInfo* pCipherInfo = GetEndpointParams()->GetCipher();
        assert(pCipherInfo->type == CipherType_Block);

        /*
        ** this check makes sure that GetPadding() was the right size to make
        ** the total size of the payload a multiple of the block size, which is
        ** a requirement for block ciphers
        */
        assert((cb % pCipherInfo->cbBlockSize) == 0);
    }

    // serializing into vbPlaintextContent
    ResizeVector(&vbPlaintextContent, cb);
    pv = &vbPlaintextContent.front();

    SERIALIZEPVB(GetContent());

    SERIALIZEPVB(GetMAC());

    SERIALIZEPVB(GetPadding());

    cbField = c_cbGenericBlockCipher_Padding_LFL;
    CHKOK(WriteNetworkLong(PaddingLength(), cbField, pv, cb));

    ADVANCE_PARSE();

    assert(cb == 0);

    CHKOK(GetEndpointParams()->GetSymCipherer()->EncryptBuffer(
             &vbPlaintextContent,
             GetIV(),
             GetEncryptedContent()));

    assert(!GetEncryptedContent()->empty());

done:
    return mr;

error:
    goto done;
} // end function UpdateWriteSecurity

// primarily this makes sure the padding is less then 256 bytes long
_Use_decl_annotations_
MT_UINT8
MT_GenericBlockCipher::PaddingLength() const
{
    MTERR mr = MT_S_OK;
    MT_BYTE b = 0;
    mr = MT_SizeTToByte(GetPadding()->size(), &b);
    assert(mr == MT_S_OK);
    return b;
} // end function PaddingLength

/*
** computes the "security info", aka MAC. see
** MT_GenericStreamCipher::ComputeSecurityInfo for more info. this differs from
** the stream cipher only in that it also computes the padding for the block
*/
_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher::ComputeSecurityInfo(
    MT_UINT64 sequenceNumber,
    const ByteVector* pvbMACKey,
    const MT_ContentType* pContentType,
    const MT_ProtocolVersion* pProtocolVersion,
    ByteVector* pvbMAC,
    ByteVector* pvbPadding
)
{
    MTERR mr = MT_S_OK;
    const CipherInfo* pCipherInfo = GetEndpointParams()->GetCipher();

    CHKOK(ComputeMAC(
               sequenceNumber,
               pvbMACKey,
               pContentType,
               pProtocolVersion,
               pvbMAC));

    // generate padding bytes and assign to pvbPadding
    {
        assert(pCipherInfo->cbBlockSize != 0);
        size_t cbUnpaddedBlockLength = GetContent()->size() + GetMAC()->size();

        // keep accumulating blocks until it just clears the content length
        size_t cbPaddedBlockLength = 0;
        while (cbPaddedBlockLength <= cbUnpaddedBlockLength)
        {
            cbPaddedBlockLength += pCipherInfo->cbBlockSize;
        }

        assert(cbPaddedBlockLength >= cbUnpaddedBlockLength);
        assert((cbPaddedBlockLength % pCipherInfo->cbBlockSize) == 0);
        assert(cbPaddedBlockLength > 0);

        // cbPaddingLength is length of just padding (excluding length byte)
        size_t cbPaddingLength = cbPaddedBlockLength -
                                 cbUnpaddedBlockLength -
                                 c_cbGenericBlockCipher_Padding_LFL;
        MT_BYTE b = 0;
        CHKOK(MT_SizeTToByte(cbPaddingLength, &b));

        assert(b == cbPaddingLength);

        pvbPadding->assign(cbPaddingLength, b);
    }

    // check that the entire content + padding is a multiple of block size
    assert(
    (
      (GetContent()->size() +
       pvbMAC->size() +
       pvbPadding->size() +
       c_cbGenericBlockCipher_Padding_LFL)
       %
       pCipherInfo->cbBlockSize
    ) == 0);

done:
    return mr;

error:
    goto done;
} // end function ComputeSecurityInfo

_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher::CheckSecurityPriv()
{
    MTERR mr = MT_S_OK;
    ByteVector vbMAC;
    ByteVector vbPadding;
    MT_ProtocolVersion hashVersion;

    CHKOK(GetCiphertext()->GetProtocolVersionForSecurity(&hashVersion));

    CHKOK(ComputeSecurityInfo(
              *GetEndpointParams()->GetSequenceNumber(),
              GetEndpointParams()->GetMACKey(),
              GetCiphertext()->GetContentType(),
              &hashVersion,
              &vbMAC,
              &vbPadding));

    wprintf(L"received MAC:\n");
    PrintByteVector(GetMAC());

    wprintf(L"computed MAC:\n");
    PrintByteVector(&vbMAC);

    if (*GetMAC() != vbMAC)
    {
        mr = MT_E_BAD_RECORD_MAC;
        goto error;
    }

    wprintf(L"received padding:\n");
    PrintByteVector(GetPadding());

    wprintf(L"computed padding:\n");
    PrintByteVector(&vbPadding);

    if (*GetPadding() != vbPadding)
    {
        mr = MT_E_BAD_RECORD_PADDING;
        goto error;
    }

done:
    return mr;

error:
    goto done;
} // end function CheckSecurityPriv


/*********** MT_GenericBlockCipher_TLS10 *****************/

_Use_decl_annotations_
const ByteVector*
MT_GenericBlockCipher_TLS10::GetIV() const
{
    return GetEndpointParams()->GetIV();
} // end function GetIV


/*********** MT_GenericBlockCipher_TLS11 *****************/

_Use_decl_annotations_
MT_GenericBlockCipher_TLS11::MT_GenericBlockCipher_TLS11(
    MT_TLSCiphertext* pCiphertext
)
    : MT_GenericBlockCipher(pCiphertext),
      m_vbIV()
{
} // end ctor MT_GenericBlockCipher_TLS11

_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher_TLS11::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    /*
    ** the IV is sent in the clear just in front of the ciphertext, which is
    ** encrypted using this very IV. apparently that's safe and okay? I don't
    ** really get it, but all right.
    **
    ** http://stackoverflow.com/q/3436864
    */

    PARSEVB(GetEndpointParams()->GetCipher()->cbIVSize, GetIV());

    wprintf(L"received IV field:\n");
    PrintByteVector(GetIV());

    CHKOK(MT_GenericBlockCipher::ParseFromPriv(pv, cb));

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher_TLS11::UpdateWriteSecurity()
{
    MTERR mr = MT_S_OK;

    CHKOK(SetIV(GetEndpointParams()->GetIV()));
    CHKOK(MT_GenericBlockCipher::UpdateWriteSecurity());

done:
    return mr;

error:
    goto done;
} // end function UpdateWriteSecurity

/*
** at the point this is called, UpdateWriteSecurity security should have
** already been called, which fills EncryptedContent with the encrypted
** contents of the payload. for TLS 1.1 and 1.2, the IV is attached
** un-encrypted to the front, so this is the last thing we do before
** serializing
*/
_Use_decl_annotations_
MTERR_T
MT_GenericBlockCipher_TLS11::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    SERIALIZEPVB(GetIV());

    CHKOK(MT_GenericBlockCipher::SerializePriv(pv, cb));

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
size_t
MT_GenericBlockCipher_TLS11::Length() const
{
    size_t cbLength = MT_GenericBlockCipher::Length() +
                      GetEndpointParams()->GetCipher()->cbIVSize;

    return cbLength;
} // end function Length


/*********** SymmetricCipherer *****************/

SymmetricCipherer::SymmetricCipherer()
    : m_cipherInfo()
{
} // end ctor SymmetricCipherer

_Use_decl_annotations_
MTERR_T
SymmetricCipherer::SetCipherInfo(
    const ByteVector* pvbKey,
    const CipherInfo* pCipherInfo
)
{
    MT_UNREFERENCED_PARAMETER(pvbKey);

    MTERR mr = MT_S_OK;

    CHKOK(SetCipher(pCipherInfo));

    // if you pick null cipher, then better send an empty key
    assert(GetCipher()->alg != CipherAlg_NULL || pvbKey->empty());

done:
    return mr;

error:
    goto done;
} // end function SetCipherInfo

/*
** handle null cipher here. MT_S_OK indicates to the caller that some
** "encryption" was done here. MT_E_NOTIMPL means that the caller needs to
** handle the encryption itself
*/
_Use_decl_annotations_
MTERR_T
SymmetricCipherer::EncryptBuffer(
    const ByteVector* pvbCleartext,
    const ByteVector* pvbIV,
    ByteVector* pvbEncrypted
)
{
    MT_UNREFERENCED_PARAMETER(pvbIV);

    if (GetCipher()->alg == CipherAlg_NULL)
    {
        *pvbEncrypted = *pvbCleartext;
        return MT_S_OK;
    }

    return MT_E_NOTIMPL;
} // end function EncryptBuffer

// handle null encryption here. MT_S_OK means we handled it. else MT_E_NOTIMPL
_Use_decl_annotations_
MTERR_T
SymmetricCipherer::DecryptBuffer(
    const ByteVector* pvbEncrypted,
    const ByteVector* pvbIV,
    ByteVector* pvbDecrypted
)
{
    MT_UNREFERENCED_PARAMETER(pvbIV);

    if (GetCipher()->alg == CipherAlg_NULL)
    {
        *pvbDecrypted = *pvbEncrypted;
        return MT_S_OK;
    }

    return MT_E_NOTIMPL;
} // end function DecryptBuffer


/*********** Hasher *****************/

// handle null (0 byte) hash. MT_S_OK means we handled it. MT_E_NOTIMPL otherwise
_Use_decl_annotations_
MTERR_T
Hasher::Hash(
    const HashInfo* pHashInfo,
    const ByteVector* pvbText,
    ByteVector* pvbHash)
{
    MT_UNREFERENCED_PARAMETER(pvbText);

    if (pHashInfo->alg == HashAlg_NULL)
    {
        // 0 byte hash
        pvbHash->clear();
        return MT_S_OK;
    }

    return MT_E_NOTIMPL;
} // end function Hash

// handle null (0 byte) HMAC. MT_S_OK means we handled it. MT_E_NOTIMPL otherwise
_Use_decl_annotations_
MTERR_T
Hasher::HMAC(
    const HashInfo* pHashInfo,
    const ByteVector* pvbKey,
    const ByteVector* pvbText,
    ByteVector* pvbHMAC)
{
    MT_UNREFERENCED_PARAMETER(pvbKey);
    MT_UNREFERENCED_PARAMETER(pvbText);

    if (pHashInfo->alg == HashAlg_NULL)
    {
        // 0 byte hash
        pvbHMAC->clear();
        return MT_S_OK;
    }

    return MT_E_NOTIMPL;
} // end function HMAC


/*********** MT_Alert *****************/

MT_Alert::MT_Alert()
    : MT_Structure(),
      m_eLevel(MTAL_Unknown),
      m_eDescription(MTAD_Unknown)
{
} // end ctor MT_Alert

_Use_decl_annotations_
MTERR_T
MT_Alert::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbAlertLevel_Length;

    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetLevel())));

    ADVANCE_PARSE();

    cbField = c_cbAlertDescription_Length;
    CHKOK(ReadNetworkLong(pv, cb, cbField, reinterpret_cast<MT_UINT8*>(GetDescription())));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
MTERR_T
MT_Alert::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    MTERR mr = MT_S_OK;
    size_t cbField = c_cbAlertLevel_Length;

    CHKOK(WriteNetworkLong(static_cast<MT_BYTE>(*GetLevel()), cbField, pv, cb));

    ADVANCE_PARSE();

    cbField = c_cbAlertDescription_Length;
    CHKOK(WriteNetworkLong(static_cast<MT_BYTE>(*GetDescription()), cbField, pv, cb));

    ADVANCE_PARSE();

done:
    return mr;

error:
    goto done;
} // end function SerializePriv

_Use_decl_annotations_
wstring
MT_Alert::ToString() const
{
    const wchar_t* wszLevel = nullptr;
    const wchar_t* wszDescription = nullptr;

    switch (*GetLevel())
    {
        case MTAL_Warning:
        wszLevel = L"warning";
        break;

        case MTAL_Fatal:
        wszLevel = L"fatal";
        break;

        default:
        wszLevel = L"unknown";
        break;
    }

    switch (*GetDescription())
    {
        case MTAD_CloseNotify:
        wszDescription = L"CloseNotify";
        break;

        case MTAD_UnexpectedMessage:
        wszDescription = L"UnexpectedMessage";
        break;

        case MTAD_BadRecordMAC:
        wszDescription = L"BadRecordMAC";
        break;

        case MTAD_DecryptionFailed_RESERVED:
        wszDescription = L"DecryptionFailed_RESERVED";
        break;

        case MTAD_RecordOverflow:
        wszDescription = L"RecordOverflow";
        break;

        case MTAD_DecompressionFailure:
        wszDescription = L"DecompressionFailure";
        break;

        case MTAD_HandshakeFailure:
        wszDescription = L"HandshakeFailure";
        break;

        case MTAD_NoCertificate_RESERVED:
        wszDescription = L"NoCertificate_RESERVED";
        break;

        case MTAD_BadCertificate:
        wszDescription = L"BadCertificate";
        break;

        case MTAD_UnsupportedCertificate:
        wszDescription = L"UnsupportedCertificate";
        break;

        case MTAD_CertificateRevoked:
        wszDescription = L"CertificateRevoked";
        break;

        case MTAD_CertificateExpired:
        wszDescription = L"CertificateExpired";
        break;

        case MTAD_CertificateUnknown:
        wszDescription = L"CertificateUnknown";
        break;

        case MTAD_IllegalParameter:
        wszDescription = L"IllegalParameter";
        break;

        case MTAD_UnknownCA:
        wszDescription = L"UnknownCA";
        break;

        case MTAD_AccessDenied:
        wszDescription = L"AccessDenied";
        break;

        case MTAD_DecodeError:
        wszDescription = L"DecodeError";
        break;

        case MTAD_DecryptError:
        wszDescription = L"DecryptError";
        break;

        case MTAD_ExportRestriction_RESERVED:
        wszDescription = L"ExportRestriction_RESERVED";
        break;

        case MTAD_ProtocolVersion:
        wszDescription = L"GetProtocolVersion";
        break;

        case MTAD_InsufficientSecurity:
        wszDescription = L"InsufficientSecurity";
        break;

        case MTAD_InternalError:
        wszDescription = L"InternalError";
        break;

        case MTAD_UserCanceled:
        wszDescription = L"UserCanceled";
        break;

        case MTAD_NoRenegotiation:
        wszDescription = L"NoRenegotiation";
        break;

        case MTAD_UnsupportedExtension:
        wszDescription = L"UnsupportedExtension";
        break;

        default:
        wszDescription = L"Unknown";
        break;
    }

    wstring wsAlert(wszLevel);
    wsAlert += L" ";
    wsAlert += wszDescription;
    return wsAlert;
} // end function ToString


/*********** MT_RenegotiationInfoExtension *****************/

MT_RenegotiationInfoExtension::MT_RenegotiationInfoExtension()
    : MT_Extension(),
      m_renegotiatedConnection()
{
} // end ctor MT_RenegotiationInfoExtension

// see notes for SetRenegotiatedConnection
_Use_decl_annotations_
MTERR_T
MT_RenegotiationInfoExtension::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;
    MT_RenegotiatedConnection rc;

    PARSESTRUCT(rc);

    CHKOK(SetRenegotiatedConnection(&rc));

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

/*
** MT_RenegotiationInfoExtension is a subclass of MT_Extension, which means it
** has to expose GetExtensionData() to get the raw bytes of the extension. but
** it also keeps track of a higher-level MT_RenegotiatedConnection object for
** easy examination in code. unfortunately, this means that
** m_renegotiatedConnection and GetExtensionData() need to be kept in sync.
**
** this function is called to set both members together. Elsewhere, there are
** calls to CheckExtensionDataIntegrity to make sure that the integrity hasn't
** been tampered with by direct modifications to GetExtensionData().
*/
_Use_decl_annotations_
MTERR_T
MT_RenegotiationInfoExtension::SetRenegotiatedConnection(
    const MT_RenegotiatedConnection* pRenegotiatedConnection
)
{
    MTERR mr = MT_S_OK;
    m_renegotiatedConnection = *pRenegotiatedConnection;

    CHKOK(m_renegotiatedConnection.SerializeToVect(MT_Extension::GetExtensionData()->GetData()));
    assert(MT_S_OK == CheckExtensionDataIntegrity());

done:
    return mr;

error:
    goto done;
} // end function SetRenegotiatedConnection

/*
** see alos: the comment for SetRenegotiatedConnection. this immediately sets
** the m_renegotiatedConnection object as well as the raw bytes, so they are
** kept in sync
*/
_Use_decl_annotations_
MTERR_T
MT_RenegotiationInfoExtension::SetExtensionData(
    const MT_ExtensionData* pExtensionData
)
{
    MTERR mr = MT_S_OK;

    CHKOK(ParseFromVect(pExtensionData->GetData()));
    CHKOK(CheckExtensionDataIntegrity());

done:
    return mr;

error:
    goto done;
} // end function SetExtensionData

/*
** serialize the renegotiated connection member and check that it matches
** GetExtensionData. they should always be in sync
*/
_Use_decl_annotations_
MTERR_T
MT_RenegotiationInfoExtension::CheckExtensionDataIntegrity() const
{
    MTERR mr = MT_S_OK;
    ByteVector vbConnection;

    CHKOK(m_renegotiatedConnection.SerializeToVect(&vbConnection));

    if (vbConnection == *MT_Extension::GetExtensionData()->GetData())
    {
        mr = MT_S_OK;
    }
    else
    {
        mr = MT_S_FALSE;
    }

done:
    return mr;

error:
    goto done;
} // end function CheckExtensionDataIntegrity

_Use_decl_annotations_
const MT_ExtensionData*
MT_RenegotiationInfoExtension::GetExtensionData() const
{
    assert(CheckExtensionDataIntegrity() == MT_S_OK);
    return MT_Extension::GetExtensionData();
} // end function GetExtensionData

_Use_decl_annotations_
const MT_RenegotiationInfoExtension::MT_RenegotiatedConnection*
MT_RenegotiationInfoExtension::GetRenegotiatedConnection() const
{
    assert(CheckExtensionDataIntegrity() == MT_S_OK);
    return &m_renegotiatedConnection;
} // end function GetRenegotiatedConnection


// boilerplate code for quickly creating new structures
/*********** MT_Thingy *****************/

/*
MT_Thingy::MT_Thingy()
    : MT_Structure(),
      m_thingy()
{
} // end ctor MT_Thingy

_Use_decl_annotations_
MTERR_T
MT_Thingy::ParseFromPriv(
    const MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;
    size_t cbField = 0;

    PARSEPSTRUCT(Thingy());

done:
    return mr;

error:
    goto done;
} // end function ParseFromPriv

_Use_decl_annotations_
size_t
MT_Thingy::Length() const
{
    size_t cbLength = Thingy()->Length();
    return cbLength;
} // end function Length

_Use_decl_annotations_
MTERR_T
MT_Thingy::SerializePriv(
    MT_BYTE* pv,
    size_t cb
) const
{
    return MT_E_NOTIMPL;
} // end function SerializePriv
*/

}
