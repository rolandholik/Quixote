/** \file
 * This file contains the implementation of an object which is used
 * to manage Type-Value-Length (TLV) requests and replies from
 * Intel provisioning services.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */


/* Local defines. */
#define DEVICE	"/dev/isgx"
#define ENCLAVE	"/opt/intel/sgxpsw/aesm/libsgx_pve.signed.so"

#define XID_SIZE 8

/* Macro to clear an array object. */
#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "SHA256.h"

#include "intel-messages.h"
#include "SGX.h"
#include "PCEenclave.h"
#include "SGXmessage.h"
#include "SGXcmac.h"
#include "SGXaesgcm.h"
#include "SGXrsa.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXmessage_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXmessage_OBJID)
#error Object identifier not defined.
#endif


/* The state of the object. */
enum object_state {
	INIT=0,
	REQUEST,
	RESPONSE
};


static char *tlv_types[] = {
	"CIPHER_TEXT",
	"BLOCK_CIPHER_TEXT",
	"BLOCK_CIPHER_INFO",
	"MESSAGE_AUTHENTICATION_CODE",
	"NONCE",
	"EPID_GID",
	"EPID_SIG_RL",
	"EPID_GROUP_CERT",
	"DEVICE_ID",
	"PS_ID",
	"EPID_JOIN_PROOF",
	"EPID_SIG",
	"EPID_MEMBERSHIP_CREDENTIAL",
	"EPID_PSVN",
	"QUOTE",
	"X509_CERT_TLV",
	"X509_CSR_TLV",
	"ES_SELECTOR",
	"ES_INFORMATION",
	"FLAGS",
	"QUOTE_SIG",
	"PLATFORM_INFO_BLOB",
	"SIGNATURE",
	"PEK",
	"PLATFORM_INFO",
	"PWK2",
	"SE_REPORT"
};


/*
 * The following structures define formats for short and long encoded
 * messages.
 */
struct TLVshort {
	uint8_t type;
	uint8_t version;
	uint16_t size;
} __attribute__((packed));

struct TLVlong {
	uint8_t type;
	uint8_t version;
	uint32_t size;
} __attribute__((packed));


/*
 * The following structure definitions define the headers that are
 * placed on the provisiong request and response packets that are
 * sent and received from the Intel provisioning service.
 */
struct provision_request_header {
	uint8_t protocol;
	uint8_t version;
	uint8_t xid[XID_SIZE];
	uint8_t type;
	uint8_t size[4];
} __attribute__((packed));

struct provision_response_header {
	uint8_t protocol;
	uint8_t version;
	uint8_t xid[XID_SIZE];
	uint8_t type;
	uint8_t gstatus[2];
	uint8_t pstatus[2];
	uint8_t size[4];
} __attribute__((packed));


/** SGXmessage private state information. */
struct NAAAIM_SGXmessage_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Object state. */
	enum object_state state;

	/* Provision request header. */
	struct provision_request_header request;

	/* Provision response header. */
	struct provision_response_header response;

	/* Encoded message buffer. */
	uint32_t size;

	Buffer msg;

	/* Unpacked messages. */
	Buffer messages;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXmessage_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXmessage_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXmessage_OBJID;

	S->poisoned = false;
	S->state    = INIT;
	S->size	    = 0;
	S->msg	    = NULL;

	S->messages	= NULL;

	memset(&S->request,  '\0', sizeof(S->request));
	memset(&S->response, '\0', sizeof(S->response));

	return;
}


/**
 * External public method.
 *
 * This method initializes a service request message.
 *
 * \param this		A pointer to the message object which is to
 *			be initialized.
 *
 * \param protocol	The message prototype to be used.
 *
 * \param type		The type of message being sent.
 *
 * \param version	The encoding version being used.
 *
 * \param xid		The transaction to be used.
 *
 * \return	No return value is defined.
 */

static void init_request(CO(SGXmessage, this), const uint8_t protocol, \
			 const uint8_t type, const uint8_t version,	\
			 CO(uint8_t *, xid))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		return;
	S->state = REQUEST;


	/* Setup protocol request definition. */
	S->request.protocol = protocol;
	S->request.type	    = type;
	S->request.version  = version;
	memcpy(S->request.xid, xid, sizeof(S->request.xid));


	return;
}


/**
 * Internal private method.
 *
 * The following function encodes the creation of a single TLV message
 * into a supplied Buffer object.  This is implemented as a separate
 * function in order to support multiple sub-messages for a given
 * TLV message type.
 *
 * \param S		The object state which is to be updated by
 *			the encoded message.
 *
 * \param type		The numeric descriptor for the object.
 *
 * \param version	The version type of the message.
 *
 * \param payload	The object containing the payload to be
 *			encoded into the message.
 *
 * \param msg		The object which is to be loaded with the
 *			encoded message.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully encoded.
 *			A false value indicates the message buffer
 *			is not valid while a true value indicates
 *			the buffer contains a valid newly encoded
 *			message.
 */

static _Bool _encode_message(CO(SGXmessage_State, S), const uint8_t type, \
			     const uint8_t version, CO(Buffer, payload),  \
			     CO(Buffer, msg))

{
	_Bool retn = false,
	      need_large_header = false;

	size_t payload_size = payload->size(payload);

	struct TLVshort smsg;

	struct TLVlong lmsg;


	/*
	 * Check for messages types explicitly requiring large header
	 * size.
	 */
	need_large_header = (type == TLV_QUOTE_SIG) || (type == TLV_SE_REPORT);


	/* Select and create the message type. */
	if ( (payload_size <= UINT16_MAX) && !need_large_header ) {
		smsg.type    = type;
		smsg.version = version;
		smsg.size    = htons(payload_size);
		msg->add(msg, (void *) &smsg, sizeof(struct TLVshort));
	} else {
		lmsg.type    = type | 0x80;
		lmsg.version = version;
		lmsg.size    = htonl(payload_size);
		msg->add(msg, (void *) &lmsg, sizeof(struct TLVlong));
	}


	/* Add the payload and increment the total message size. */
	if ( !msg->add(msg, payload->get(payload), payload_size) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * Encodes the request method initializes a service request message.
 *
 * \param this		A pointer to the message object which is to
 *			have the message encoded into.
 *
 * \param type		The type of the message to be encoded.
 *
 * \param selector	The identity selector.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully encoded.
 *			A false value indicates an error was encountered
 *			while encoding the message, a true value indicates
 *			the message was successfully encoded.
 */

static _Bool encode_es_request(CO(SGXmessage, this), const uint8_t type, \
			       const uint8_t selector)

{
	STATE(S);

	_Bool retn = false;

	uint8_t payload[2];

	struct TLVshort msg;


	/* Verify object status. */
	if ( S->poisoned )
		return false;


	/* Setup and encode a message buffer. */
	payload[0] = type;
	payload[1] = selector;

	msg.type    = TLV_ES_SELECTOR;
	msg.version = 1;

	msg.size = htons(sizeof(payload));

	S->msg->add(S->msg, (void *) &msg, sizeof(struct TLVshort));
	if ( !S->msg->add(S->msg, payload, sizeof(payload)) )
		ERR(goto done);

	S->size += S->msg->size(S->msg);
	retn = true;


 done:

	return retn;
}


/**
 * External public method.
 *
 * This method encodes the second provisioning message to be sent
 * to the Intel provisioning service.
 *
 * \param this		A pointer to the message object which is to
 *			have the message encoded into.
 *
 * \param rnd		A pointer to the random number generation
 *			object to be used.
 *
 * \param pve		The transaction key issued by the Intel
 *			provisioning service in response to the
 *			endpoint selection message.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully encoded.
 *			A false value indicates an error was encountered
 *			while encoding the message, a true value indicates
 *			the message was successfully encoded.
 */

static _Bool encode_message2(CO(SGXmessage, this), CO(RandomBuffer, rnd), \
			     CO(PCEenclave, pce), struct SGX_pek *pek,	  \
			     struct SGX_report *pek_report)

{
	STATE(S);

	_Bool retn = false;

	uint8_t pek_pub = 3;

	uint16_t pce_svn,
		 pce_id;

	uint32_t size;

	struct SGX_platform_info platform_info;

	struct provision_request_header reqhdr;

	Buffer b,
	       sk     = NULL,
	       bufr   = NULL,
	       submsg = NULL,
	       aaad   = NULL,
	       tag    = NULL,
	       encout = NULL;

	Sha256 sha256 = NULL;

	SGXcmac cmac = NULL;

	SGXaesgcm aesgcm = NULL;

	SGXrsa rsa = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state != REQUEST )
		ERR(goto done);


	/*
	 * Generate the sub message consisting of the randomly generated
	 * key along with the hash of the components of the key supplied
	 * by the provisioning server.
	 */
	INIT(HurdLib, Buffer, submsg, ERR(goto done));

	INIT(HurdLib, Buffer, sk, ERR(goto done));
	rnd->generate(rnd, 16);
	b = rnd->get_Buffer(rnd);
	if ( !sk->add(sk, b->get(b), b->size(b)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_BLOCK_CIPHER_INFO, 1, sk, submsg) )
		ERR(goto done);
	fputs("SK: \n", stdout);
	b->print(b);

	/* Hash the exponent and modulus of the PEK. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	bufr->add(bufr, pek->n, sizeof(pek->n));
	sha256->add(sha256, bufr);

	bufr->reset(bufr);
	bufr->add(bufr, pek->e, sizeof(pek->e));
	sha256->add(sha256, bufr);

	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	if ( !_encode_message(S, TLV_PS_ID, 1, b, submsg) )
		ERR(goto done);

	/* Encrypt the sub-message and encode it in the current message. */
	INIT(NAAAIM, SGXrsa, rsa, ERR(goto done));
	INIT(HurdLib, Buffer, encout, ERR(goto done));

	if ( !rsa->init(rsa, pek) )
		ERR(goto done);
	if ( !rsa->encrypt(rsa, submsg, encout) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, &pek_pub, sizeof(pek_pub));
	if ( !bufr->add_Buffer(bufr, encout) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_CIPHER_TEXT, 1, bufr, S->msg) )
		ERR(goto done);


	/*
	 * Create the second sub-message containing the following:
	 *
	 *	PPID
	 *	Platform configuration information
	 *	Flags, only if this is a rekey.
	 */
	submsg->reset(submsg);
	bufr->reset(bufr);
	bufr->add(bufr, &pek_pub, sizeof(pek_pub));
	if ( !pce->get_ppid(pce, bufr) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_CIPHER_TEXT, 1, bufr, submsg) )
		ERR(goto done);

	memset(&platform_info, '\0', sizeof(platform_info));
	memcpy(platform_info.cpu_svn, pek_report->body.cpusvn, \
	       sizeof(platform_info.cpu_svn));
	memcpy(&platform_info.pve_svn, &pek_report->body.isvsvn, \
	       sizeof(platform_info.pve_svn));

	pce->get_version(pce, &pce_svn, &pce_id);
	memcpy(&platform_info.pce_svn, &pce_svn, \
	       sizeof(platform_info.pce_svn));
	memcpy(&platform_info.pce_id, &pce_id, sizeof(platform_info.pce_id));

	bufr->reset(bufr);
	if ( !bufr->add(bufr, (void *) &platform_info, sizeof(platform_info)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_PLATFORM_INFO, 1, bufr, submsg) )
		ERR(goto done);


	/*
	 * Encrypt the second sub-message.  The buffer object will
	 * hold the encryption key which is the CMAC of the transaction
	 * ID under the randomly generated key encrypted under
	 * the RSA public key provided by the endpoint selection
	 * message.
	 */
	INIT(HurdLib, Buffer, tag, ERR(goto done));
	if ( !this->get_xid(this, tag) )
		ERR(goto done);

	INIT(NAAAIM, SGXcmac, cmac, ERR(goto done));
	bufr->reset(bufr);
	if ( !cmac->compute(cmac, sk, tag, bufr) )
		ERR(goto done);

	if ( !rnd->generate(rnd, 12) )
		ERR(goto done);
	b = rnd->get_Buffer(rnd);


	/*
	 * Setup a local request header to be included in the
	 * authenticated data stream.  The size is computed as the
	 * current message size, the initialization vector size, the
	 * size of the ciphertext and the final MAC tag.
	 */
	reqhdr = S->request;
	size  = S->msg->size(S->msg);
	size += sizeof(struct TLVshort) + b->size(b) + submsg->size(submsg);
	size += sizeof(struct TLVshort) + 16;
	size  = htonl(size);
	memcpy(&reqhdr.size, &size, sizeof(reqhdr.size));

	INIT(HurdLib, Buffer, aaad, ERR(goto done));
	if ( !aaad->add(aaad, (unsigned char *) &reqhdr, sizeof(reqhdr)) )
		ERR(goto done);

	INIT(NAAAIM, SGXaesgcm, aesgcm, ERR(goto done));
	tag->reset(tag);
	encout->reset(encout);
	if ( !aesgcm->encrypt(aesgcm, bufr, b, submsg, encout, aaad, tag) )
		ERR(goto done);

	/* Add the IV and encrypted message to the current message. */
	bufr->reset(bufr);
	bufr->add_Buffer(bufr, b);
	if ( !bufr->add_Buffer(bufr, encout) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_BLOCK_CIPHER_TEXT, 1, bufr, S->msg) )
		ERR(goto done);

	/* Add the MAC tag to the current message. */
	if ( !_encode_message(S, TLV_MESSAGE_AUTHENTICATION_CODE, 1, tag, \
			      S->msg) )
		ERR(goto done);

	S->size = S->msg->size(S->msg);
	retn = true;


 done:
	WHACK(sk)
	WHACK(bufr);
	WHACK(submsg);
	WHACK(aaad);
	WHACK(tag);
	WHACK(encout);
	WHACK(sha256);
	WHACK(cmac);
	WHACK(aesgcm);
	WHACK(rsa);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method encodes the third provisioning message to be sent
 * to the Intel provisioning service.
 *
 * \param this		A pointer to the message object which is to
 *			have the message encoded into.
 *
 * \param nonce		The object containing the nonce from the incoming
 *			message that will be re-used in the output
 *			message.
 *
 * \param ek2		The key that was generated for decryption of
 *			the incoming message used to create the response
 *			that is being encoded.
 *
 * \param msg3		The object containing the output message from
 *			the provisioning enclave that is to be sent to
 *			the Intel provisioning servers.
 *
 * \param epid_sig	The object containing an EPID signature that
 *			may have been generated in instance of when
 *			an EPID is available from previouis platform
 *			provisioning.
 *
 * \param report_sig	The object containing the signature generated
 *			by the PCE enclave over the report imbedded
 *			in the response.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully encoded.
 *			A false value indicates an error was encountered
 *			while encoding the message, a true value indicates
 *			the message was successfully encoded.
 */

static _Bool encode_message3(CO(SGXmessage, this), CO(Buffer, nonce),	 \
			     CO(Buffer, ek2), struct SGX_message3 *msg3, \
			     CO(Buffer, epid_sig), CO(Buffer, report_sig))

{
	STATE(S);

	_Bool retn = false;

	uint8_t pek_pub = 3;

	uint32_t size;

	struct provision_request_header reqhdr;

	Buffer iv,
	       aaad   = NULL,
	       tag    = NULL,
	       encout = NULL,
	       bufr   = NULL,
	       submsg = NULL;

	RandomBuffer rnd = NULL;

	SGXaesgcm aesgcm = NULL;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state != REQUEST )
		ERR(goto done);
	if ( nonce->poisoned(nonce) )
		ERR(goto done);
	if ( epid_sig->poisoned(epid_sig) )
		ERR(goto done);


	/* Add the incoming nonce value to this message. */
	if ( !_encode_message(S, TLV_NONCE, 1, nonce, S->msg) )
		ERR(goto done);


	/* Add the join proof as a sub message. */
	if ( !msg3->is_join_proof_generated ) {
		fputs("No join proof generated.\n", stderr);
		ERR(goto done);
	}

	INIT(HurdLib, Buffer, submsg, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, msg3->field1_iv, sizeof(msg3->field1_iv));
	if ( !bufr->add(bufr, msg3->field1_data, sizeof(msg3->field1_data)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_BLOCK_CIPHER_TEXT, 1, bufr, submsg) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, msg3->field1_mac, sizeof(msg3->field1_mac)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_MESSAGE_AUTHENTICATION_CODE, 1, bufr, \
			      submsg) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, msg3->n2, sizeof(msg3->n2)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_NONCE, 1, bufr, submsg) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, &pek_pub, sizeof(pek_pub));
	if ( !bufr->add(bufr, msg3->encrypted_pwk2, \
			sizeof(msg3->encrypted_pwk2)) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_CIPHER_TEXT, 1, bufr, submsg) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, (void *) &msg3->pwk2_report.body, \
		  sizeof(msg3->pwk2_report.body));
	bufr->add_Buffer(bufr, report_sig);
	if ( !_encode_message(S, TLV_SE_REPORT, 1, bufr, submsg) )
		ERR(goto done);

	/* Encrypt the sub-message. */
	INIT(NAAAIM, RandomBuffer, rnd, ERR(goto done));
	if ( !rnd->generate(rnd, 12) )
		ERR(goto done);
	iv = rnd->get_Buffer(rnd);

	/*
	 * See documentation in encode_message2 for computation of
	 * header size for AAAD data block.
	 *
	 * If an EPID signature is present the size of the request
	 * header needs to be extended in order to support the EPID
	 * TLV.
	 */
	reqhdr = S->request;
	size  = S->msg->size(S->msg);
	size += sizeof(struct TLVshort) + iv->size(iv) + submsg->size(submsg);
	size += sizeof(struct TLVshort) + 16;

	if ( msg3->is_epid_sig_generated ) {
		size += sizeof(struct TLVshort) + sizeof(msg3->epid_sig_iv) + \
			msg3->epid_sig_output_size;
		size += sizeof(struct TLVshort) + sizeof(msg3->epid_sig_mac);
	}

	size  = htonl(size);
	memcpy(&reqhdr.size, &size, sizeof(reqhdr.size));

	INIT(HurdLib, Buffer, aaad, ERR(goto done));
	if ( !aaad->add(aaad, (unsigned char *) &reqhdr, sizeof(reqhdr)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, encout, ERR(goto done));
	INIT(HurdLib, Buffer, tag, ERR(goto done));
	INIT(NAAAIM, SGXaesgcm, aesgcm, ERR(goto done));
	if ( !aesgcm->encrypt(aesgcm, ek2, iv, submsg, encout, aaad, tag) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add_Buffer(bufr, iv);
	if ( !bufr->add_Buffer(bufr, encout) )
		ERR(goto done);
	if ( !_encode_message(S, TLV_BLOCK_CIPHER_TEXT, 1, bufr, S->msg) )
		ERR(goto done);

	/* Add the MAC tag to the current message. */
	if ( !_encode_message(S, TLV_MESSAGE_AUTHENTICATION_CODE, 1, tag, \
			      S->msg) )
		ERR(goto done);


	/* Add the encrypted EPID signature and MAC if available. */
	if ( msg3->is_epid_sig_generated ) {
		if ( epid_sig->size(epid_sig) == 0 )
			ERR(goto done);

		bufr->reset(bufr);
		bufr->add(bufr,				       \
			  (unsigned char *) msg3->epid_sig_iv, \
			  sizeof(msg3->epid_sig_iv));
		if ( !bufr->add_Buffer(bufr, epid_sig) )
			ERR(goto done);
		if ( !_encode_message(S, TLV_BLOCK_CIPHER_TEXT, 1, bufr, \
				      S->msg) )
			ERR(goto done);

		bufr->reset(bufr);
		if ( !bufr->add(bufr, (unsigned char *) msg3->epid_sig_mac, \
				sizeof(msg3->epid_sig_mac)) )
			ERR(goto done);
		if ( !_encode_message(S, TLV_MESSAGE_AUTHENTICATION_CODE, 1, \
				      bufr, S->msg) )
			ERR(goto done);
	}


	S->size = S->msg->size(S->msg);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(aaad);
	WHACK(tag);
	WHACK(encout);
	WHACK(bufr);
	WHACK(submsg);
	WHACK(rnd);
	WHACK(aesgcm);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the final encoding of the message for
 * transmission.  This encoding occurs in two separate forms.  The
 * provision request header is encoded by converting each byte of
 * the structure into a 2-digit hexadecimal value.  The TLV encoded
 * payload is encoded with Base64 encoding.
 *
 * \param this		A pointer to the message object which is to
 *			have the message encoded into.
 *
 * \param type		The type of the message to be encoded.
 *
 * \param selector	The identity selector.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully encoded.
 *			A false value indicates an error was encountered
 *			while encoding the message, a true value indicates
 *			the message was successfully encoded.
 */

static _Bool encode(CO(SGXmessage, this), CO(String, msg))

{
	STATE(S);

	_Bool retn = false;

	char hexchar[3];

	unsigned char *p,
		       encbufr[5];

	uint32_t lp,
		 blocks,
		 residual,
		 size;

	struct provision_request_header request;

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	S->state = REQUEST;

	/* Convert the header and message into a common buffer. */
	request = S->request;
	size = S->msg->size(S->msg);
	size = htonl(size);
	memcpy(&request.size, &size, sizeof(request.size));

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (void *) &request, sizeof(request));

	/* Encode the header. */
	p = bufr->get(bufr);
	for (lp= 0; lp < sizeof(struct provision_request_header); ++lp) {
		snprintf(hexchar, sizeof(hexchar), "%02X", *p);
		msg->add(msg, hexchar);
		++p;
	}

	/* Base64 encode the TLV message. */
	p = S->msg->get(S->msg);

	blocks   = S->msg->size(S->msg) / 3;
	residual = S->msg->size(S->msg) % 3;

	for (lp= 0; lp < blocks; ++lp) {
		memset(encbufr, '\0', sizeof(encbufr));
		EVP_EncodeBlock(encbufr, p, 3);
		if ( !msg->add(msg, (char *) encbufr) )
			ERR(goto done);
		p += 3;
	}

	if ( residual > 0 ) {
		memset(encbufr, '\0', sizeof(encbufr));
		EVP_EncodeBlock(encbufr, p, residual);
		if ( !msg->add(msg, (char *) encbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(bufr);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Interal private method.
 *
 * This method unpacks the TLV encoded buffer which was received into
 * a series of Buffer objects each of which represents one message
 * in the transaction.
 *
 * \param state		The state for the object containing the
 *			transaction message to be processed.
 *
 * \return		A boolean value is used to indicate the status
 *			of the decoding.  A false value indicates an
 *			error occurred during decoding while a true
 *			value indicates the message was successfully
 *			unpacked.
 */

static _Bool _unpack_messages(CO(SGXmessage_State, S))

{
	_Bool retn = false;

	uint8_t *msg = S->msg->get(S->msg);

	size_t size,
	       mp	= 0,
	       msg_size = S->msg->size(S->msg);

	struct TLVshort *smsg;

	struct TLVlong *lmsg;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, S->messages, ERR(goto done));

	while ( mp < msg_size ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));

		if ( msg[mp] & 0x80 ) {
			lmsg = (struct TLVlong *) &msg[mp];
			size = sizeof(struct TLVlong) + htonl(lmsg->size);
			if ( !bufr->add(bufr, (void *) &msg[mp], size) )
				ERR(goto done);
			mp += size;
		} else {
			smsg = (struct TLVshort *) &msg[mp];
			size = sizeof(struct TLVshort) + htons(smsg->size);
			if ( !bufr->add(bufr, (void *) &msg[mp], size) )
				ERR(goto done);
			mp += size;
		}

		if ( !S->messages->add(S->messages, (unsigned char *) &bufr, \
				       sizeof(Buffer)) )
			ERR(goto done);
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements decoding of a message received from the
 * Intel server.  It conducts the reverse of the process described
 * in the ->encode method.  The primary difference is that the
 * hexadecimally encoded header is unpacked into a
 * provision_response_header.
 *
 * \param this		A pointer to the message object which is to
 *			have the message decoded into into.
 *
 * \param response	The ASCII encoded response from the server.
 *
 * \return		A boolean value is used to indicate whether
 *			or not the message was successfully decoded.
 *			A false value indicates an error was encountered
 *			while decoding the message, a true value indicates
 *			the message was successfully decoded.
 */

static _Bool decode(CO(SGXmessage, this), CO(String, msg))

{
	STATE(S);

	_Bool retn = false;

	uint32_t lp,
		 blocks,
		 residual,
		 hdr_size = 2 * sizeof(struct provision_response_header);

	char response_header[hdr_size + 1];

	unsigned char *p,
		       decbufr[3];

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		goto done;
	S->state = RESPONSE;


	/* Parse the header. */
	memset(response_header, '\0', sizeof(response_header));
	memcpy(response_header, msg->get(msg), hdr_size);

	S->msg->reset(S->msg);
	if ( !S->msg->add_hexstring(S->msg, response_header) )
		ERR(goto done);
	memcpy(&S->response, S->msg->get(S->msg), sizeof(S->response));


	/* Decode the payload. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	S->msg->reset(S->msg);
	if ( !bufr->add(bufr, (void *) (msg->get(msg) + hdr_size), \
			msg->size(msg) - hdr_size) )
		ERR(goto done);

	p = bufr->get(bufr);

	blocks   = bufr->size(bufr) / 4;
	residual = bufr->size(bufr) % 4;

	for (lp= 0; lp < blocks; ++lp) {
		EVP_DecodeBlock(decbufr, p, 4);
		if ( !S->msg->add(S->msg, (void *) decbufr, sizeof(decbufr)) )
			ERR(goto done);
		p += 4;
	}

	if ( residual > 0 ) {
		memset(decbufr, '\0', sizeof(decbufr));
		EVP_DecodeBlock(decbufr, p, residual);
		if ( !S->msg->add(S->msg, (void *) decbufr, sizeof(decbufr)) )
			ERR(goto done);
	} else {
		p -= 4;
		lp = 0;
		if ( *(p+2) == '=' )
			++lp;
		if ( *(p+3) == '=' )
			++lp;
		S->msg->shrink(S->msg, lp);
	}

	memcpy(&lp, S->response.size, sizeof(lp));
	if ( ntohl(lp) != S->msg->size(S->msg) )
		ERR(goto done);


	/* Unpack the messages. */
	if ( !_unpack_messages(S) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for returning the number of
 * decoded messages contained in the object.
 *
 * \param this		A pointer to the message object whose message
 *			count is to be returned.
 *
 * \return		A count of the number of messages in the
 *			object is returned.  If the object is poisoned
 *			or is not in RESPONSE state a value of zero
 *			is returned.
 */

static size_t message_count(CO(SGXmessage, this))

{
	STATE(S);


	/* Exit if the object is poisoned or in the wrong state. */
	if ( S->poisoned )
		return 0;
	if ( S->state != RESPONSE )
		return 0;

	/* Return the number of objects in the messages buffer. */
	return S->messages->size(S->messages) / sizeof(Buffer);
}


/**
 * External public method.
 *
 * This method is an accessor method for returning a message of the
 * specified type and version.
 *
 * \param this		A pointer to the message object whose message
 *			count is to be returned.
 *
 * \param type		The type of the message to be searched for.
 *
 * \param version	The version number of the message.
 *
 * \param msg		The object which the payload of the message
 *			is to be loaded into.
 *
 * \return		A boolean value is returned to indicate if
 *			the object lookup was successful.  A false
 *			value indicates the lookup failed while a
 *			true value indicates the payload has been
 *			loaded into the supplied object.
 */

static _Bool get_message(CO(SGXmessage, this), const uint8_t requested, \
			 uint8_t version, CO(Buffer, msg))

{
	STATE(S);

	_Bool retn = false;

	uint8_t *mp,
		*pp,
		type,
		mver;

	uint32_t size;

	size_t lp,
	       cnt;

	struct TLVshort *smsg;

	struct TLVlong *lmsg;

	Buffer tlv,
	       *tlvp;


	/* Verify object status and state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state != RESPONSE )
		ERR(goto done);


	/* Loop through the available messages searching for a match. */
	tlvp = (Buffer *) S->messages->get(S->messages);
	cnt  = S->messages->size(S->messages) / sizeof(Buffer);

	for (lp= 0; lp < cnt; ++lp ) {
		tlv = *tlvp;
		mp  = (uint8_t *) tlv->get(tlv);

		if ( *mp & 0x80 ) {
			lmsg = (struct TLVlong *) mp;
			type = lmsg->type & ~0x80;
			pp   = mp + sizeof(struct TLVlong);
			size = ntohl(lmsg->size);
			mver = lmsg->version;
		} else {
			smsg = (struct TLVshort *) mp;
			type = smsg->type;
			pp   = mp + sizeof(struct TLVshort);
			size = ntohs(smsg->size);
			mver = smsg->version;
		}

		if ( (type == requested) && (mver == version) ) {
			if ( !msg->add(msg, pp, size) )
				ERR(goto done);
			retn = true;
			goto done;
		}

		++tlvp;
	}


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for returning a specific message
 * from the stack of returned messages.  This is primarily needed
 * to support the retrieval of the previous platform information
 * since there are two messages with the same identifier.
 *
 * \param this		A pointer to the message object whose message
 *			count is to be returned.
 *
 * \param type		The type of the message to be searched for.
 *
 * \param version	The version number of the message.
 *
 * \param msg		The object which the payload of the message
 *			is to be loaded into.
 *
 * \param locn		The location number of the message that is
 *			to be returned.
 *
 * \return		A boolean value is returned to indicate if
 *			the object lookup was successful.  A false
 *			value indicates the lookup failed while a
 *			true value indicates the payload has been
 *			loaded into the supplied object.
 */

static _Bool get_message_number(CO(SGXmessage, this),			  \
				const uint8_t requested, uint8_t version, \
				CO(Buffer, msg), uint8_t locn)

{
	STATE(S);

	_Bool retn = false;

	uint8_t *mp,
		*pp,
		type,
		mver;

	uint32_t size;

	size_t cnt;

	struct TLVshort *smsg;

	struct TLVlong *lmsg;

	Buffer tlv,
	       *tlvp;


	/* Verify object status and state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state != RESPONSE )
		ERR(goto done);


	/* Loop through the available messages searching for a match. */
	tlvp = (Buffer *) S->messages->get(S->messages);
	cnt  = S->messages->size(S->messages) / sizeof(Buffer);
	if ( locn >= cnt )
		ERR(goto done);
	tlvp += locn;

	tlv = *tlvp;
	mp  = (uint8_t *) tlv->get(tlv);

	if ( *mp & 0x80 ) {
		lmsg = (struct TLVlong *) mp;
		type = lmsg->type & ~0x80;
		pp   = mp + sizeof(struct TLVlong);
		size = ntohl(lmsg->size);
		mver = lmsg->version;
	} else {
		smsg = (struct TLVshort *) mp;
		type = smsg->type;
		pp   = mp + sizeof(struct TLVshort);
		size = ntohs(smsg->size);
		mver = smsg->version;
	}


	/* Verify the requested message. */
	if ( (type == requested) && (mver == version) ) {
		if ( !msg->add(msg, pp, size) )
			ERR(goto done);
		retn = true;
		goto done;
	}


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the re-initialization of messages that are
 * managed by the object.  This method allows the message object to
 * be re-populated from a subordinate message that is carried in
 * the top-level object.
 *
 * \param this		A pointer to the message object whose messages
 *			are to be re-initialized.
 *
 * \param messages	The object containing the binary message block
 *			which contains the new message list.

 * \return		A boolean value is used to indicate the status
 *			of message processing.  A false value indicates
 *			an error occurred while a true value indicates
 *			a new message list has been loaded.
 */

static _Bool reload_messages(CO(SGXmessage, this), CO(Buffer, messages))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		return 0;
	if ( S->state != RESPONSE )
		return 0;

	if ( messages->poisoned(messages) )
		ERR(goto done);


	/* Clear the current message list. */
	S->msg->reset(S->msg);

	if ( S->messages != NULL ) {
		GWHACK(Buffer, S->messages);
		WHACK(S->messages);
		S->messages = NULL;
	}


	/* Load the new message buffer and decode it. */
	if ( !S->msg->add_Buffer(S->msg, messages) )
		ERR(goto done);
	if ( !_unpack_messages(S) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for returning the transaction
 * ID from either the request or response structures depending on
 * the mode that the message is in.
 *
 * \param this		A pointer to the message object whose
 *			transaction id is to be returned.
 *
 * \param bufr		The object which the XID is to be loaded into.
 *
 * \return		A boolean value is returned to indicate if
 *			the XID return was successful.  A false
 *			value indicates the lookup failed while a
 *			true value indicates the XID has been
 *			loaded into the supplied object.
 */

static _Bool get_xid(CO(SGXmessage, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint8_t *xidp = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Return XID from the active structure. */
	if ( S->state == REQUEST )
		xidp = S->request.xid;
        if ( S->state == RESPONSE )
		xidp = S->response.xid;

	if ( xidp == NULL )
		ERR(goto done);

	if ( !bufr->add(bufr, xidp, sizeof(S->request.xid)) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for returning the binary
 * representation of the current message header that is operational.
 * This is needed to support verification of encrypted messages
 * which include the protocol header as part of the integrity tag.
 *
 * \param this		A pointer to the message object whose
 *			header is to be returned.
 *
 * \param bufr		The object which the header is to be loaded
 *			into.
 *
 * \return		A boolean value is returned to indicate if
 *			the header return was successful.  A false
 *			value indicates the header failed while a
 *			true value indicates the header has been
 *			loaded into the supplied object.
 */

static _Bool get_header(CO(SGXmessage, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and caller status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state == INIT )
		ERR(goto done);

	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Load the header. */
	if ( S->state == REQUEST )
		bufr->add(bufr, (void *) &S->request, sizeof(S->request));
        if ( S->state == RESPONSE )
		bufr->add(bufr, (void *) &S->response, sizeof(S->response));

	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for returning the type of the
 * response message that was received.  This is used to support
 * the ability to determine if the provisioning service is returning
 * an EPID that has been previously provisioned.  This infomation
 * is used to determine whether or not the response from the
 * provisioning request message 1 can be immediately given to
 * the message three processing routine which will extract the EPID.
 *
 * \param this		A pointer to the message object whose
 *			header is to be returned.
 *
 * \param type		A pointer to the variable that will be
 *			loaded with the response type.
 *
 * \return		A boolean value is returned to indicate if
 *			an error was encountered in the processing
 *			of the response message.  A true value
 *			indicates the location referenced by the
 *			pointer contains a valid response type.  A
 *			false value indicates an error was encountered
 *			and the value in the variable is undefined.
 */

static _Bool get_response_type(CO(SGXmessage, this), uint8_t *type)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and caller status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->state != RESPONSE )
		ERR(goto done);


	/* Load the variable location with the response type. */
	*type = S->response.type;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements a diagnostic dump of the state of the
 * message object.
 *
 * \param this	A pointer to the object whose state is to be
 *		displayed.
 */

static void dump(CO(SGXmessage, this))

{
	STATE(S);

	uint8_t *mp,
		type;

	uint16_t status;

	uint32_t cnt,
		 size,
	         hsize;

	uint64_t xid;

	struct TLVshort *smsg;

	struct TLVlong *lmsg;

	String msg = NULL;

	Buffer tlv,
	       *tlvp;


	/* Display object status. */
	if ( S->poisoned )
		fputs("*POISONED*\n", stdout);

	/* Display response information. */
	if ( S->state == RESPONSE ) {
		memcpy(&xid,  S->response.xid,  sizeof(xid));

		fputs("RESPONSE:\n", stdout);
		fprintf(stdout, "\tprotocol: %u\n", S->response.protocol);
		fprintf(stdout, "\tversion:  %u\n", S->response.version);
		fprintf(stdout, "\txid:	  0x%0lx\n", xid);
		fprintf(stdout, "\ttype:     %u\n", S->response.type);

		memcpy(&status, S->response.gstatus, sizeof(status));
		fprintf(stdout, "\tgstatus:  %u\n", ntohs(status));

		memcpy(&status, S->response.pstatus, sizeof(status));
		fprintf(stdout, "\tpstatus:  %u\n", ntohs(status));

		memcpy(&size, S->response.size, sizeof(size));
		size = ntohl(size);
		fprintf(stdout, "\tsize:     %u\n", size);

		fputs("\nMESSAGES:\n", stdout);
		tlvp = (Buffer *) S->messages->get(S->messages);
		cnt  = S->messages->size(S->messages) / sizeof(Buffer);

		for (size= 0; size < cnt; ++size) {
			tlv = *tlvp;
			mp  = (uint8_t *) tlv->get(tlv);

			if ( *mp & 0x80 ) {
				lmsg = (struct TLVlong *) mp;
				type = lmsg->type & ~0x80;
				hsize = sizeof(struct TLVlong);
			} else {
				smsg = (struct TLVshort *) mp;
				type = smsg->type;
				hsize = sizeof(struct TLVshort);
			}

			fprintf(stdout, "\tMsg %u: %s (%zu)\n", size, \
				tlv_types[type], tlv->size(tlv) - hsize);
			++tlvp;
		}

		goto done;
	}


	/* Output request information. */
	memcpy(&xid,  S->request.xid,  sizeof(xid));

	fputs("REQUEST:\n", stdout);
	fprintf(stdout, "\tprotocol: %u\n", S->request.protocol);
	fprintf(stdout, "\tversion:  %u\n", S->request.version);
	fprintf(stdout, "\txid:	  0x%0lx\n", xid);
	fprintf(stdout, "\ttype:     %u\n", S->request.type);

	memcpy(&size, S->request.size, sizeof(size));
	size = ntohl(size);
	fprintf(stdout, "\tsize:     %u\n", size);

	fputs("\nMESSAGES:\n", stdout);
	if ( !_unpack_messages(S) )
		ERR(goto done);
	tlvp = (Buffer *) S->messages->get(S->messages);
	cnt  = S->messages->size(S->messages) / sizeof(Buffer);

	for (size= 0; size < cnt; ++size) {
		tlv = *tlvp;
		mp  = (uint8_t *) tlv->get(tlv);

		if ( *mp & 0x80 ) {
			lmsg = (struct TLVlong *) mp;
			type = lmsg->type & ~0x80;
			hsize = sizeof(struct TLVlong);
		} else {
			smsg = (struct TLVshort *) mp;
			type = smsg->type;
			hsize = sizeof(struct TLVshort);
		}

		fprintf(stdout, "\tMsg %u: %s (%zu)\n", size, \
			tlv_types[type], tlv->size(tlv) - hsize);
		++tlvp;
	}
	GWHACK(Buffer, S->messages);
	WHACK(S->messages);
	fputc('\n', stdout);
	S->msg->hprint(S->msg);


	INIT(HurdLib, String, msg, ERR(goto done));
	if ( !this->encode(this, msg) )
		ERR(goto done);

	fputs("\nENCODED MESSAGE:\n", stdout);
	msg->print(msg);


 done:
	WHACK(msg);

	return;
}


/**
 * External public method.
 *
 * This method implements a reset of the object to prepare it for
 * creation of a new message.
 * message object.
 *
 * \param this	A pointer to the object whose state is to be reset.
 *
 * \return	No return value is defined.
 */

static void reset(CO(SGXmessage, this))

{
	STATE(S);


	S->poisoned = false;
	S->state    = INIT;
	S->size	    = 0;

	memset(&S->request,  '\0', sizeof(S->request));
	memset(&S->response, '\0', sizeof(S->response));

	S->msg->reset(S->msg);

	if ( S->messages != NULL ) {
		GWHACK(Buffer, S->messages);
		WHACK(S->messages);
	}

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for the SGXmessage object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXmessage, this))

{
	STATE(S);


	WHACK(S->msg);
	if ( S->messages != NULL ) {
		GWHACK(Buffer, S->messages);
		WHACK(S->messages);
	}

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXmessage object.
 *
 * \return	A pointer to the initialized SGXmessage.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXmessage NAAAIM_SGXmessage_Init(void)

{
	Origin root;

	SGXmessage this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXmessage);
	retn.state_size   = sizeof(struct NAAAIM_SGXmessage_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXmessage_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->msg, goto err);

	/* Method initialization. */
	this->init_request	= init_request;
	this->encode_es_request = encode_es_request;
	this->encode_message2	= encode_message2;
	this->encode_message3	= encode_message3;

	this->encode = encode;
	this->decode = decode;

	this->message_count	 = message_count;
	this->get_message	 = get_message;
	this->get_message_number = get_message_number;
	this->reload_messages = reload_messages;

	this->get_xid		= get_xid;
	this->get_header	= get_header;
	this->get_response_type = get_response_type;

	this->reset = reset;
	this->dump  = dump;
	this->whack = whack;

	return this;


 err:
	return NULL;
}
