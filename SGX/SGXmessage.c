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


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/evp.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SGXmessage.h"


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


enum _tlv_enum_type_t {
	TLV_CIPHER_TEXT=0,
	TLV_BLOCK_CIPHER_TEXT,
	TLV_BLOCK_CIPHER_INFO,
	TLV_MESSAGE_AUTHENTICATION_CODE,
	TLV_NONCE,
	TLV_EPID_GID,
	TLV_EPID_SIG_RL,
	TLV_EPID_GROUP_CERT,
	/*SE Provisioning Protocol TLVs*/
	TLV_DEVICE_ID,
	TLV_PS_ID,
	TLV_EPID_JOIN_PROOF,
	TLV_EPID_SIG,
	TLV_EPID_MEMBERSHIP_CREDENTIAL,
	TLV_EPID_PSVN,
	/*PSE Provisioning Protocol TLVs*/
	TLV_QUOTE,
	TLV_X509_CERT_TLV,
	TLV_X509_CSR_TLV,
	/*End-point Selection Protocol TLVs*/
	TLV_ES_SELECTOR,
	TLV_ES_INFORMATION,
	/* EPID Provisioning Protocol TLVs Part 2*/
	TLV_FLAGS,
	/* PSE Quote Signature*/
	TLV_QUOTE_SIG,
	TLV_PLATFORM_INFO_BLOB,
	/* Generic TLVs*/
	TLV_SIGNATURE,
	/* End-point Selection Protocol TLVs*/
	TLV_PEK,
	TLV_PLATFORM_INFO,
	TLV_PWK2,
	TLV_SE_REPORT
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


	/* Setup protocol request definition. */
	S->request.protocol = protocol;
	S->request.type	    = type;
	S->request.version  = version;
	memcpy(S->request.xid, xid, sizeof(S->request.xid));


	return;
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
 * External public method.
 *
 * This method implements decoding of a message received from the
 * Intel server.  It conducts the reverse of the process described
 * in the ->encode method.  The primary difference is that the
 * hexadecimally encoded header is unpacked into a
 * provision_response_header._
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
	bufr->add(bufr, (void *) (msg->get(msg) + hdr_size), \
		  msg->size(msg) - hdr_size);

	p = bufr->get(bufr);

	blocks   = bufr->size(bufr) / 4;
	residual = bufr->size(bufr) % 4;

	fprintf(stdout, "size: %zu, blocks: %u, residual: %u\n", \
		bufr->size(bufr), blocks, residual);

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
 * This method implements a diagnostic dump of the state of the
 * message object.
 *
 * \param this	A pointer to the object whose state is to be
 *		displayed.
 */

static void dump(CO(SGXmessage, this))

{
	STATE(S);

	uint64_t xid;

	uint16_t status;

	uint32_t size;

	String msg = NULL;


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
		fprintf(stdout, "\tgstatus:  %u\n", status);

		memcpy(&status, S->response.pstatus, sizeof(status));
		fprintf(stdout, "\tgstatus:  %u\n", status);

		memcpy(&size, S->response.size, sizeof(size));
		size = ntohl(size);
		fprintf(stdout, "\tsize:     %u\n", size);

		fputs("\nMESSAGE:\n", stdout);
		S->msg->hprint(S->msg);
		goto done;
	}


	/* Output request information. */
	memcpy(&xid,  S->request.xid,  sizeof(xid));

	fputs("REQUEST:\n", stdout);
	fprintf(stdout, "\tprotocol: %u\n", S->request.protocol);
	fprintf(stdout, "\tversion:  %u\n", S->request.version);
	fprintf(stdout, "\txid:	  0x%0lx\n", xid);
	fprintf(stdout, "\ttype:     %u\n", S->request.type);
	fprintf(stdout, "\tsize:     %u\n", S->size);

	fputs("\nMESSAGE:\n", stdout);
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
 * This method implements a destructor for the SGXmessage object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXmessage, this))

{
	STATE(S);


	WHACK(S->msg);

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

	this->encode = encode;
	this->decode = decode;

	this->dump  = dump;
	this->whack = whack;

	return this;


 err:
	return NULL;
}