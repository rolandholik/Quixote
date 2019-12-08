/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement SRDEpipe based communications with another enclave on
 * the same host.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define IV_SIZE 16
#define CHECKSUM_SIZE 32
#if 0
#define ENCRYPTION_BLOCKSIZE 16
#endif


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <SRDE.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "Curve25519.h"
#include "AES256_cbc.h"
#include "Report.h"
#include "SRDEpipe.h"


/* State extraction macro. */
#define STATE(var) CO(SRDEpipe_State, var) = this->state


/*
 * The Intel SDK version of this function is being used until the
 * loader initialization issue is addressed.
 */
static _Bool SRDEfusion_untrusted_region(void *ptr, size_t size)

{
	_Bool retn = false;

	if ( ptr == NULL )
		goto done;
	if ( sgx_is_within_enclave(ptr, size) )
		goto done;
	retn = true;
 done:
	return retn;
}


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEpipe_OBJID)
#error Object identifier not defined.
#endif


/** SRDEpipe private state information. */
struct NAAAIM_SRDEpipe_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Untrusted instance. */
	unsigned int instance;

	/* Object status. */
	_Bool poisoned;

	/* Endpoint type. */
	_Bool initiator;

	/* Connect status. */
	enum {
		SRDEpipe_state_init,
		SRDEpipe_state_wait,
		SRDEpipe_state_connected
	} state;

	/* Initiator target definition for connection acknowledgement. */
	struct SGX_targetinfo target;

	/* Elliptic curve object. */
	Curve25519 dhkey;

	/* Initialization vector. */
	Sha256 iv;

	/* Shared key. */
	Buffer key;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the packet which is transmitted over the wire.
 */
typedef struct {
	ASN1_INTEGER *type;
	ASN1_OCTET_STRING *payload;
} SRDEpipe_packet;

ASN1_SEQUENCE(SRDEpipe_packet) = {
	ASN1_SIMPLE(SRDEpipe_packet, type,    ASN1_INTEGER),
	ASN1_SIMPLE(SRDEpipe_packet, payload, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SRDEpipe_packet)

IMPLEMENT_ASN1_FUNCTIONS(SRDEpipe_packet)


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int SRDEpipe_ocall(struct SRDEpipe_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct SRDEpipe_ocall);

	struct SRDEpipe_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == SRDEpipe_send_packet ) {
		if ( SRDEfusion_untrusted_region(ocall->bufr, \
						 ocall->bufr_size) )
			goto done;
		arena_size += ocall->bufr_size;
	}

	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == SRDEpipe_send_packet ) {
		memcpy(ocp->arena, ocall->bufr, ocall->bufr_size);
		ocp->bufr = ocp->arena;
	}


	/* Call the SRDEpipe manager. */
	if ( (status = sgx_ocall(SRDENAAAIM_OCALL4, ocp)) == 0 ) {
		retn = true;
		ocall->target	 = ocp->target;
		ocall->report	 = ocp->report;
		ocall->bufr	 = ocp->bufr;
		ocall->bufr_size = ocp->bufr_size;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEpipe_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S	A pointer to the object containing the state
 *		information that is to be initialized.
 */

static void _init_state(CO(SRDEpipe_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Duct_OBJID;


	S->poisoned  = false;
	S->state     = SRDEpipe_state_init;
	S->initiator = false;

	S->dhkey = NULL;

	S->iv  = NULL;
	S->key = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the initialization and setup of the enclave
 * that will be communicated with.
 *
 * \param this		A pointer to the object which is to have an
 *			enclave associated with it.
 *
 * \param name		A pointer to a null terminated buffer containing
 *			the pathname of the enclave to open.
 *
 * \param slot		The slot number of the enclave that will implement
 *			the pipe endpoint.
 *
 * \param token		A pointer to a null terminated buffer containing
 *			the pathname of the launch token to be used
 *			for initializing the enclave.
 *
 * \param debug		A flag to indicate whether or not the enclave
 *			is to be initialized in debug or production mode.
 *
 * \return		A false value is returned if an error is
 *			encountered while setting the enclave up.  The
 *			object is poisoned and is not available for
 *			additional processing.  If the setup was successful
 *			a true value is returned to the caller.
 */

static _Bool setup(CO(SRDEpipe, this), CO(char *, name), const int slot, \
		   CO(char *, token), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;

	struct SRDEpipe_ocall ocall;


	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall = SRDEpipe_init_object;
	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);
	this->state->instance = ocall.instance;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.debug = debug;
	ocall.slot  = slot;

	if ( (strlen(name) + 1) > sizeof(ocall.enclave) )
		ERR(goto done);
	memcpy(ocall.enclave, name, strlen(name));

	if ( (strlen(token) + 1) > sizeof(ocall.token) )
		ERR(goto done);
	memcpy(ocall.token, token, strlen(token));

	ocall.ocall    = SRDEpipe_setup;
	ocall.instance = S->instance;
	if ( SRDEpipe_ocall(&ocall) != 0 )
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
 * This method is an API placeholder for the method that is implemented
 * in standard userspace to issue the ECALL's needed to setup the
 * security context between two enclaves that are to implement a
 * communications conduit.
 *
 * \param this		A pointer to the object which is to implement
 *			the connection.
 *
 * \param target	A pointer to the structure containing target
 *			information that an attestation report is to
 *			be generated against.
 *
 * \param report	A pointer to the structuring containing a local
 *			attestation report.
 *
 * \return		A false value is universally returned in order
 *			to prevent this method from being invoked from
 *			enclave context.
 */

static _Bool bind(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		  struct SGX_report *report)

{
	return false;
}


/**
 * External public method.
 *
 * This method drives the creation of a security context with another
 * enclave that has been previously created and initialized with the
 * ->setup method.
 *
 * \param this	A pointer to the object which is to implement the
 *		connection.
 *
 * \return	A boolean value is returned to indication the status
 *		of the connection setup.  A false value indicates the
 *		establishment of the communications context has been
 *		failed and the object is poisoned from subsequent use.
 *		A true value indicates that a communications context
 *		has been established between the two enclaves.
 */

static _Bool connect(CO(SRDEpipe, this))

{
	STATE(S);

	_Bool status,
	      retn = false;

	struct SRDEpipe_ocall ocall;

	Buffer b,
	       bufr = NULL;

	Report rpt = NULL;

	SHA256_hmac hmac = NULL;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall    = SRDEpipe_connect;
	ocall.instance = S->instance;


	/* Generate target information for remote endpoint. */
	INIT(NAAAIM, Report, rpt, ERR(goto done));
	if ( !rpt->get_targetinfo(rpt, &ocall.target) )
		ERR(goto done);


	/* Invoke OCALL to get report from remote endpoint. */
	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);


	/* Validate remote report and generate report for endpoint. */
	if ( !rpt->validate_report(rpt, &ocall.report, &status) )
		ERR(goto done);
	if ( !status )
		ERR(goto done);

	fputs("Validated target endpoint.\n", stdout);


	/* Generate shared key and counter-report. */
	INIT(NAAAIM, Curve25519, S->dhkey, ERR(goto done));
	if ( !S->dhkey->generate(S->dhkey) )
		ERR(goto done);

	INIT(HurdLib, Buffer, S->key, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !bufr->add(bufr, ocall.report.body.reportdata, 32) )
		ERR(goto done);
	if ( !S->dhkey->compute(S->dhkey, bufr, S->key) )
		ERR(goto done);

	if ( !rpt->generate_report(rpt, &ocall.target,		   \
				   S->dhkey->get_public(S->dhkey), \
				   &ocall.report) )
			ERR(goto done);


	/* Generate the encryption key and initialization vector seed. */
	INIT(NAAAIM, Sha256, S->iv, ERR(goto done));
	S->iv->add(S->iv, S->key);
	if ( !S->iv->compute(S->iv) )
		ERR(goto done);
	b = S->iv->get_Buffer(S->iv);

	S->key->reset(S->key);
	if ( !S->key->add_Buffer(S->key, b) )
		ERR(goto done);

	fputs("\nShared key:\n", stdout);
	S->key->print(S->key);

	S->iv->rehash(S->iv, 100);
	fputs("\nIV: \n", stdout);
	b->print(b);


	/* Invoke OCALL to send report to remote endpoint. */
	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);


	/* Verify acknowledgement. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(S->key)) == NULL )
		ERR(goto done);
	hmac->add_Buffer(hmac, S->iv->get_Buffer(S->iv));
	if ( !hmac->compute(hmac) )
		ERR(goto done);
	b = hmac->get_Buffer(hmac);

	if ( !rpt->validate_report(rpt, &ocall.report, &status) )
		ERR(goto done);
	if ( !status )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, ocall.report.body.reportdata, 32) )
		ERR(goto done);

	fputs("\nComputed acknowledgement:\n", stdout);
	b->print(b);
	fputs("Report acknowledgement:\n", stdout);
	bufr->print(bufr);

	if ( !bufr->equal(bufr, b) )
		ERR(goto done);
	fputs("Acknowledgement verified.\n", stdout);

	S->iv->rehash(S->iv, 1);
	S->state     = SRDEpipe_state_connected;
	S->initiator = true;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);
	WHACK(rpt);
	WHACK(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method handles the client side of creating a security context
 * from an enclave that is invoking the ->connect method.
 *
 * \param this		A pointer to the object which is to implement
 *			acceptance of a connection.
 *
 * \param target	A pointer to a target structure that contains
 *			a target that a report is to be generated
 *			against.  This structure will be populated
 *			with a report for the executing enclave upon
 *			initial connection acceptance.
 *
 * \param report	A pointer to a report structure that will
 *			be populated with a report of the executing
 *			enclave or alternately the report from the
 *			enclave initiating the connection.
 *
 * \return	A boolean value is returned to indication the status
 *		of the connection setup.  A false value indicates the
 *		establishment of the communications context has failed
 *		and the object is poisoned from subsequent use. A true
 *		value indicates that a communications context has been
 *		established between the two enclaves.
 */

static _Bool accept(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		    struct SGX_report *report)

{
	STATE(S);

	_Bool status,
	      retn = false;

	Buffer b,
	       bufr = NULL;

	Report rpt = NULL;

	SHA256_hmac hmac = NULL;


	INIT(NAAAIM, Report, rpt, ERR(goto done));

	/* Initial endpoint. */
	if ( S->dhkey == NULL ) {
		INIT(NAAAIM, Curve25519, S->dhkey, ERR(goto done));
		if ( !S->dhkey->generate(S->dhkey) )
			ERR(goto done);

		if ( !rpt->generate_report(rpt, target,			   \
					   S->dhkey->get_public(S->dhkey), \
					   report) )
			ERR(goto done);

		S->target = *target;
		if ( !rpt->get_targetinfo(rpt, target) )
			ERR(goto done);

		retn	 = true;
		S->state = SRDEpipe_state_wait;
		goto done;
	}


	/* Validate counter party report. */
	if ( S->state != SRDEpipe_state_wait )
		ERR(goto done);

	if ( !rpt->validate_report(rpt, report, &status) )
		ERR(goto done);

	if ( status )
		fputs("\nSource report verified.\n", stdout);
	else {
		fputs("\nSource report not verified.\n", stdout);
		ERR(goto done);
	}


	/* Generate the shared key. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, report->body.reportdata, 32) )
		ERR(goto done);

	INIT(HurdLib, Buffer, S->key, ERR(goto done));
	if ( !S->dhkey->compute(S->dhkey, bufr, S->key) )
		ERR(goto done);


	/* Generate the encryption key and initialization vector seed. */
	INIT(NAAAIM, Sha256, S->iv, ERR(goto done));
	S->iv->add(S->iv, S->key);
	if ( !S->iv->compute(S->iv) )
		ERR(goto done);
	b = S->iv->get_Buffer(S->iv);

	S->key->reset(S->key);
	if ( !S->key->add_Buffer(S->key, b) )
		ERR(goto done);

	fputs("\nShared key:\n", stdout);
	S->key->print(S->key);

	S->iv->rehash(S->iv, 100);
	fputs("\nIV: \n", stdout);
	b->print(b);


	/* Generate acknowledgement report. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(S->key)) == NULL )
		ERR(goto done);
	hmac->add_Buffer(hmac, S->iv->get_Buffer(S->iv));
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	if ( !rpt->generate_report(rpt, &S->target, hmac->get_Buffer(hmac), \
				   report) )
		ERR(goto done);

	S->iv->rehash(S->iv, 1);
	S->state  = SRDEpipe_state_connected;
	retn	  = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(rpt);
	WHACK(bufr);
	WHACK(hmac);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements the encryption of the ASN1 encoded packet
 * to be sent to the remote enclave.
 *
 * \param S		A pointer to the object state of the object
 *			requesting encryption.
 *
 * \param bufr		The object containing the packet payload.  The
 *			contents of the object is replaced with the
 *			encrypted payload.
 *
 * \return		A boolean value is returned to indicate the
 *			status of packet encryption.  A false value
 *			indicates an error occured during
 *			encryption. A true value indicates the
 *			packet was successfully encrypted.
 */

static _Bool _encrypt_packet(CO(SRDEpipe_State, S), CO(Buffer, payload))

{
	_Bool retn = false;

	Buffer b,
	       iv;

	AES256_cbc cipher = NULL;


	/* Verify arguement status. */
	if ( payload == NULL )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);


	/* Extract the initialization vector from the first shared secret. */
	INIT(HurdLib, Buffer, iv, goto done);
	b = S->iv->get_Buffer(S->iv);
	if ( !iv->add(iv, b->get(b), IV_SIZE) )
		ERR(goto done);


	/* Encrypt the packet. */
	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(S->key, iv)) == NULL )
		ERR(goto done);
	if ( cipher->encrypt(cipher, payload) == NULL )
		ERR(goto done);

	payload->reset(payload);
	if ( !payload->add_Buffer(payload, cipher->get_Buffer(cipher)) )
		ERR(goto done);

	retn = true;


done:
	WHACK(iv);
	WHACK(cipher);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements the computation of the HMAC checksum over
 * the supplied payload.
 *
 * \param S		A pointer to the object state of the object
 *			requesting checksum computation.
 *
 * \param bufr		The object containing the payload on which the
 *			checksum is to be computed.
 *
 * \param chksum	The object which will contain the checksum.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the checksum generation.  A false value
 *			indicates an error occured during computation
 *			of the checksum.  A true value indicates the
 *			computation was successful and the output
 *			buffer contains a valid checksum.
 */

static _Bool _compute_checksum(CO(SRDEpipe_State, S), CO(Buffer, payload), \
			       CO(Buffer, chksum))

{
	_Bool retn = false;

	unsigned char *p;

	Buffer b   = S->iv->get_Buffer(S->iv),
	       key = NULL;

	SHA256_hmac hmac = NULL;


	/* Verify arguement status. */
	if ( payload == NULL  )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);
	if ( chksum == NULL )
		ERR(goto done);
	if ( chksum->poisoned(chksum) )
		ERR(goto done);


	/* Generate the key for the checksum. */
	INIT(HurdLib, Buffer, key, goto done);
	p = b->get(b) + IV_SIZE;
	if ( !key->add(key, p, b->size(b) - IV_SIZE) )
		ERR(goto done);


	/* Compute the checksum over the packet payload with the key. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		ERR(goto done);
	hmac->add_Buffer(hmac, payload);
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	if ( !chksum->add_Buffer(chksum, hmac->get_Buffer(hmac)) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(key);
	WHACK(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method implements sending a packet to the remote endpoint.
 * The supplied packet information is ASN1 encoded and the resulting
 * ASN1 data structure is encrypted and an HMAC trailing checksum
 * is added.  The resulting data structure is forwarded to the
 * endpoing through an OCALL.
 *
 * \param this		A pointer to the object which is to initiate
 *			the send.
 *
 * \param type		The type of packet to be sent.
 *
 * \param packet	The object containing the raw data to be
 *			transmitted if the packet type requires data.
 *
 * \return		A boolean value is returned to indicate the
 *			status of packet transmission.  A false value
 *			indicates an error occured during
 *			transmission.  A true value indicates the
 *			packet was successfully transmitted.
 */

static _Bool send_packet(CO(SRDEpipe, this), const SRDEpipe_type type, \
			 CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	int asn_size;

	struct SRDEpipe_ocall ocall;

	SRDEpipe_packet *packet = NULL;

	Buffer chksum = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* ASN1 encode the packet. */
	if ( (packet = SRDEpipe_packet_new()) == NULL )
		ERR(goto done);
	if ( ASN1_INTEGER_set(packet->type, type) != 1 )
		ERR(goto done);
	if ( ASN1_OCTET_STRING_set(packet->payload, bufr->get(bufr), \
				   bufr->size(bufr)) != 1 )
		ERR(goto done);

        asn_size = i2d_SRDEpipe_packet(packet, p);
        if ( asn_size < 0 )
                ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, asn, asn_size) )
		ERR(goto done);


	/* Encrypt and checksum the data. */
	INIT(HurdLib, Buffer, chksum, goto done);
	if ( !_encrypt_packet(S, bufr) )
		ERR(goto done);

	if ( !_compute_checksum(S, bufr, chksum) )
		ERR(goto done);
	bufr->add_Buffer(bufr, chksum);

	if ( !S->iv->rehash(S->iv, 1) )
		ERR(goto done);


	/* We are done if this is the caller. */
	if ( !S->initiator ) {
		retn = true;
		goto done;
	}


	/* Send the packet buffer. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall	= SRDEpipe_send_packet;
	ocall.instance	= S->instance;
	ocall.bufr_size = bufr->size(bufr);
	ocall.bufr	= bufr->get(bufr);

	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);

	bufr->reset(bufr);
	if ( ocall.bufr_size > 0 ) {
		if ( !bufr->add(bufr, ocall.bufr, ocall.bufr_size) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(chksum);

	if ( !retn )
		S->poisoned = true;
	if ( packet != NULL )
		SRDEpipe_packet_free(packet);
	if ( asn != NULL )
		OPENSSL_free(asn);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements the verification of the checksum in the
 * supplied payload.
 *
 * \param S		A pointer to the object state of the object
 *			requesting checksum verification.
 *
 * \param debug		A flag used to indicated whether or not
 *			debugging is enabled in the communications
 *			object.
 *
 * \param packet	The object containing the payload containing
 *			the checksum to be verified.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the checksum verification.  A false
 *			value indicates an error occured during verification
 *			of the checksum.  A true value indicates the
 *			computation was successful and the payload was
 *			verfified as valid.
 */

static _Bool _verify_checksum(CO(SRDEpipe_State, S), CO(Buffer, packet))

{
	_Bool retn = false;

	size_t payload;

	Buffer computed = NULL,
	       incoming = NULL;


	/* Verify arguement status. */
	if ( packet == NULL )
		ERR(goto done);
	if ( packet->poisoned(packet) )
		ERR(goto done);


	/* Extract the incoming checksum. */
	INIT(HurdLib, Buffer, incoming, goto done);
	payload = packet->size(packet) - CHECKSUM_SIZE;
	if ( !incoming->add(incoming, packet->get(packet) + payload, \
			    CHECKSUM_SIZE) )
		ERR(goto done);
	packet->shrink(packet, CHECKSUM_SIZE);


	/* Compute the checksum over the packet body. */
	INIT(HurdLib, Buffer, computed, goto done);
	if ( !_compute_checksum(S, packet, computed) )
		ERR(goto done);
	if ( !incoming->equal(incoming, computed) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(computed);
	WHACK(incoming);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements the generation of the initialization vector
 * and key for the supplied packet payload for the remote host.  This
 * vector and key are then used to decrypt the packet.
 *
 * \param S		A pointer to the object state of the object
 *			requesting decryption.
 *
 * \param bufr		The object containing the encrypted packet
 *			payload.  The contents of the object is
 *			replaced with the encrypted payload.
 *
 * \return		A boolean value is returned to indicate the
 *			status of payload decryption.  A false value
 *			indicates an error occured during
 *			decryption. A true value indicates the
 *			packet was successfully encrypted and the
 *			contents of the result object is valid.
 */

static _Bool _decrypt_packet(CO(SRDEpipe_State, S), CO(Buffer, payload))

{
	_Bool retn = false;

	Buffer iv = NULL;

	AES256_cbc cipher = NULL;


	/* Verify object status and arguement status. */
	if ( payload == NULL )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);


	/* Extract the initialization vector. */
	INIT(HurdLib, Buffer, iv, goto done);
	if ( !iv->add(iv, S->iv->get(S->iv), IV_SIZE) )
		ERR(goto done);


	/* Decrypt the packet. */
	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(S->key, iv)) == NULL )
		ERR(goto done);
	if ( cipher->decrypt(cipher, payload) == NULL )
		ERR(goto done);

	payload->reset(payload);
	if ( !payload->add_Buffer(payload, cipher->get_Buffer(cipher)) )
		ERR(goto done);

	retn = true;


done:
	WHACK(iv);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the reception and decoding of a packet from
 * an enclave endpoint.  The raw packet is decrypted and authenticated
 * with the trailing checksum.  The ASN1 data structure is decoded and
 * loaded into the supplied buffer.
 *
 * \param this	A pointer to the object which is to initiate
 *		the send.
 *
 * \param bufr	On entry to the function this object contains the
 *		packet that was received.  This object is loaded with
 *		the authenticated and decrypted contents of the packet.
 *
 * \return	An enumerated type is returned to indicate the status
 *		and type of the payload.  If an internal error occurs
 *		this is reflected with a SRDEpipe_failure code.
 */

static SRDEpipe_type receive_packet(CO(SRDEpipe, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	SRDEpipe_type status,
		      remote_retn;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	int asn_size;

	SRDEpipe_packet *packet = NULL;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Decrypt the payload. */
	if ( !_verify_checksum(S, bufr) )
		ERR(goto done);
	if ( !_decrypt_packet(S, bufr) )
		ERR(goto done);
	if ( !S->iv->rehash(S->iv, 1) )
		ERR(goto done);


	/* Decode the packet. */
	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_SRDEpipe_packet(&packet, &p, asn_size) )
                ERR(goto done);

	remote_retn = ASN1_INTEGER_get(packet->type);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, ASN1_STRING_get0_data(packet->payload), \
			ASN1_STRING_length(packet->payload)) )
		ERR(goto done);

	retn = true;


 done:
	if ( retn )
		status = remote_retn;
	else {
		S->poisoned = true;
		status = SRDEpipe_failure;
	}

	if ( packet != NULL )
		SRDEpipe_packet_free(packet);

	return status;
}


/**
 * External public method.
 *
 * This method implements closing of the connection to the target
 * enclave.
 *
 * \param this	A pointer to the object that is initiating the close
 *		event.
 *
 * \return	A false value is returned if an error is encountered
 *		while transmitting the packet with the close request.
 *		In this event the state of the remote object cannot
 *		be assumed.  A true value indicates the remote
 *		connection was successfully closed.
 */

static _Bool close(CO(SRDEpipe, this))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;

	struct SRDEpipe_ocall ocall;


	/* Send the close signal to the remote enclave. */

	if ( S->state == SRDEpipe_state_connected ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));

		ocall.ocall    = SRDEpipe_data;
		ocall.instance = S->instance;
		if ( !this->send_packet(this, SRDEpipe_eop, bufr) )
			ERR(goto done);
	}


	/* Release the implementation object. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall    = SRDEpipe_whack;
	ocall.instance = S->instance;
	SRDEpipe_ocall(&ocall);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method returns the current connection state of the pipe.  It
 * is designed to provide a method for the remote endpoint to determine
 * if a second ->accept call is to be made to complete the connection.
 *
 * \param this	A pointer to the object whose connection state is to
 *		be interrogated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the object is connected and has a valid security context.
 *		A false value indicates the object is not connected while
 *		a true value means a security context has been established
 *		and the pipe is available for communications.
 */

static _Bool connected(CO(SRDEpipe, this))

{
	STATE(S);


	if ( S->state == SRDEpipe_state_connected )
		return true;
	else
		return false;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Duct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEpipe, this))

{
	STATE(S);


	/* Destroy resources. */
	WHACK(S->dhkey);

	WHACK(S->iv);
	WHACK(S->key);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEpipe object.
 *
 * \return	A pointer to the initialized SRDEpipe.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEpipe NAAAIM_SRDEpipe_Init(void)

{
	Origin root;

	SRDEpipe this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEpipe);
	retn.state_size   = sizeof(struct NAAAIM_SRDEpipe_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Duct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->setup = setup;
	this->bind  = bind;

	this->connect = connect;
	this->accept  = accept;

	this->send_packet    = send_packet;
	this->receive_packet = receive_packet;

	this->close	= close;
	this->connected = connected;
	this->whack	= whack;

	return this;
}
