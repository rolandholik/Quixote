/** \file
 * This file contains the implementation of an object which is used to
 * manage the Intel provisioning enclave.  This enclave is provided as
 * a signed enclave by Intel as part of their runtime distribution.
 *
 * The provisioning enclave is used to mediate provisioning of an EPID
 * 'blob' generated by Intel to an SGX enabled platform.  This 'blob'
 * is needed in order to generate remotely verifiable attestation
 * reports from a platform.
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
#define MAX_HEADER_SIZE 6


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXmessage.h"
#include "PVEenclave.h"


/* Object state extraction macro. */
#define STATE(var) CO(PVEenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PVEenclave_OBJID)
#error Object identifier not defined.
#endif


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


/**
 * Structure to define a PVE endpoint.
 */
struct pve_endpoint {
	uint8_t xid[XID_SIZE];
	uint8_t id;
};


/**
 * The following defines an empty OCALL table for the provisioning
 * enclave.
 */
static const struct {
	size_t nr_ocall;
	void *table[1];
} PVE_ocall_table = { 0, {NULL}};


/** PVEenclave private state information. */
struct NAAAIM_PVEenclave_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The enclave object. */
	SGXenclave enclave;

	/* The PVE endpoint description. */
	struct pve_endpoint endpoint;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_PVEenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(PVEenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PVEenclave_OBJID;


	S->poisoned = false;
	S->enclave  = NULL;

	return;
}


/**
 * External public method.
 *
 * This method opens the SGX interface device and loads the SGX
 * metadata and program segment data.
 *
 * \param this		A pointer to the provisioning object which
 *			is to be opened.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the launch token computed for
 *			the enclave.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool open(CO(PVEenclave, this), CO(char *, token))

{
	STATE(S);

	_Bool retn = false;

	struct SGX_einittoken *einit;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Load the launch token. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SGXenclave, S->enclave, ERR(goto done));

	if ( !S->enclave->open_enclave(S->enclave, DEVICE, ENCLAVE, false) )
		ERR(goto done);

	if ( !S->enclave->create_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->load_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->init_enclave(S->enclave, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a wrapper for calling the following ECALL:
 *
 * This is the message used to initiate communications with the
 * provisioning service.
 *
 * \param this		A pointer to the provisioning object for which
 *			the message is to be generated.
 *
 * \return	If an error is encountered while generating the endpoint
 *		a false value is returned.  A true value indicates the
 *		endpoint value has been generated.
 */

static _Bool generate_message1(CO(PVEenclave, this), CO(SGXmessage, msg))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Initialize request for:
	 *	protocol: ENDPOINT_SELECTION
	 *	type: TYPE_ES_MSG1
	 *	version: 1
	 */
	msg->init_request(msg, 2, 0, 1, S->endpoint.xid);

	/* Add the endpoint selector message. */
	if ( !msg->encode_es_request(msg, 0, S->endpoint.id) )
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
 * This method implements the gen_es_msg1_data_wrapper ECALL to the
 * PVE enclave.
 *
 * gen_es_msg1_data_wrapper
 *
 * This call populates the endpoint structure in the object state
 * information with an endpoing definition generated by the provisioning
 * enclave.
 *
 * \param this		A pointer to the provisioning object for which
 *			an endpoint is to be generated.
 *
 *
 * \return	If an error is encountered while generating the endpoint
 *		a false value is returned.  A true value indicates the
 *		endpoint value has been generated.
 */

static _Bool get_endpoint(CO(PVEenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct {
		uint32_t retn;
		struct pve_endpoint *endpoint;
	} ecall3;


	/* Call slot 3 to obtain endpoint information. */
	ecall3.endpoint = &S->endpoint;
	if ( !S->enclave->boot_slot(S->enclave, 3, &PVE_ocall_table, &ecall3, \
				    &rc) ) {
		fprintf(stderr, "PVE slot 3 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall3.retn != 0 ) {
		fprintf(stderr, "PVE error: %d\n", ecall3.retn);
		ERR(goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for the PVEenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(PVEenclave, this))

{
	STATE(S);


	WHACK(S->enclave);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a PVEenclave object.
 *
 * \return	A pointer to the initialized PVEenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PVEenclave NAAAIM_PVEenclave_Init(void)

{
	Origin root;

	PVEenclave this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PVEenclave);
	retn.state_size   = sizeof(struct NAAAIM_PVEenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PVEenclave_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->open = open;

	this->get_endpoint	= get_endpoint;
	this->generate_message1 = generate_message1;

	this->whack = whack;

	return this;
}