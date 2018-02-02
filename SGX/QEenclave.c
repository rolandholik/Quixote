/** \file
 * This file contains the implementation of an object which is used to
 * manage the Intel quoting enclave.  This enclave is provided as
 * a signed enclave by Intel as part of their runtime distribution.
 *
 * The quoting enclave is used generate platform 'quotes' which can
 * be submitted to Intel for verification.  The quoting enclave has
 * two major roles.  The fist is to verify the integrity of the EPID
 * 'blob' which has been provisioned to the platform.  The second
 * is to generate a platform quote using this 'blob'.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */


/* Local defines. */
#define DEVICE	"/dev/isgx"
#define ENCLAVE	"/opt/intel/sgxpsw/aesm/libsgx_qe.signed.so"


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
#include "RandomBuffer.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "QEenclave.h"


/* Object state extraction macro. */
#define STATE(var) CO(QEenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_QEenclave_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following defines an empty OCALL table for the quoting
 * enclave.
 */
static const struct {
	size_t nr_ocall;
	void *table[1];
} QE_ocall_table = { 0, {NULL}};


/** QEenclave private state information. */
struct NAAAIM_QEenclave_State
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

	/* The buffer containing the EPID. */
	Buffer epid;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_QEenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(QEenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_QEenclave_OBJID;


	S->poisoned = false;

	S->enclave = NULL;
	S->epid	   = NULL;
	return;
}


/**
 * External public method.
 *
 * This method is responsible for loading and initializing the
 * quoting enclave.
 *
 * \param this		A pointer to the quoting enclave object
 *			that is to be opened.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the launch token for the quoting
 *			enclave.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool open(CO(QEenclave, this), CO(char *, token))

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
 * This method is responsible for loading and verifying the EPID
 * that has been provisioned to the platform.
 *
 * \param this		A pointer to the quoting enclave object
 *			that is to load the EPID.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the EPID.
 *
 * \return	If an error is encountered while loading the EPID a
 *		false value is returned.  A true value indicates the
 *		EPID has been successfully loaded and verified.
 */

static _Bool load_epid(CO(QEenclave, this), CO(char *, epid))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	uint8_t resealed;

	File epid_file = NULL;

	struct {
		uint32_t retn;
		uint8_t *p_blob;
		uint32_t blob_size;
		uint8_t *p_is_resealed;
	} ecall0;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Allocate the EPID buffer if this is the first call, otherwise
	 * reset it.
	 */
	if ( S->epid == NULL ) {
		INIT(HurdLib, Buffer, S->epid, ERR(goto done));
	}
	else {
		if ( S->epid->poisoned(S->epid) )
			ERR(goto done);
		S->epid->reset(S->epid);
	}


	/* Load the blob. */
	INIT(HurdLib, File, epid_file, ERR(goto done));
	if ( !epid_file->open_ro(epid_file, epid) )
		ERR(goto done);
	if ( !epid_file->slurp(epid_file, S->epid) )
		ERR(goto done);


	/* Call slot 0 to verify the blob. */
	memset(&ecall0, '\0', sizeof(ecall0));

	ecall0.p_blob	     = S->epid->get(S->epid);
	ecall0.blob_size     = S->epid->size(S->epid);
	ecall0.p_is_resealed = &resealed;

	if ( !S->enclave->boot_slot(S->enclave, 0, &QE_ocall_table, &ecall0, \
				    &rc) ) {
		fprintf(stderr, "QE slot 0 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall0.retn != 0 ) {
		fprintf(stderr, "QE error: %d\n", ecall0.retn);
		ERR(goto done);
	}

	fprintf(stdout, "resealed: %u\n", resealed);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(epid_file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for the QEenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(QEenclave, this))

{
	STATE(S);


	WHACK(S->enclave);
	WHACK(S->epid);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a QEenclave object.
 *
 * \return	A pointer to the initialized QEenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern QEenclave NAAAIM_QEenclave_Init(void)

{
	Origin root;

	QEenclave this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_QEenclave);
	retn.state_size   = sizeof(struct NAAAIM_QEenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_QEenclave_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->open = open;

	this->load_epid = load_epid;

	this->whack = whack;

	return this;
}
