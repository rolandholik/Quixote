/** \file
 * This file contains the implementation of an object which is used to
 * implement the AES128-CMAC algorithm used to generate message
 * authentication signatures.  It currently serves as a wrapper
 * around the AES128_cmac object.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sgx_tcrypto.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "AES128_cmac.h"
#include "SRDEcmac.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEcmac_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEcmac_OBJID)
#error Object identifier not defined.
#endif


/** SRDEcmac private state information. */
struct NAAAIM_SRDEcmac_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEcmac_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SRDEcmac_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEcmac_OBJID;


	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the verification of an ECDSA signature.
 *
 * \param this		A pointer to the provisioning object which
 *			is to be opened.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool compute(CO(SRDEcmac, this), CO(Buffer, key), CO(Buffer, msg), \
		     CO(Buffer, mac))

{
	STATE(S);

	_Bool retn = false;

	AES128_cmac cmac = NULL;


	/* Object status verification. */
	if ( S->poisoned )
		ERR(goto done);


	/* Generate the signature. */
	INIT(NAAAIM, AES128_cmac, cmac, ERR(goto done));
	if ( !cmac->set_key(cmac, key) )
		ERR(goto done);
	if ( !cmac->add(cmac, msg->get(msg), msg->size(msg)) )
		ERR(goto done);
	if ( !cmac->compute(cmac) )
		ERR(goto done);

	if ( !mac->add_Buffer(mac, cmac->get_Buffer(cmac)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(cmac);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for the SRDEcmac object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEcmac, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEcmac object.
 *
 * \return	A pointer to the initialized SRDEcmac.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEcmac NAAAIM_SRDEcmac_Init(void)

{
	Origin root;

	SRDEcmac this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEcmac);
	retn.state_size   = sizeof(struct NAAAIM_SRDEcmac_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEcmac_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->compute = compute;

	this->whack = whack;

	return this;
}
