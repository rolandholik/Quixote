/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2009, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>

#include <openssl/rsa.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "IDsignature.h"
#include "SHA256.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDsignature_OBJID)
#error Object identifier not defined.
#endif


/** IDsignature private state information. */
struct NAAAIM_IDsignature_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Private RSA key for signature generation. */
	RSA *private_key;

	/* Public RSG key for verifying signature. */
	RSA *public_key;
       
	/* Signature buffer. */
	SHA256 signature;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDsignature_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const IDsignature_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDsignature_OBJID;

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDsignature object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const IDsignature const this)

{
	auto const IDsignature_State const S = this->state;


	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a IDsignature object.
 *
 * \return	A pointer to the initialized IDsignature.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDsignature NAAAIM_IDsignature_Init(void)

{
	auto Origin root;

	auto IDsignature this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDsignature);
	retn.state_size   = sizeof(struct NAAAIM_IDsignature_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDsignature_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->signature = NAAAIM_SHA256_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->whack = whack;

	return this;
}
