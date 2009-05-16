/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>

#include <krb5.h>

#include <Origin.h>

#include "KerDAP.h"
#include "Hash.h"


/* Verify library/object header file inclusions. */
#if !defined(KerDAP_LIBID)
#error Library identifier not defined.
#endif

#if !defined(KerDAP_Hash_OBJID)
#error Object identifier not defined.
#endif


/** Hash private state information. */
struct KerDAP_Hash_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the KerDAP_Hash_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const Hash_State const S) {

	S->libid = KerDAP_LIBID;
	S->objid = KerDAP_Hash_OBJID;

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Hash object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const Hash const this)

{
	auto Hash_State S = this->state;

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Hash object.
 *
 * \return	A pointer to the initialized Hash.
 */

extern Hash KerDAP_Hash_Init(void)

{
	auto Origin root;

	auto Hash this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct KerDAP_Hash);
	retn.state_size   = sizeof(struct KerDAP_Hash_State);
	root->init(root, KerDAP_LIBID, KerDAP_Hash_OBJID, &retn);
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->whack = whack;

	return this;
}
