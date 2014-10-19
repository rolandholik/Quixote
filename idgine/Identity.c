/** \file
 * This file contains the implementation methods for the object which
 * creates and manages a basic instance of any of the fundamental
 * identity types.
 *
 * A fundamental identity is created via the following construct:
 *
 *	ID = Hn(anonymizer, Hn(identifier))
 *
 *	Where Hn = SHA256, the anonymizer is a randomly selected 256
 *	bit confounder and name is the ASCII representation of the
 *	identifier for the user, service or device.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "OrgID.h"
#include "Identity.h"


/* State definition macro. */
#define STATE(var) CO(Identity_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Identity_OBJID)
#error Object identifier not defined.
#endif


/** Identity private state information. */
struct NAAAIM_Identity_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Entity identity. */
	Buffer id;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Identity_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information for the object which is to be initialized.
 */

static void _init_state(CO(Identity_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Identity_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the creation of a fundamental identity.
 *
 * \param this		A pointer to the object which is requesting
 *			creation of an identity.
 *
 * \param orgid		The object which represents the organizational
 *			identity in which the created identity is to
 *			be rooted.
 *
 * \param identifier	A String object containing the identifier to
 *			be used as the basis for the identity.
 *
 * \return		A true value is returned if identity creation
 *			was successful.  A false value is returned if
 *			creation fails.
 */

static _Bool create(CO(Identity, this), CO(OrgID, orgid), \
		    CO(String, anonymizer), CO(String, identifier))

{
	STATE(S);

	_Bool retn = false;

	Buffer id = S->id;

	SHA256 sha256 = NULL;


	/* Integrity checks. */
	if ( S->poisoned )
		goto done;
	if ( orgid->poisoned(orgid) )
		goto done;
	if ( identifier->poisoned(identifier) )
		goto done;

	/* Hash the identifier. */
	INIT(NAAAIM, SHA256, sha256, goto done);

	if ( !id->add(id, (unsigned char *) identifier->get(identifier), \
		      identifier->size(identifier)) )
		goto done;

	sha256->add(sha256, id);
	if ( !sha256->compute(sha256) ) 
		goto done;

	/*
	 * Add the anonymizer for this identifier and extend the
	 * anonymizer with the hash of the identifier.
	 */
	id->reset(id);
	if ( !id->add_hexstring(id, anonymizer->get(anonymizer)) )
		goto done;

	if ( !id->add_Buffer(id, sha256->get_Buffer(sha256)) )
		goto done;

	sha256->reset(sha256);
	sha256->add(sha256, id);
	if ( !sha256->compute(sha256) )
		goto done;

	/* Extend the organizational identity with the identity entity hash. */
	id->reset(id);
	if ( !id->add_Buffer(id, sha256->get_Buffer(sha256)) )
		goto done;

	sha256->reset(sha256);
	sha256->add(sha256, orgid->get_Buffer(orgid));
	sha256->add(sha256, id);
	if ( !sha256->compute(sha256) )
		goto done;

	id->reset(id);
	if ( !id->add_Buffer(S->id, sha256->get_Buffer(sha256)) )
		goto done;

	retn = true;


 done:
	WHACK(sha256);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning the Buffer
 * object which holds the entity identity
 *
 * \param this		A pointer to the object whose identity is to
 *			be returned.
 *
 * \return		A pointer to the buffer which holds the computed
 *			identity is returned.
 */

static Buffer get_identity(CO(Identity, this))

{
	STATE(S);

	return S->id;
}


/**
 * External public method.
 *
 * This method implements resetting the current identity to prepare for
 * creation of additional identities.
 *
 * \param this		A pointer to the identity object which is to
 *			be reset.
 *
 * \return		No return value is defined.
 */

static void reset(CO(Identity, this))

{
	STATE(S);

	S->id->reset(S->id);
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Identity object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Identity, this))

{
	STATE(S);


	WHACK(S->id);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Identity object.
 *
 * \return	A pointer to the initialized Identity.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Identity NAAAIM_Identity_Init(void)

{
	auto Origin root;

	auto Identity this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Identity);
	retn.state_size   = sizeof(struct NAAAIM_Identity_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Identity_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->id, goto fail);

	/* Method initialization. */
	this->create = create;

	this->get_identity = get_identity;

	this->reset = reset;
	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->id);

	root->whack(root, this, this->state);
	return NULL;
}
