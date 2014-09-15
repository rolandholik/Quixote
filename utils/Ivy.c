/** \file
 * This file contains the implementation of an object which manages
 * identity verification objects.
 *
 * An identify verification object contains the information which is
 * needed to verify the status of a remote host which is requesting
 * machine status verification.
 *
 * The following data elements are incorporated in an identity
 * verification data structure:
 *
 *	Identity token
 *	Identity attestation public key
 *	Software status
 *	Machine status reference
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Ivy.h"

/* Object state extraction macro. */
#define STATE(var) CO(Ivy_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Ivy_OBJID)
#error Object identifier not defined.
#endif


/** Ivy private state information. */
struct NAAAIM_Ivy_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Identity token. */
	Buffer id;

	/* Attestation identity public key. */
	Buffer pubkey;

	/* Software status. */
	Buffer software;

	/* Machine status reference. */
	Buffer reference;
};


/**
 * External public method.
 *
 * This method implements an accessor for obtaining the various verifier
 * elements from this object.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed.
 *
 * \param this		The verifier whose elements are to be accessed.
 *
 * \param element	The element which is to be returned.
 *
 * \return		The Buffer object containing the desired element
 *			is returned.
 */

static Buffer get_element(CO(Ivy, this), CO(Ivy_element, element))

{
	STATE(S);


	if ( S->poisoned )
		return NULL;

	switch ( element ) {
		case Ivy_id:
			return S->id;
			break;
		case Ivy_pubkey:
			return S->pubkey;
			break;
		case Ivy_software:
			return S->software;
			break;
		case Ivy_reference:
			return S->reference;
			break;

		default:
			return NULL;
			break;
	}

	return NULL;
}


/**
 * External public method.
 *
 * This method implements an accessor for setting the various verifier
 * elements in this token.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed to set the
 * multiple elements in the object.
 *
 * \param this		The verifier whose elements are to be set.
 *
 * \param element	The identity component to be set.
 * 
 * \param bufr		The data to be used for setting the element.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of setting the verifier element.  A true
 *			value is used to indicate success of the
 *			operation.  If a failure is detected in setting
 *			any component the object is poisoned.
 */

static _Bool set_element(CO(Ivy, this), CO(Ivy_element, element), \
			 CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	switch ( element ) {
		case Ivy_id:
			if ( !S->id->add_Buffer(S->id, bufr) )
				goto done;
			break;
		case Ivy_pubkey:
			if ( !S->pubkey->add_Buffer(S->pubkey, bufr) )
				goto done;
			break;
		case Ivy_software:
			if ( !S->software->add_Buffer(S->software, bufr) )
				goto done;
			break;
		case Ivy_reference:
			if ( !S->reference->add_Buffer(S->reference, bufr) )
				goto done;
			break;
		default:
			goto done;
			break;
	}

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Ivy_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(Ivy_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Ivy_OBJID;

	S->poisoned = false;

	S->id	     = NULL;
	S->pubkey    = NULL;
	S->software  = NULL;
	S->reference = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Ivy object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Ivy, this))

{
	STATE(S);


	WHACK(S->id);
	WHACK(S->pubkey);
	WHACK(S->software);
	WHACK(S->reference);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Ivy object.
 *
 * \return	A pointer to the initialized Ivy.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Ivy NAAAIM_Ivy_Init(void)

{
	auto Origin root;

	auto Ivy this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Ivy);
	retn.state_size   = sizeof(struct NAAAIM_Ivy_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Ivy_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->id, goto fail);
	INIT(HurdLib, Buffer, this->state->pubkey, goto fail);
	INIT(HurdLib, Buffer, this->state->software, goto fail);
	INIT(HurdLib, Buffer, this->state->reference, goto fail);

	/* Method initialization. */
	this->whack = whack;

	this->get_element = get_element;
	this->set_element = set_element;

	return this;


 fail:
	WHACK(this->state->id);
	WHACK(this->state->pubkey);
	WHACK(this->state->software);
	WHACK(this->state->reference);

	root->whack(root, this, this->state);
	return NULL;
}
