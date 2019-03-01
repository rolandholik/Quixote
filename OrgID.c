/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "OrgID.h"
#include "SHA256.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_OrgID_OBJID)
#error Object identifier not defined.
#endif


/** OrgID private state information. */
struct NAAAIM_OrgID_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Organizational identity. */
	Sha256 identity;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_OrgID_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const OrgID_State const S) {

	S->poisoned = false;

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_OrgID_OBJID;

	return;
}


/**
 * External public method.
 *
 * This method implements the creation of an organizational identity.
 * The identity is defined by the following function:
 *
 *	ID = Hn(anonymizer, Hn(NPI))
 *
 *	Where Hn = SHA256, the anonymizer is a randomly selected 256
 *	bit confounder and NPI is the ASCII representation of the 10
 *	digit ASCII National Provider Identity number.
 *
 * \param this		A pointer to the object implementing an
 * 			organizational identity.
 *
 * \param anonymizer	A character pointer to the hexadecimal
 *			representation of the organizational confounder.
 *
 * \param npi		A character pointer to the NPI number.
 *
 * \return		If an error occurs during the generation of
 * 			the identity the identity object is poisoned
 *			and a false value is returned.
 */

static _Bool create(const OrgID const this, const char * const anonymizer, \
		    const char * const npi)

{
	auto _Bool retn = false;

	auto const OrgID_State const S = this->state;

	auto Buffer anonkey = NULL,
		    npihash = NULL;


	/* Allocate Buffers used for input to hashing algorithm. */
	npihash = HurdLib_Buffer_Init();
	anonkey = HurdLib_Buffer_Init();
	if ( (npihash == NULL) || (anonkey == NULL) ) {
		S->poisoned = true;
		goto done;
	}

	/* Create hash of NPI number. */
	npihash->add(npihash, (unsigned char *) npi, strlen(npi));
	S->identity->add(S->identity, npihash);
	S->identity->compute(S->identity);
	npihash->reset(npihash);
	npihash->add_Buffer(npihash, S->identity->get_Buffer(S->identity));

	/* Merge anonymizer and npi hash. */
	anonkey->add_hexstring(anonkey, anonymizer);

	S->identity->reset(S->identity);
	S->identity->add(S->identity, anonkey);
	S->identity->add(S->identity, npihash);
	if ( S->identity->compute(S->identity) )
		retn = true;

	
 done:
	if ( anonkey != NULL )
		anonkey->whack(anonkey);
	if ( npihash != NULL )
		npihash->whack(npihash);

	return retn;
}


/**
 * External public method.
 *
 * This method resets the organizational identity.  This method needs
 * to be called after the create method has been in order to allow
 * additional organizational identities to be created.
 *
 * \param this	The organizational identity which is to be reset.
 */

static void reset(const OrgID const this)

{
	this->state->identity->reset(this->state->identity);
}


/**
 * External public method.
 *
 * This method returns the functional status of the organizational
 * identity.
 *
 * \param this	The object whose status is to be returned.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		the object has been contaminated by a dysfunctional
 *		event during its creatioin or operation.
 */

static _Bool poisoned(const OrgID const this)

{
	return this->state->poisoned;
}


/**
 * External public method.
 *
 * This method implements returning the Buffer object which contains
 * the organizational identity.
 *
 * \param this	The organizational identity whose Buffer object is to be
 *		returned.
 *
 * \return	A pointer to the Buffer object in the SHA256 hash object
 *		is returned to the caller.
 */

static Buffer get_Buffer(const OrgID const this)

{
	return this->state->identity->get_Buffer(this->state->identity);
}


/**
 * External public method.
 *
 * This method prints the organizational identity in hexadecimal
 * format.
 *
 * \param this	The identity to be printed.
 */

static void print(const OrgID const this)

{
	if ( this->state->poisoned ) {
		fputs("* POISONED *\n", stdout);
		return;
	}

	this->state->identity->print(this->state->identity);
}


/**
 * External public method.
 *
 * This method implements a destructor for a OrgID object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const OrgID const this)

{
	auto const OrgID_State const S = this->state;


	S->identity->whack(S->identity);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a OrgID object.
 *
 * \return	A pointer to the initialized OrgID.  A null value
 *		indicates an error was encountered in object generation.
 */

extern OrgID NAAAIM_OrgID_Init(void)

{
	auto Origin root;

	auto OrgID this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_OrgID);
	retn.state_size   = sizeof(struct NAAAIM_OrgID_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_OrgID_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->identity = NAAAIM_Sha256_Init()) == NULL )
		return NULL;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->create	 = create;
	this->reset	 = reset;
	this->get_Buffer = get_Buffer;
	this->print	 = print;
	this->poisoned	 = poisoned;
	this->whack	 = whack;

	return this;
}
