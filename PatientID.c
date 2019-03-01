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
#include "PatientID.h"
#include "SHA256.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PatientID_OBJID)
#error Object identifier not defined.
#endif


/** PatientID private state information. */
struct NAAAIM_PatientID_State
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
 * This method is responsible for initializing the NAAAIM_PatientID_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const PatientID_State const S) {

	S->poisoned = false;

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PatientID_OBJID;

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
 * \param orgid		An object containing the organizational identity
 *			which the patient's identity is to be fused into.
 *
 * \param patientid	A character pointer to the patient identifier to
 *			be used as the identifier credential.
 *
 * \return		If an error occurs during the generation of
 * 			the identity the identity object is poisoned
 *			and a false value is returned.
 */

static _Bool create(const PatientID const this, const OrgID const orgid, \
		    const char * const idkey, const char * const ptid)

{
	auto _Bool retn = false;

	auto const PatientID_State const S = this->state;

	auto Buffer idhash = NULL,
		    ptidhash = NULL;


	/* Verify functionality of organizational identity. */
	if ( orgid->poisoned(orgid) ) {
		S->poisoned = true;
		goto done;
	}

	/* Allocate Buffer used for input to hashing algorithm. */
	idhash = HurdLib_Buffer_Init();
	ptidhash = HurdLib_Buffer_Init();
	if ( (idhash == NULL) || (ptidhash == NULL) ) {
		S->poisoned = true;
		goto done;
	}

	/* Convert the credential identifier key into a Buffer. */
	idhash->add_hexstring(idhash, idkey);

	/* Create patient identity precursor. */
	ptidhash->add(ptidhash, (unsigned char *) ptid, strlen(ptid));
	S->identity->add(S->identity, ptidhash);
	S->identity->compute(S->identity);

	ptidhash->reset(ptidhash);
	ptidhash->add_Buffer(ptidhash, S->identity->get_Buffer(S->identity));

	S->identity->reset(S->identity);
	S->identity->add(S->identity, idhash);
	S->identity->add(S->identity, ptidhash);
	S->identity->compute(S->identity);

	ptidhash->reset(ptidhash);
	ptidhash->add_Buffer(ptidhash, S->identity->get_Buffer(S->identity));


	/* Fuse the organization identity and the patient identity hash. */
	S->identity->reset(S->identity);
	S->identity->add(S->identity, orgid->get_Buffer(orgid));
	S->identity->add(S->identity, ptidhash);
	if ( S->identity->compute(S->identity) )
		retn = true;


 done:
	if ( idhash != NULL )
		idhash->whack(idhash);
	if ( ptidhash != NULL )
		ptidhash->whack(ptidhash);

	return retn;
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

static Buffer get_Buffer(const PatientID const this)

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

static void print(const PatientID const this)

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
 * This method implements a destructor for a PatientID object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const PatientID const this)

{
	auto const PatientID_State const S = this->state;


	S->identity->whack(S->identity);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a PatientID object.
 *
 * \return	A pointer to the initialized PatientID.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PatientID NAAAIM_PatientID_Init(void)

{
	auto Origin root;

	auto PatientID this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PatientID);
	retn.state_size   = sizeof(struct NAAAIM_PatientID_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PatientID_OBJID, &retn) )
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
	this->get_Buffer = get_Buffer;
	this->print	 = print;
	this->whack	 = whack;

	return this;
}
