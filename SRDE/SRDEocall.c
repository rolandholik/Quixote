/** \file
 * This file contains the implementation on object that is used to
 * maintain the OCALL definitions for an enclave.
 *
 * When an ECALL is executed one of the parameters passed to an
 * enclave is a pointer to a structure that contains two members.  The
 * first member is a count of the number of function pointers in the
 * dispatch table.  The second member is an array of function
 * pointers, each of which points to the address of a function in
 * untrusted space that implements the designated OCALL.
 *
 * This object allows the function dispatch table to be built
 * dynamically and by multiple libraries.  When requested it populates
 * an OCALL dispatch table with the appropriate values.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEocall.h"
#include "SRDEfusion-ocall.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEocall_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEocall_OBJID)
#error Object identifier not defined.
#endif


/** SRDEocall private state information. */
struct NAAAIM_SRDEocall_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* OCALL count. */
	uint16_t ocall_count;

	/* Buffer object to hold function pointers. */
	Buffer ocalls;

	/* Buffer object to hold image of OCALL_api structre. */
	Buffer table;
};


/* Definition for the function used to register SRDEfusion OCALL's. */
_Bool SRDEfusion_ocall_add(const SRDEocall);


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEocall_State
 * structure that holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information that is to be initialized.
 */

static void _init_state(CO(SRDEocall_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEocall_OBJID;

	S->poisoned = false;

	S->ocall_count = 0;

	S->ocalls = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the registration of an OCALL function
 * handler.
 *
 * \param this	A pointer to the object that the function handler
 *		is to be added to.
 *
 * \param ptr	A pointer to the function that is to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the function pointer was added.  A false value
 *		indicates the addition is failed and the object is
 *		poisoned.  A true value indicates the value was
 *		added.
 */

static _Bool add(CO(SRDEocall, this), CO(void *, ptr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Add the function pointer. */
	if ( !S->ocalls->add(S->ocalls, (uint8_t *) &ptr, sizeof(void *)) )
		ERR(goto done);

	++S->ocall_count;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the registration of OCALL functions that
 * are used by the SRDEfusion trusted library.
 *
 * \param this	A pointer to the object that will have the OCALL's
 *		added to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the OCALL's were added.  A false value indicates the
 *		addition is failed and the object is poisoned.  A
 *		true value indicates the functions were added.
 */

static _Bool add_SRDEfusion(CO(SRDEocall, this))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);

	/* Call the registration function and set the return code. */
	if ( !SRDEfusion_ocall_add(this) )
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
 * This method is an accessor method that is used to populate the
 * structure that is passed in an ECALL to define the functions that
 * will be invoked in response to OCALL's requested by the enclave.
 *
 *
 * \param this	A pointer to the object that contains the OCALL
 *		function pointers that are being requested.
 *
 * \param tp	A pointer to the structure that is to be populated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the structure was populated.  A false value
 *		indicates population.  A truve value indicates the
 *		structure can be considered valid.
 */

static _Bool get_table(CO(SRDEocall, this), struct OCALL_api **tp)

{
	STATE(S);

	_Bool retn = false;

	size_t nr_ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Populate the table. */
	S->table->reset(S->table);

	nr_ocall = S->ocall_count;
	S->table->add(S->table, (uint8_t *) &nr_ocall, sizeof(nr_ocall));

	if ( !S->table->add_Buffer(S->table, S->ocalls) )
		ERR(goto done);

	*tp  = (struct OCALL_api *) S->table->get(S->table);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements printing out the contents of the currently
 * defined OCALL dispatch table.
 *
 * \param this	 A pointer to the object whose contents is to be printed.
 */

static void print(CO(SRDEocall, this))

{
	STATE(S);

	unsigned int lp;

	struct OCALL_api *table;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*POISONED*\n", stderr);
		return;
	}


	/* Traverse current OCALL table. */
	if ( !this->get_table(this, &table) )
		ERR(return;);

	fprintf(stdout, "OCALL count: %zd\n", table->nr_ocall);

	for (lp= 0; lp < table->nr_ocall; ++lp)
		fprintf(stdout, "\t#%d: %p\n", lp, table->table[lp]);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a SRDEocall object.
 *
 * \param this	 A pointer to the object that is to be destroyed.
 */

static void whack(CO(SRDEocall, this))

{
	STATE(S);


	WHACK(S->ocalls);
	WHACK(S->table);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEocall object.
 *
 * \return	A pointer to the initialized SRDEocall.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEocall NAAAIM_SRDEocall_Init(void)

{
	Origin root;

	SRDEocall this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEocall);
	retn.state_size   = sizeof(struct NAAAIM_SRDEocall_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEocall_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->ocalls, goto err);
	INIT(HurdLib, Buffer, this->state->table, goto err);

	/* Method initialization. */
	this->add	     = add;
	this->add_SRDEfusion = add_SRDEfusion;

	this->get_table = get_table;

	this->print = print;
	this->whack = whack;

	return this;

 err:
	if ( this->state->ocalls != NULL )
		this->state->ocalls->whack(this->state->ocalls);
	if ( this->state->table != NULL )
		this->state->table->whack(this->state->table);

	this->state->root->whack(this->state->root, this, this->state);
	return NULL;
}
