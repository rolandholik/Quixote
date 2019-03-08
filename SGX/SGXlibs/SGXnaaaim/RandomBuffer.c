/** \file
 * This file provides the implementation methods for the RandomBuffer
 * object which populates a Buffer object with random data.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_RandomBuffer_OBJID)
#error Object identifier not defined.
#endif


/* Object state extraction macro. */
#define STATE(var) CO(RandomBuffer_State, var) = this->state


/* External definition for assembler wrapper. */
extern _Bool rdrand(uint8_t *);


/** RandomBuffer private state information. */
struct NAAAIM_RandomBuffer_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Buffer of random data. */
	Buffer random;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_RandomBuffer_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const RandomBuffer_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_RandomBuffer_OBJID;

	S->poisoned = false;

	return;
}


/**
 * Internal private method.
 *
 * This method implements initialization of the cryptographic state for
 * this object.
 *
 * \param	A pointer to the state information which is to be
 *		initialized.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of the initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_crypto(CO(RandomBuffer_State, S))

{
	return true;
}


/**
 * External public method.
 *
 * This method implements a request for a specific number of random
 * bytes.  If the PRNG state does not support the request the object
 * will be poisoned.  If the request is successful the internal Buffer
 * object is loaded with the specified number of bytes.
 *
 * \param this	The object for which the allocation is to be requested.
 *
 * \param count	The number of bytes requested.
 *
 * \return	A boolean value is returned to indicate the success or
 *		failure of the allocation.
 */

static _Bool generate(CO(RandomBuffer, this), const unsigned int count)

{
	STATE(S);

	_Bool retn = false;

	uint8_t retry,
		bufr[sizeof(uint64_t)];

	unsigned int blocks,
		     residual;


	/* Verify object state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->random->poisoned(S->random) )
		ERR(goto done);
	if ( count == 0 )
		ERR(goto done);


	/* Generate random data eight bytes at a time. */
	if ( S->random->size(S->random) > 0 )
		S->random->reset(S->random);

	blocks	 = count / sizeof(uint64_t);
	residual = count % sizeof(uint64_t);

	while ( blocks-- ) {
		for (retry= 0; retry < 10; ++retry) {
			if ( rdrand(bufr) )
				break;
		}
		if ( retry == 10 )
			ERR(goto done);
		if ( !S->random->add(S->random, bufr, sizeof(bufr)) )
			ERR(goto done);
	}

	if ( residual ) {
		for (retry= 0; retry < 10; ++retry) {
			if ( rdrand(bufr) )
				break;
		}
		if ( retry == 10 )
			ERR(goto done);
		if ( !S->random->add(S->random, bufr, residual) )
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
 * This method implements returning a pointer to the Buffer object
 * containing the random buffer pool.
 *
 * \param this	A pointer to the object whose random buffer state is to
 *		be returned.
 *
 * \return	A pointer to the Buffer containing the random data pool.
 */

static Buffer get_Buffer(CO(RandomBuffer, this))

{
	STATE(S);


	return S->random;
}


/**
 * External public method.
 *
 * This method implements printing the contents of the random buffer
 * pool.  It is implemented by calling the print method of the Buffer
 * object containing the random data.
 *
 * \param this	The object whose random pool is to be printed.
 */

static void print(CO(RandomBuffer, this))

{
	STATE(S);


	S->random->print(S->random);
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a RandomBuffer object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(RandomBuffer, this))

{
	STATE(S);


	S->random->whack(S->random);
	S->root->whack(S->root, this, S);

	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a RandomBuffer object.
 *
 * \return	A pointer to the initialized RandomBuffer.  A null value
 *		indicates an error was encountered in object generation.
 */

extern RandomBuffer NAAAIM_RandomBuffer_Init(void)

{
	Origin root;

	RandomBuffer this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_RandomBuffer);
	retn.state_size   = sizeof(struct NAAAIM_RandomBuffer_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_RandomBuffer_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->random = HurdLib_Buffer_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Initilize cryptographic state .*/
	if ( !_init_crypto(this->state) ) {
		this->state->random->whack(this->state->random);
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Method initialization. */
	this->generate	 = generate;
	this->get_Buffer = get_Buffer;
	this->print	 = print;
	this->whack	 = whack;

	return this;
}
