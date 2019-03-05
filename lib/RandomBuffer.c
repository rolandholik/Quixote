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
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>

#include <Origin.h>
#include <Buffer.h>
#include <String.h>

#include <openssl/rand.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_RandomBuffer_OBJID)
#error Object identifier not defined.
#endif


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

	/* Random seed filename. */
	String randfile;

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

static _Bool _init_crypto(const RandomBuffer_State const S)

{
	auto const char *filep;
	auto char rfile[PATH_MAX];


	/* Acquire and set random filename. */
	S->randfile = NULL;

	memset(rfile, '\0', sizeof(rfile));
	filep = RAND_file_name(rfile, sizeof(rfile));
	if ( filep != NULL ) {
		if ( RAND_load_file(rfile, -1) )
			S->randfile = HurdLib_String_Init_cstr(filep);
		if ( !RAND_status() ) {
			S->randfile->whack(S->randfile);
			return false;
		}
	}

	if ( !RAND_status() )
		return false;
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

static _Bool generate(const RandomBuffer const this, const int count)

{
	auto const RandomBuffer_State const S = this->state;

	auto _Bool retn = false;

	auto unsigned char *p = NULL;


	if ( S->poisoned )
		return false;

	/* Malloc the area to fill to insure stack safety. */
	if ( (p = malloc(count)) == NULL )
		return false;

	if ( RAND_bytes(p, count) == 0 ) {
		S->poisoned = true;
		goto done;
	}

	if ( S->random->poisoned(S->random) ) {
		S->poisoned = true;
		goto done;
	}
	if ( S->random->size(S->random) > 0 )
		S->random->reset(S->random);
	if ( !S->random->add(S->random, p, count) ) {
		S->poisoned = true;
		goto done;
	}
	retn = true;


 done:
	if ( p != NULL )
		free(p);
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

static Buffer get_Buffer(const RandomBuffer const this)

{
	return this->state->random;
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

static void print(const RandomBuffer const this)

{
	this->state->random->print(this->state->random);
}
	

/**
 * External public method.
 *
 * This method implements a destructor for a RandomBuffer object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const RandomBuffer const this)

{
	auto const RandomBuffer_State const S = this->state;


	if ( S->randfile != NULL ) {
		RAND_write_file(S->randfile->get(S->randfile)); 
		S->randfile->whack(S->randfile);
	}

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
	auto Origin root;

	auto RandomBuffer this = NULL;

	auto struct HurdLib_Origin_Retn retn;


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
