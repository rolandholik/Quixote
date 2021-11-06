/** \file
 * This file provides the method implementations for an object which
 * implements the encoding and decoding of data in Base64 format.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/base64.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "Base64.h"

/* Object state extraction macro. */
#define STATE(var) CO(Base64_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_Base64_OBJID)
#error Object identifier not defined.
#endif


/** Base64 private state information. */
struct HurdLib_Base64_State
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
 * This method is responsible for initializing the NAAAIM_Base64_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(Base64_State, S)) {

	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_Base64_OBJID;

	S->poisoned  = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the encoding of a block of binary data into
 * Base64 ASCII format.
 *
 * \param this		A pointer to the object which is requesting
 *			encoding of a collection of binary data.
 *
 * \param input		The object containing the binary data to be
 *			encoded.
 *
 * \param output	The object which will contain the Base64
 *			encoded data.
 *
 * \return	If an error is encountered while carrying out the
 *		encoding a false value is returned.  A true value
 *		indicates the output object contains valid encoded
 *		data.
 */

static _Bool encode(CO(Base64, this), CO(Buffer, input), CO(String, output))

{
	STATE(S);

	_Bool retn = false;


	/* Validate object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( input->poisoned(input) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Get the size of the output buffer. */



	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the decoding of the ASCII specification of
 * a Base64 string into its binary form.
 *
 * \param this		A pointer to the object which is requesting
 *			decoding of a Base64 string.
 *
 * \param input		The object containing the ASCII data to be
 *			decoded.
 *
 * \param output	The object which will will be loaded with the
 *			binary representation of the decoding.
 *
 * \return	If an error is encountered while carrying out the
 *		decoding a false value is returned.  A true value
 *		indicates the output object contains valid decoded
 *		data.
 */

static _Bool decode(CO(Base64, this), CO(String, input), CO(Buffer, output))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	size_t size;


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( input->poisoned(input) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Get output length and size Buffer accordingly. */
	rc = mbedtls_base64_decode(NULL, 0, &size,			\
				   (unsigned char *) input->get(input),	\
				   input->size(input));
	if ( rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL )
		ERR(goto done);

	output->reset(output);
	while ( size-- ) {
		if ( !output->add(output, (void *) "\0", 1) )
			ERR(goto done);
	}


	/* Decode the buffer. */
	rc = mbedtls_base64_decode(output->get(output),			\
				   output->size(output), &size,		\
				   (unsigned char *) input->get(input),	\
				   input->size(input));
	if ( rc != 0 )
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
 * This method implements a destructor for the Base64 object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Base64, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Base64 object.
 *
 * \return	A pointer to the initialized Base64.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Base64 NAAAIM_Base64_Init(void)

{
	Origin root;

	Base64 this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct HurdLib_Base64);
	retn.state_size   = sizeof(struct HurdLib_Base64_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_Base64_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);


	/* Method initialization. */
	this->encode = encode;
	this->decode = decode;

	this->whack = whack;

	return this;
}
