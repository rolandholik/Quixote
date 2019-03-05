/** \file
 * This file provides the method implementations for an object which
 * implements the encoding and decoding of data in Base64 format.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
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

#include <openssl/evp.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "Base64.h"

/* Object state extraction macro. */
#define STATE(var) CO(Base64_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Base64_OBJID)
#error Object identifier not defined.
#endif


/** Base64 private state information. */
struct NAAAIM_Base64_State
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

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Base64_OBJID;

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

	unsigned char *p;

	unsigned char encbufr[5];

	uint32_t lp,
		 blocks,
		 residual;


	/* Validate object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( input->poisoned(input) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Base64 encode the input buffer. */
	p = input->get(input);

	blocks   = input->size(input) / 3;
	residual = input->size(input) % 3;

	for (lp= 0; lp < blocks; ++lp) {
		memset(encbufr, '\0', sizeof(encbufr));
		EVP_EncodeBlock(encbufr, p, 3);
		if ( !output->add(output, (char *) encbufr) )
			ERR(goto done);
		p += 3;
	}

	if ( residual > 0 ) {
		memset(encbufr, '\0', sizeof(encbufr));
		EVP_EncodeBlock(encbufr, p, residual);
		if ( !output->add(output, (char *) encbufr) )
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

	uint32_t lp,
		 blocks,
		 residual;

	unsigned char *p,
		       decbufr[3];


	/* Verify object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( input->poisoned(input) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Run the initial loop over the total data blocks. */
	p = (unsigned char *) input->get(input);

	blocks   = input->size(input) / 4;
	residual = input->size(input) % 4;

	for (lp= 0; lp < blocks; ++lp) {
		EVP_DecodeBlock(decbufr, p, 4);
		if ( !output->add(output, decbufr, sizeof(decbufr)) )
			ERR(goto done);
		p += 4;
	}


	/* Decode the residual bytes. */
	if ( residual > 0 ) {
		memset(decbufr, '\0', sizeof(decbufr));
		EVP_DecodeBlock(decbufr, p, residual);
		if ( !output->add(output, (void *) decbufr, sizeof(decbufr)) )
			ERR(goto done);
	} else {
		p -= 4;
		lp = 0;
		if ( *(p+2) == '=' )
			++lp;
		if ( *(p+3) == '=' )
			++lp;
		output->shrink(output, lp);
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
	retn.object_size  = sizeof(struct NAAAIM_Base64);
	retn.state_size   = sizeof(struct NAAAIM_Base64_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Base64_OBJID, &retn) )
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
