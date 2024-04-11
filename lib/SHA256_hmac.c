/** \file
 * This file contains the implementation of an object which generates
 * message digests bashed on SHA-256 crypographic hashing.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SHA256_hmac.h"


/* Object state extraction macro. */
#define STATE(var) CO(SHA256_hmac_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SHA256_hmac_OBJID)
#error Object identifier not defined.
#endif


/** SHA256_hmac private state information. */
struct NAAAIM_SHA256_hmac_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate whether or not object has been initialized. */
	_Bool initialized;

	/* Flag to indicate if digest has been computed. */
	_Bool computed;

	/* The message digest being used. */
	const EVP_MD *digest;

	/* The keyed digest context. */
	HMAC_CTX *context;

	/* The Buffer object containing the authentication key. */
	Buffer key;

	/* The MAC output buffer. */
	Buffer buffer;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the KerDAP_SHA256_hmac_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SHA256_hmac_State, S))

{

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SHA256_hmac_OBJID;

	S->poisoned    = false;
	S->initialized = false;
	S->computed    = false;

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

static _Bool _init_crypto(CO(SHA256_hmac_State, S))

{
	_Bool retn = false;

	static _Bool initialized = false;


	/* Initialize all the available digests. */
	if ( !initialized ) {
		EVP_add_digest(EVP_sha256());
		initialized = true;
	}

	/* Describe the hash we are using. */
	if ( (S->digest = EVP_sha256()) == NULL )
		ERR(goto done);

	/* Initialize structures for the hash and digest algorithms. */
	if ( (S->context = HMAC_CTX_new()) == NULL )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return true;
}


/**
 * Internal private method.
 *
 * This method implements computation of a final message authentication
 * code.  The computed variable in the state object is set so as to
 * force re-initialization of the HMAC context at the next attempt to
 * add contents to the digest
 *
 * The finalization function for the digest context is called by this
 * method.  If that call is successful the computed digest value is
 * transferred to the Buffer object designed to hold the digest for
 * the object.
 *
 * \param	A pointer to the state information of the SHA256 object
 *		whose digest is being computed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the hash computation.
 */

static _Bool _compute_digest(CO(SHA256_hmac_State, S))

{
	_Bool retn = false;

	unsigned char buffer[EVP_MD_size(S->digest)];

	unsigned int size;


	if ( S->poisoned )
		return false;

	if ( S->computed )
		ERR(goto done);
	S->computed = true;

	HMAC_Final(S->context, buffer, &size);

	if ( !S->buffer->add(S->buffer, buffer, size) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * This method implements adding the contents of a buffer of given size
 * to the MAC being constructed.
 *
 * \param this	A pointer to the MAC object which is having content
 *		added to it.
 *
 * \param bf	A pointer to buffer which is to be added.
 *
 * \param size	The number of bytes in the buffer to add.
 */

static _Bool add(CO(SHA256_hmac, this), unsigned const char * const bf, \
		 size_t const size)

{
	STATE(S);

	_Bool retn = false;


	/*
	 * Sanity checks for the integrity of the object and improper use
	 * of the object.
	 */
	if ( S->poisoned )
		goto done;
	if ( S->computed ) {
		S->poisoned = true;
		goto done;
	}


	/* Initialize the digest if necessary. */
	if ( !S->initialized ) {
		HMAC_Init_ex(S->context, S->key->get(S->key), \
			     S->key->size(S->key), S->digest, NULL);
		S->initialized = true;
	}

	/* Add the buffer contents. */
	HMAC_Update(S->context, bf, size);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * This method implements adding the contents of a buffer to the current
 * MAC being constructed.
 *
 * \param this	A pointer to the MAC object which is having content
 *		added to it.
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of the data addition.
 */

static _Bool add_Buffer(CO(SHA256_hmac, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;


	/*
	 * Refuse to add to the hash and poison the object to indicate a
	 * programming issue.  Also verify the incoming object does not
	 * have a problem.
	 */
	if ( S->computed )
		ERR(goto done);
	if ( bf->poisoned(bf) )
		ERR(goto done);


	/* Initialize the digest if necessary. */
	if ( !S->initialized ) {
		HMAC_Init_ex(S->context, S->key->get(S->key), \
			     S->key->size(S->key), S->digest, NULL);
		S->initialized = true;
	}

	/* Add the buffer contents. */
	HMAC_Update(S->context, bf->get(bf), bf->size(bf));
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * This method implements computation of the final authentication code
 * the MAC object.
 *
 * \param this	A pointer to the digest object whose MAC is to be
 *		computed.
 *
 * \return	A boolean value is used to indicate success or failure
 *		of the digest computation.
 */

static _Bool compute(CO(SHA256_hmac, this))

{
	return _compute_digest(this->state);
}


/**
 * External public method.
 *
 * This method implements resetting the HMAC object in preparation for
 * computation of another MAC code.
 * of another element.  It flags the digest to be re-initialized and
 * clears the current digest Buffer.
 *
 * \param this	A pointer to the SHA256 digest which is to be reset.
 *
 */

static void reset(CO(SHA256_hmac, this))

{
	STATE(S);

	S->computed    = false;
	S->initialized = false;
	S->buffer->reset(S->buffer);

	return;
}


/**
 * External public method.
 *
 * This method implements the return of the contents of the computed
 * MAC.  If the MAC has not been computed an error return is issued to
 * the caller.
 *
 * \param this	A pointer to the MAC digest object whose hash
 *		buffer is to be returned.
 *
 * \return	This method returns the character pointer returned
 *		by the get method of the Buffer object used to hold
 *		the MAC code.
 */

static unsigned char *get(CO(SHA256_hmac, this))

{
	STATE(S);


	if ( !S->computed )
		S->poisoned = true;
	if ( S->poisoned )
		return NULL;

	return S->buffer->get(S->buffer);
}


/**
 * External public method.
 *
 * This method implements the return of the contents of the computed
 * MAC in the form of a Buffer object.  If the MAC has not been computed
 * an error return is issued to the caller.
 *
 * \param this	A pointer to the MAC object whose Buffer object is to
 *		be returned.
 *
 * \return	The method returns a pointer to the Buffer object from
 *		the state structure of the object.  The MAC object
 *		returns control of the Buffer which will be destoryed if
 *		the destructor for MAC object is called.
 */

static Buffer get_Buffer(CO(SHA256_hmac, this))

{
	STATE(S);


	if ( !S->computed )
		S->poisoned = true;
	if ( S->poisoned )
		return NULL;

	return S->buffer;
}


/**
 * External public method.
 *
 * This method implements printing of the MAC doe.  Printing is implemented
 * by calling the print method of the Buffer holding the hash digest.
 *
 * \param this	A pointer to the MAC object which is to be printed.
 */

static void print(CO(SHA256_hmac, this))

{
	STATE(S);


	if ( S->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}
	S->buffer->print(S->buffer);
}


/**
 * External public method.
 *
 * This method implements a destructor for a SHA256_hmac object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SHA256_hmac, this))

{
	STATE(S);


	HMAC_CTX_free(S->context);

	if ( S->buffer != NULL )
		S->buffer->whack(S->buffer);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SHA256_hmac object.
 *
 * \param key	A Buffer object whose contents will be used as the key
 *		for the MAC.  The provider of the key retains control
 *		of the object.  The object destructor for the MAC will
 *		not destroy the key object buffer.
 *
 * \return	A pointer to the initialized SHA256_hmac.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SHA256_hmac NAAAIM_SHA256_hmac_Init(const Buffer key)

{
	Origin root;

	SHA256_hmac this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SHA256_hmac);
	retn.state_size   = sizeof(struct NAAAIM_SHA256_hmac_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SHA256_hmac_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->buffer = HurdLib_Buffer_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);
	this->state->key = key;

	/* Initilize cryptographic state .*/
	if ( !_init_crypto(this->state) ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Method initialization. */
	this->add	 = add;
	this->add_Buffer = add_Buffer;

	this->compute	 = compute;
	this->reset	 = reset;

	this->get   	 = get;
	this->get_Buffer = get_Buffer;

	this->print	 = print;
	this->whack	 = whack;

	return this;
}
