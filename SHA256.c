/** \file
 * This file contains the implementation of an object which generates
 * cryptographic hashes based on the SHA256 algorithm.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SHA256.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SHA256_OBJID)
#error Object identifier not defined.
#endif


/** SHA256 private state information. */
struct NAAAIM_SHA256_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate if digest has been computed. */
	_Bool computed;

	/* The type of digest being used. */
	const EVP_MD *digest;

	/* The digest context. */
	EVP_MD_CTX context;

	/* The output of the hash. */
	Buffer buffer;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the KerDAP_SHA256_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const SHA256_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SHA256_OBJID;

	S->poisoned = false;
	S->computed = false;

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

static _Bool _init_crypto(const SHA256_State const S )

 {
	 static _Bool initialized = false;


	 /* Initialize all the available digests. */
	 if ( !initialized ) {
		 OpenSSL_add_all_digests();
		 initialized = true;
	 }

	 /* Describe the hash we are using. */
	 if ( (S->digest = EVP_get_digestbyname("SHA256")) == NULL ) {
		 S->poisoned = true;
		 return false;
	 }

	 /* Initialize a structure for digest manipulations. */
	 EVP_MD_CTX_init(&S->context);

	 return true;
}


/**
 * Internal private method.
 *
 * This method implements computation of a final digest value for the
 * hash.  The needs_init variable in the state object is set so as to
 * force re-initialization of the digest context at the next attempt to
 * add contents to the hash.
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

static _Bool _compute_digest(const SHA256_State const S)

{
	auto _Bool retn = false;

	auto unsigned char buffer[EVP_MD_size(S->digest)];

	auto unsigned int size;


	if ( S->poisoned )
		return false;

	if ( S->computed ) {
		S->poisoned = true;
		goto done;
	}
	S->computed = true;

	if ( !EVP_DigestFinal_ex(&S->context, buffer, &size) ) {
		S->poisoned = true;
		goto done;
	}

	if ( !S->buffer->add(S->buffer, buffer, size) ){
		S->poisoned = true;
		goto done;
	}
	retn = true;

 done:
	return retn;
}
	
	
/**
 * External public method.
 *
 * This method implements adding the contents of a Buffer to the current
 * digest being constructed.
 *
 * \param this	A pointer to the SHA256 digest which is having content
 *		added to it.
 *
 * \param bf	The Buffer whose contents are to be added to the digest.
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of the data addition.
 */

static _Bool add(const SHA256 const this, const Buffer const bf)

{
	auto _Bool retn = false;

	auto const SHA256_State const S = this->state;


	/*
	 * Sanity checks for the integrity of the object and the
	 * input object.
	 */
	if ( S->poisoned )
		goto done;
	if ( bf->poisoned(bf) ) {
		S->poisoned = true;
		goto done;
	}


	/* Refuse to add to the hash if it has been computed. */
	if ( S->computed ) {
		S->poisoned = true;
		goto done;
	}

	/* Initialize the digest if necessary. */
	if ( !S->computed ) {
		if ( !EVP_DigestInit_ex(&S->context, S->digest, NULL) ) {
			S->poisoned = true;
			goto done;
		}
		S->buffer->reset(S->buffer);
	}

	/* Add the buffer contents. */
	if ( !EVP_DigestUpdate(&S->context, bf->get(bf), bf->size(bf)) ) {
		S->poisoned = true;
		goto done;
	}
	retn = true;

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements computation of the final digest value of
 * the SHA256 hash.
 *
 * \param this	A pointer to the digest object whose value is to be
 *		computed.
 *
 * \return	A boolean value is used to indicate success or failure
 *		of the digest computation.
 */

static _Bool compute(const SHA256 const this)

{
	return _compute_digest(this->state);
}


/**
 * External public method.
 *
 * This method implements resetting the hash in preparation for computation
 * of another element.  It flags the digest to be re-initialized and
 * clears the current digest Buffer.
 *
 * \param this	A pointer to the SHA256 digest which is to be reset.
 *
 */

static void reset(const SHA256 const this)

{
	auto const SHA256_State const S = this->state;

	S->computed = false;
	S->buffer->reset(S->buffer);

	return;
}
	

/**
 * External public method.
 *
 * This method implements the return of the contents of the computed
 * hash.  If the hash digest has not been computed an error is returned
 * to the caller.
 *
 * \param this	A pointer to the SHA256 digest object whose hash
 *		buffer is to be returned.
 *
 * \return	This method returns the character pointer returned
 *		by the get method of the Buffer object used to hold
 *		the results of the hash.
 */

static unsigned char *get(const SHA256 const this)

{
	auto const SHA256_State const S = this->state;


	if ( S->poisoned )
		return NULL;

	if ( !S->computed ) {
		S->poisoned = true;
		return NULL;
	}

	return S->buffer->get(S->buffer);
}


/**
 * External public method.
 *
 * This method implements the return of the contents of the computed
 * hash in the form of a Buffer object.  If the digest has not been
 * computed an error return is issued to the caller.
 *
 * \param this	A pointer to the SHA256 digest object whose Buffer
 *		object is to be returned.
 *
 * \return	The method returns a pointer to the Buffer object from
 *		the state structure of the object.  The SHA256 object
 *		returns control of the Buffer which will be destoryed if
 *		the destructor for this object is called.
 */

static Buffer get_Buffer(const SHA256 const this)

{
	auto const SHA256_State const S = this->state;


	if ( !S->computed ) {
		S->poisoned = true;
		return NULL;
	}

	return S->buffer;
}


/**
 * External public method.
 *
 * This method implements printing of the hash.  Printing is implemented
 * by calling the print method of the Buffer holding the hash digest.
 *
 * \param this	A pointer to the SHA256 object which is to be printed.
 */

static void print(const SHA256 const this)

{
	if ( this->state->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}
	this->state->buffer->print(this->state->buffer);
}


/**
 * External public method.
 *
 * This method implements a destructor for a SHA256 object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const SHA256 const this)

{
	auto const SHA256_State const S = this->state;


	EVP_MD_CTX_cleanup(&S->context);

	if ( S->buffer != NULL )
		S->buffer->whack(S->buffer);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a SHA256 object.
 *
 * \return	A pointer to the initialized SHA256.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SHA256 NAAAIM_SHA256_Init(void)

{
	auto Origin root;

	auto SHA256 this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SHA256);
	retn.state_size   = sizeof(struct NAAAIM_SHA256_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SHA256_OBJID, &retn) )
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

	/* Initilize cryptographic state .*/
	if ( !_init_crypto(this->state) ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Method initialization. */
	this->add	 = add;
	this->compute	 = compute;
	this->reset	 = reset;
	this->get   	 = get;
	this->get_Buffer = get_Buffer;
	this->print	 = print;
	this->whack 	 = whack;

	return this;
}
