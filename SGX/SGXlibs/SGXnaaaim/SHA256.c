/** \file
 * This file contains the implementation of an object which generates
 * cryptographic hashes based on the SHA256 algorithm.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SHA256.h"


/* Object state extraction macro. */
#define STATE(var) CO(SHA256_State, var) = this->state


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

	/* Flag to indicate whether or not object has been initialized. */
	_Bool initialized;

	/* Flag to indicate if digest has been computed. */
	_Bool computed;

	/* The type of digest being used. */
	const EVP_MD *digest;

	/* The digest context. */
	EVP_MD_CTX *context;

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

static void _init_state(CO(SHA256_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SHA256_OBJID;

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

static _Bool _init_crypto(CO(SHA256_State, S))

 {
	 static _Bool initialized = false;

	 _Bool retn = false;


	 /* Initialize all the available digests. */
	 if ( !initialized ) {
		 EVP_add_digest(EVP_sha256());
		 initialized = true;
	 }

	 /* Describe the hash we are using. */
	 if ( (S->digest = EVP_sha256()) == NULL )
		 ERR(goto done);

	 /* Initialize a structure for digest manipulations. */
	 S->context = EVP_MD_CTX_new();
	 retn = true;


 done:
	 if ( !retn )
		 S->poisoned = true;

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

static _Bool _compute_digest(CO(SHA256_State, S))

{
	_Bool retn = false;

	unsigned char buffer[EVP_MD_size(S->digest)];

	unsigned int size;


	if ( S->poisoned )
		ERR(goto done);

	if ( S->computed )
		ERR(goto done);
	S->computed = true;

	if ( !EVP_DigestFinal_ex(S->context, buffer, &size) )
		ERR(goto done);

	if ( !S->buffer->add(S->buffer, buffer, size) )
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

static _Bool add(CO(Sha256, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;


	/*
	 * Sanity checks for the integrity of the object and the
	 * input object.
	 */
	if ( S->poisoned )
		ERR(goto done);
	if ( bf->poisoned(bf) )
		ERR(goto done);


	/* Refuse to add to the hash if it has been computed. */
	if ( S->computed )
		ERR(goto done);

	/* Initialize the digest if necessary. */
	if ( !S->initialized ) {
		if ( !EVP_DigestInit_ex(S->context, S->digest, NULL) )
			ERR(goto done);
		S->initialized = true;
	}

	/* Add the buffer contents. */
	if ( !EVP_DigestUpdate(S->context, bf->get(bf), bf->size(bf)) )
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
 * This method implements computation of the final digest value of
 * the SHA256 hash.
 *
 * \param this	A pointer to the digest object whose value is to be
 *		computed.
 *
 * \return	A boolean value is used to indicate success or failure
 *		of the digest computation.
 */

static _Bool compute(CO(Sha256, this))

{
	return _compute_digest(this->state);
}


/**
 * External public method.
 *
 * This method implements performing one or more iterations over a
 * previously computed hash.  The ->compute method must have been
 * called on some preliminary contents before this method is called.
 *
 * \param this	A pointer to the digest object whose value is to be
 *		rehashed.
 *
 * \param cnt	The number of times the hash is to be iteratively
 *		computed.
 *
 * \return	A boolean value is used to indicate success or failure
 *		of the hashing sequence.
 */

static _Bool rehash(CO(Sha256, this), const unsigned int cnt)

{
	STATE(S);

	_Bool retn = false;

	unsigned char buffer[EVP_MD_size(S->digest)];

	unsigned int lp,
		     size;

	Buffer b = S->buffer;


	if ( S->poisoned )
		ERR(goto done);
	if ( cnt == 0 )
		ERR(goto done);
	if ( !S->computed )
		ERR(goto done);


	for (lp= 0; lp < cnt; ++lp) {
		if ( !EVP_DigestInit_ex(S->context, S->digest, NULL) )
			ERR(goto done);
		if ( !EVP_DigestUpdate(S->context, b->get(b), b->size(b)) )
			ERR(goto done);
		if ( !EVP_DigestFinal_ex(S->context, buffer, &size) )
			ERR(goto done);

		b->reset(b);
		if ( !b->add(b, buffer, size) )
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
 * This method implements extending the current hash value of the
 * object with the supplied material.  The strategy is to compute
 * the hash of the supplied material and concantenate the hash
 * to the current hash with subseqent re-hashing of the combined
 * value.
 *
 * The gotal of this is to implement the equivalent of a TPM PCR
 * register extension.
 *
 * \param this	A pointer to the digest object whose value is to be
 *		extended.
 *
 * \param bufr	The object containing the data to extend the hash
 *		with.
 *
 * \return	A boolean value is used to indicate success or failure
 *		of the extension sequence.
 */

static _Bool extend(CO(Sha256, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	unsigned char buffer[EVP_MD_size(S->digest)];

	unsigned int size;


	if ( S->poisoned )
		ERR(goto done);
	if ( !S->computed )
		ERR(goto done);
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		ERR(goto done);


	/* Hash the supplied material. */
	if ( !EVP_DigestInit_ex(S->context, S->digest, NULL) )
		ERR(goto done);
	if ( !EVP_DigestUpdate(S->context, bufr->get(bufr), \
			       bufr->size(bufr)) )
		ERR(goto done);
	if ( !EVP_DigestFinal_ex(S->context, buffer, &size) )
		ERR(goto done);

	if ( !S->buffer->add(S->buffer, buffer, size) )
		ERR(goto done);


	/* Hash the current buffer contents. */
	S->computed    = false;
	S->initialized = false;

	add(this, S->buffer);
	S->buffer->reset(S->buffer);
	if ( !compute(this) )
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
 * This method implements resetting the hash in preparation for computation
 * of another element.  It flags the digest to be re-initialized and
 * clears the current digest Buffer.
 *
 * \param this	A pointer to the SHA256 digest which is to be reset.
 *
 */

static void reset(CO(Sha256, this))

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

static unsigned char *get(CO(Sha256, this))

{
	STATE(S);


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

static Buffer get_Buffer(CO(Sha256, this))

{
	STATE(S);


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

static void print(CO(Sha256, this))

{
	STATE(S);

	if ( S->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}

	S->buffer->print(this->state->buffer);
}


/**
 * External public method.
 *
 * This method implements a destructor for a SHA256 object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Sha256, this))

{
	STATE(S);


	EVP_MD_CTX_free(S->context);

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

extern Sha256 NAAAIM_Sha256_Init(void)

{
	Origin root;

	Sha256 this = NULL;

	struct HurdLib_Origin_Retn retn;


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
	this->rehash	 = rehash;
	this->extend	 = extend;
	this->reset	 = reset;
	this->get   	 = get;
	this->get_Buffer = get_Buffer;
	this->print	 = print;
	this->whack 	 = whack;

	return this;
}
