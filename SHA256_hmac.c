/** \file
 * This file contains the implementation of an object which generates
 * message digests bashed on SHA-256 crypographic hashing.
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
#include <openssl/hmac.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SHA256_hmac.h"


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

	/* Flag to indicate if digest has been computed. */
	_Bool computed;

	/* The message digest being used. */
	const EVP_MD *digest;

	/* The keyed digest context. */
	HMAC_CTX context;

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

static void _init_state(const SHA256_hmac_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SHA256_hmac_OBJID;

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

static _Bool _init_crypto(const SHA256_hmac_State const S )

{
	 static _Bool initialized = false;


	 /* Initialize all the available digests. */
	 if ( !initialized ) {
		 OpenSSL_add_all_digests();
		 initialized = true;
	 }

	 /* Describe the hash we are using. */
#if 1
	 if ( (S->digest = EVP_get_digestbyname("SHA256")) == NULL ) {
		 fputs("HMAC defaulting to shorter hash.\n", stderr);
		 if ( (S->digest = EVP_get_digestbyname("SHA1")) == NULL )
			 return false;
	 }
#else
	 if ( (S->digest = EVP_get_digestbyname("SHA1")) == NULL )
		 return false;
#endif


	 /* Initialize structures for the hash and digest algorithms. */
	 HMAC_CTX_init(&S->context);

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

static _Bool _compute_digest(const SHA256_hmac_State const S)

{
	auto unsigned char buffer[EVP_MD_size(S->digest)];

	auto int size;


	if ( S->computed )
		return true;
	S->computed = true;

	HMAC_Final(&S->context, buffer, &size);

	if ( !S->buffer->add(S->buffer, buffer, size) )
		return false;

	return true;
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

static _Bool add(const SHA256_hmac const this, \
		 unsigned const char * const bf, size_t const size)

{
	auto const SHA256_hmac_State const S = this->state;


	/* Refuse to add to the hash if it has been computed. */
	if ( S->computed )
		return false;

	/* Initialize the digest if necessary. */
	if ( !S->computed ) {
		HMAC_Init_ex(&S->context, S->key->get(S->key), \
			     S->key->size(S->key), S->digest, NULL);
		S->buffer->reset(S->buffer);
	}

	/* Add the buffer contents. */
	HMAC_Update(&S->context, bf, size);

	return true;
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

static _Bool add_Buffer(const SHA256_hmac const this, const Buffer const bf)

{
	auto const SHA256_hmac_State const S = this->state;


	/* Refuse to add to the hash if it has been computed. */
	if ( S->computed )
		return false;

	/* Initialize the digest if necessary. */
	if ( !S->computed ) {
		HMAC_Init_ex(&S->context, S->key->get(S->key), \
			     S->key->size(S->key), S->digest, NULL);
		S->buffer->reset(S->buffer);
	}

	/* Add the buffer contents. */
	HMAC_Update(&S->context, bf->get(bf), bf->size(bf));

	return true;
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

static _Bool compute(const SHA256_hmac const this)

{
	if ( !_compute_digest(this->state) )
		return NULL;

	return true;
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

static void reset(const SHA256_hmac const this)

{
	auto const SHA256_hmac_State const S = this->state;

	S->computed = false;
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

static unsigned char *get(const SHA256_hmac const this)

{
	auto const SHA256_hmac_State const S = this->state;


	if ( !S->computed )
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

static Buffer get_Buffer(const SHA256_hmac const this)

{
	auto const SHA256_hmac_State const S = this->state;


	if ( !S->computed )
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

static void print(const SHA256_hmac const this)

{
	this->state->buffer->print(this->state->buffer);
}


/**
 * External public method.
 *
 * This method implements a destructor for a SHA256_hmac object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const SHA256_hmac const this)

{
	auto const SHA256_hmac_State const S = this->state;


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
	auto Origin root;

	auto SHA256_hmac this = NULL;

	auto struct HurdLib_Origin_Retn retn;


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
