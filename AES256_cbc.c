/** \file
 * This file contains the implementation of an object which implements
 * 256 bit AES encryption/decryption in CBC mode.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "AES256_cbc.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_AES256_cbc_OBJID)
#error Object identifier not defined.
#endif


/** AES256_CBC private state information. */
struct NAAAIM_AES256_cbc_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* The mode of the object. */
	enum
	{
		encrypt_mode=1,
		decrypt_mode
	} mode;

	/* The blocksize of the hash. */
	int blocksize;

	/* The encryption control structure. */
	EVP_CIPHER_CTX context;

	/* The encryption key. */
	Buffer key;

	/* The initialization vector. */
	Buffer iv;

	/* The Buffer to hold the input or output of the cipher. */
	Buffer buffer;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_AES256_CBC_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const AES256_cbc_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_AES256_cbc_OBJID;

	EVP_CIPHER_CTX_init(&S->context);

	return;
}


/**
 * External public method.
 *
 * This method implements encryption of the Buffer object which is supplied
 * by the caller.
 *
 * \param this	A pointer to the cipher object which is to carry out
 *		the encryption.
 *
 * \return	If the encryption is successful the Buffer object containing
 *		the encrypted payload is returned.
 */

static Buffer encrypt(const AES256_cbc const this, Buffer in)

{
	const AES256_cbc_State const S = this->state;

	unsigned char *bp = in->get(in),
			    encbuf[S->blocksize];

	int lp,
	    encsize,
	    rounds,
	    residual;

	size_t size = in->size(in);


	if ( S->mode != encrypt_mode )
		return NULL;
	if ( size == 0 )
		return NULL;

	
	rounds   = size / S->blocksize;
	residual = size % S->blocksize;

	for (lp= 0; lp < rounds; ++lp) {
		if ( !EVP_EncryptUpdate(&S->context, encbuf, &encsize, bp, \
					S->blocksize) )
			return NULL;
		if ( encsize > 0 )
			S->buffer->add(S->buffer, encbuf, encsize);
		bp += S->blocksize;
	}

	if ( !EVP_EncryptFinal_ex(&S->context, encbuf, &residual) )
		return NULL;
	S->buffer->add(S->buffer, encbuf, residual);

	return S->buffer;
}


/**
 * External public method.
 *
 * This method implements decryption of the Buffer object which is supplied
 * by the caller.
 *
 * \param this	A pointer to the cipher object which is to carry out
 *		the decryption.
 *
 * \return	If the decryption is successful the Buffer object containing
 *		the decrypted payload is returned.
 */

static Buffer decrypt(const AES256_cbc const this, Buffer in)

{
	const AES256_cbc_State const S = this->state;

	unsigned char *bp = in->get(in),
		      decbuf[S->blocksize * 2];

	unsigned int lp,
		     rounds;

	int decsize;


	if ( S->mode != decrypt_mode )
		return NULL;
	if ( in->size(in) == 0 )
		return NULL;

	rounds = in->size(in) / S->blocksize;

	for (lp= 0; lp < rounds; ++lp) {
		memcpy(decbuf, bp, S->blocksize);

		if ( !EVP_DecryptUpdate(&S->context, decbuf, &decsize, bp, \
					S->blocksize) )
			return NULL;
		if ( decsize > 0 )
			S->buffer->add(S->buffer, decbuf, decsize);
		bp += S->blocksize;
	}

	if ( !EVP_DecryptFinal_ex(&S->context, decbuf, &decsize) )
		return NULL;
	S->buffer->add(S->buffer, decbuf, decsize);

	return S->buffer;
}


/**
 * External public method.
 *
 * This method implements an accessor for obtaining the payload Buffer
 * holding the encrypted or decrypted message.
 *
 * \param this	The encryption object whose payload is to be returned.
 *
 * \return	The Buffer object containing the encrypted/decrypted
 *		message.
 */

static Buffer get_Buffer(const AES256_cbc const this)

{
	return this->state->buffer;
}


/**
 * External public method.
 *
v * This method implements a destructor for a AES256_CBC object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const AES256_cbc const this)

{
	const AES256_cbc_State const S = this->state;


	if ( S->buffer != NULL )
		S->buffer->whack(S->buffer);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a AES256_CBC object.
 *
 * \return	A pointer to the initialized AES256_CBC.  A null value
 *		indicates an error was encountered in object generation.
 */

extern AES256_cbc NAAAIM_AES256_cbc_Init(void)

{
	Origin root;

	AES256_cbc this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_AES256_cbc);
	retn.state_size   = sizeof(struct NAAAIM_AES256_cbc_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_AES256_cbc_OBJID, &retn) )
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

	/* Method initialization. */
	this->encrypt    = encrypt;
	this->decrypt    = decrypt;
	this->get_Buffer = get_Buffer;
	this->whack      = whack;

	return this;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call to set an AES256_CBC
 * object for encryption.
 *
 * \return	A pointer to the initialized AES256_CBC encryption object.
 *		A null value indicates an error was encountered in object
 *		generation.
 */

extern AES256_cbc NAAAIM_AES256_cbc_Init_encrypt(const Buffer const key, \
						 const Buffer const iv)

{
	AES256_cbc_State S;

	AES256_cbc this;


	if ( (this = NAAAIM_AES256_cbc_Init()) == NULL )
		return NULL;
	S = this->state;

	S->iv   = iv;
	S->key  = key;
	S->mode = encrypt_mode;

	if ( !EVP_EncryptInit_ex(&S->context, EVP_aes_256_cbc(), NULL, \
				 key->get(key), iv->get(iv)) ) {
		this->whack(this);
		return NULL;
	}
	S->blocksize = EVP_CIPHER_CTX_block_size(&S->context);

	return this;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call to set an AES256_CBC
 * object for decryption.
 *
 * \return	A pointer to the initialized AES256_CBC decryption object.
 *		A null value indicates an error was encountered in object
 *		generation.
 */

extern AES256_cbc NAAAIM_AES256_cbc_Init_decrypt(const Buffer const key, \
						 const Buffer const iv)

{
	AES256_cbc_State S;

	AES256_cbc this;


	if ( (this = NAAAIM_AES256_cbc_Init()) == NULL )
		return NULL;
	S = this->state;

	S->iv   = iv;
	S->key  = key;
	S->mode = decrypt_mode;

	if ( !EVP_DecryptInit_ex(&S->context, EVP_aes_256_cbc(), NULL, \
				 key->get(key), iv->get(iv)) ) {
		this->whack(this);
		return NULL;
	}
	S->blocksize = EVP_CIPHER_CTX_block_size(&S->context);

	return this;
}
