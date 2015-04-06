/** \file
 * This file implements methods for managing and manipulating
 * operations using assymetric RSA keys.  The RSAkey.h file provides
 * the API definitions and contracts for this object.
 */

/**************************************************************************
 * (C)Copyright 2009, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RSAkey.h"


/* State definition macro. */
#define STATE(var) CO(RSAkey_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_RSAkey_OBJID)
#error Object identifier not defined.
#endif


/** RSAkey private state information. */
struct NAAAIM_RSAkey_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Type of RSA key. */
	enum {no_key, public_key, private_key} type;

	/* RSA key. */
	RSA *key;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_RSAkey_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(RSAkey_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_RSAkey_OBJID;

	S->poisoned = false;

	S->type = no_key;
	S->key	= NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA private key and sets
 * the object type to be a private key object.
 *
 */

static _Bool load_private_key(CO(RSAkey, this), CO(char *,file))

{
	STATE(S);

	_Bool retn = false;

	FILE *infile = NULL;


	if ( (infile = fopen(file, "r")) == NULL )
		ERR(goto done);

	if ( PEM_read_RSAPrivateKey(infile, &S->key, NULL, NULL) == NULL )
		ERR(goto done);

	retn	= true;
	S->type = private_key;


 done:
	if ( !retn )
		S->poisoned = true;

	if ( infile != NULL )
		fclose(infile);

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA public key and sets the object
 * type to be a public key object.
 *
 */

static _Bool load_public_key(CO(RSAkey, this), CO(char *, file))

{
	STATE(S);

	_Bool retn = false;
	
	FILE *infile = NULL;


	if ( (infile = fopen(file, "r")) == NULL )
		ERR(goto done);

	if ( PEM_read_RSA_PUBKEY(infile, &S->key, NULL, NULL) == NULL )
		ERR(goto done);

	retn	= true;
	S->type = public_key;


 done:
	if ( !retn )
		S->poisoned = true;

	if ( infile != NULL )
		fclose(infile);

	return retn;
}


/**
 * External public method.
 *
 * This method implements encryption of a Buffer object with either an
 * RSA public or private key.  The mode of encryption is determined by
 * the type of key loaded into the structure.  For example if a private
 * key is loaded the supplied plaintext will be encrypted with the
 * private key and thus be suitable for decryption with the public
 * portion of the key.
 *
 * \param this		A pointer to the object describing the key to be used
 *			for encryption.
 *
 * \param payload	A Buffer object containing the plaintext to be
 *			encrypted.   This size of the payload must be
 *			less then the keysize of the RSA key minus the
 *			OAEP padding size.  If the encryption is successful
 *			the Buffer object will be cleared and loaded with
 *			the resultant ciphertext.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the encryption process.  A false
 *			value implies failure while a true value implies
 *			success.
 */

static _Bool encrypt(CO(RSAkey, this), CO(Buffer, payload))

{
	STATE(S);

	_Bool retn = false;

	int enc_status;

	unsigned char output[RSA_size(S->key)];


	/* Sanity checks. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->type == no_key )
		ERR(goto done);
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with private key. */
	if ( S->type == private_key )
		enc_status = RSA_private_encrypt(payload->size(payload), \
						 payload->get(payload),	 \
						 output, S->key,	 \
						 RSA_PKCS1_PADDING);
	else
		enc_status = RSA_public_encrypt(payload->size(payload), \
						payload->get(payload),	 \
						output, S->key,	 \
						RSA_PKCS1_OAEP_PADDING);

	if ( enc_status == -1 || (enc_status != RSA_size(S->key)) )
		ERR(goto done);

	payload->reset(payload);
	if ( !payload->add(payload, output, sizeof(output)) )
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
 * This method implements decryption of a Buffer object with either an
 * RSA public or private key.  The mode of decryption is determined by
 * the type of key loaded into the structure.  For example if a private
 * key is loaded the supplied plaintext will be decrypted with the
 * private key.
 *
 * \param this		A pointer to the object describing the key to be used
 *			for decryption.
 *
 * \param payload	A Buffer object containing the ciphertext to be
 *			decrypted.  If the decryption is successful the
 *			Buffer object will be loaded with the decrypted
 *			plaintext.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the decryption process.  A false
 *			value implies failure while a true value implies
 *			success.
 */

static _Bool decrypt(CO(RSAkey, this), CO(Buffer, payload))

{
	STATE(S);

	_Bool retn = false;

	int status;

	unsigned char output[RSA_size(S->key)];


	/* Sanity checks. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->type == no_key )
		ERR(goto done);
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with private key. */
	if ( S->type == private_key )
		status = RSA_private_decrypt(payload->size(payload),	    \
					     payload->get(payload), output, \
					     S->key, RSA_PKCS1_OAEP_PADDING);
	else
		status = RSA_public_decrypt(payload->size(payload),	   \
					    payload->get(payload), output, \
					    S->key, RSA_PKCS1_PADDING);

	if ( status == -1 )
		ERR(goto done);

	payload->reset(payload);
	if ( !payload->add(payload, output, status) )
		goto done;

	retn = true;


done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the size of the RSA encryption key.
 *
 * \param this	A pointer to the key whose size is to be returned.
 *
 * \return	The size of the encrypion key in bytes.
 */

static int size(CO(RSAkey, this))

{
	return RSA_size(this->state->key);
}


/**
 * External public method.
 *
 * This method implements printing of the RSA key.  Ouput is dependent
 * is dependent on the key type and includes information such as the
 * key exponent, modulus, etc.
 *
 * \param this	A pointer to the key which is to be printed.
 */

static void print(CO(RSAkey, this))

{
	STATE(S);

	BIO *output;


	if ( S->poisoned ) {
		fputs("Object is poisoned.\n", stderr);
		return;
	}
	if ( S->type == no_key ) {
		fputs("Object has no key.\n", stderr);
		return;
	}

        output=BIO_new(BIO_s_file());
	BIO_set_fp(output, stdout, BIO_NOCLOSE);
	if ( !RSA_print(output, S->key, 0) )
		fputs("Error printing key.\n", stderr);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a RSAkey object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(RSAkey, this))

{
	STATE(S);


	if ( S->key != NULL )
		RSA_free(S->key);
	S->root->whack(S->root, this, S);

	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a RSAkey object.
 *
 * \return	A pointer to the initialized RSAkey.  A null value
 *		indicates an error was encountered in object generation.
 */

extern RSAkey NAAAIM_RSAkey_Init(void)

{
	auto Origin root;

	auto RSAkey this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_RSAkey);
	retn.state_size   = sizeof(struct NAAAIM_RSAkey_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_RSAkey_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->key = RSA_new()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load_private_key = load_private_key;
	this->load_public_key  = load_public_key;
	this->encrypt	       = encrypt;
	this->decrypt	       = decrypt;
	this->size	       = size;
	this->print	       = print;
	this->whack 	       = whack;

	return this;
}
