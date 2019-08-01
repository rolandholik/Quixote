/** \file
 * This file contains the implementation of an object which is used to
 * implement RSA encryption using SHA256 based OAEP.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SGXrsa.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXrsa_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXrsa_OBJID)
#error Object identifier not defined.
#endif


/** SGXrsa private state information. */
struct NAAAIM_SGXrsa_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The key object. */
	EVP_PKEY *key;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXrsa_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXrsa_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXrsa_OBJID;


	S->poisoned = false;

	S->key = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements initialization of the OpenSSL state needed
 * to carry out RSA encryption and decryption.  An RSA key is provided
 * by the Intel provisioning servers in the form of a PEK structure
 * which carries the RSA key as modulus and exponent in big-endian
 * binary format.
 *
 *
 * \param this		A pointer to the object managing the RSA key.
 *
 * \param pek		A pointer to the structure containing the RSA
 *			key elements.
 *
 * \return	If an error is encountered initializing the key a
 *		false value is returned.  A true value indicates the
 *		object represents a valid key.
 */

static _Bool init(CO(SGXrsa, this), struct SGX_pek *pek)

{
	STATE(S);

	_Bool retn = false;

	BIGNUM *exponent = NULL,
	       *modulus	 = NULL;

	RSA *key = NULL;


	/* Verify object status. */
	if ( S->key != NULL )
		ERR(goto done);


	/* Create an RSA key from the key elements in the PEK structure. */
	if ( (exponent = BN_bin2bn(pek->e, sizeof(pek->e), NULL)) == NULL )
		ERR(goto done);

	if ( (modulus = BN_bin2bn(pek->n, sizeof(pek->n), NULL)) == NULL )
		ERR(goto done);

	if ( (key = RSA_new()) == NULL )
		ERR(goto done);
	if ( RSA_set0_key(key, modulus, exponent, NULL) == 0 )
		ERR(goto done);


	/* Initialize an envelope key and assign the RSA key to it. */
	if ( (S->key = EVP_PKEY_new()) == NULL )
		ERR(goto done);
	if ( EVP_PKEY_assign_RSA(S->key, key) != 1 )
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
 * This method implements AES128-GCM encryption of the supplied message
 * with inclusion of extra data into the verification tag.
 *
 * \param this		A pointer to the object managing the encryption
 *			data.
 *
 * \param key		The object containing the binary encryption key.
 *
 * \param iv		The object containing the initialization vector.
 *
 * \param output	The object into which the encrypted data is
 *			to be copied.
 *
 * \param extra		The object containing additional team to be
 *			included into the authentication tag.
 *
 * \return	If an error is encountered processing the encryption
 *		request a false value is returned.  A true value
 *		indicates the output object has valid encrypted data.
 */

static _Bool encrypt(CO(SGXrsa, this), CO(Buffer, payload), CO(Buffer, output))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	size_t size;

	const EVP_MD *md;

	EVP_PKEY_CTX *ctx = NULL;


	/* Validate object and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Initialize a context for the operation. */
	if ( (ctx = EVP_PKEY_CTX_new(S->key, NULL)) == NULL )
		ERR(goto done);
	ERR_load_crypto_strings();


	/*
	 * Initialize the context for an encryption operation and
	 * set the padding and hash type.
	 */
	if ( EVP_PKEY_encrypt_init(ctx) != 1 )
		ERR(goto done);
	if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 )
		ERR(goto done);

	if ( (md = EVP_get_digestbyname("sha256")) == NULL )
		ERR(goto done);
	if ( EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1 )
		ERR(goto done);


	/* Setup the output buffer. */
	if ( EVP_PKEY_encrypt(ctx, NULL, &size, payload->get(payload), \
			      payload->size(payload)) != 1 )
		ERR(goto done);

	while ( size ) {
		output->add(output, (void *) "\0", 1);
		--size;
	}

	if ( output->poisoned(output) )
		ERR(goto done);
	size = output->size(output);


	/* Do the encryption. */
	rc = EVP_PKEY_encrypt(ctx, output->get(output), &size, \
			      payload->get(payload),	       \
			      payload->size(payload));
	if ( rc != 1 )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	EVP_PKEY_CTX_free(ctx);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a diagnostic method for dumping out the
 * contents of the key.
 *
 * \param this	The object whose state is to be dumped.
 *
 * \return	No return value is defined.
 */

static void dump(CO(SGXrsa, this))

{
	STATE(S);

	BIO *out;


	/* Setup a structure to wrap the stdout filestream. */
	if ( (out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL) {
		fputs("BIO initialization error.\n", stderr);
		return;
	}


	/* Print the public key parameters. */
	EVP_PKEY_print_public(out, S->key, 0, NULL);


	BIO_free(out);
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for the SGXrsa object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXrsa, this))

{
	STATE(S);


	if ( S->key != NULL )
		EVP_PKEY_free(S->key);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXrsa object.
 *
 * \return	A pointer to the initialized SGXrsa.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXrsa NAAAIM_SGXrsa_Init(void)

{
	Origin root;

	SGXrsa this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXrsa);
	retn.state_size   = sizeof(struct NAAAIM_SGXrsa_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXrsa_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init = init;

	this->encrypt = encrypt;

	this->dump  = dump;
	this->whack = whack;

	return this;
}
