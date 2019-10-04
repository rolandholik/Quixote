/** \file
 * This file implements methods for managing and manipulating
 * operations using assymetric RSA keys.  The RSAkey.h file provides
 * the API definitions and contracts for this object.
 *
 * This implementation is currently tuned to the needs of manipulating
 * RSA keys by an enclave.  As such the interface for loading public
 * and private keys use Buffer objects rather then the name of
 * a file.
 *
 * The implemenation assumes that the enclave will be responsible for
 * decrypting the PEM object before passing it into the key loading
 * method.
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
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

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
	enum {no_key, public_key, private_key, hardware_key, generated} type;

	/* Type of padding. */
	RSAkey_padding padding;

	/* Hardware engine definition. */
	ENGINE *engine;

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

	S->type	   = no_key;
	S->padding = RSAkey_pad_pkcs1;
	S->engine  = NULL;
	S->key	   = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This function is responsible for translating the enumerated padding
 * type with the internal value used by the OpenSSL library to specify
 * the padding type.
 *
 * \param this	The object state whose padding type is to be
 *		returned.
 *
 * \return	The numerical coding value is be used is returned.
 */

static int _padding(CO(RSAkey_State, S))

{
	int padding;


	switch ( S->padding ) {
		case RSAkey_pad_none:
			padding = RSA_NO_PADDING;
			break;
		case RSAkey_pad_pkcs1:
			padding = RSA_PKCS1_PADDING;
			break;
		case RSAkey_pad_oaep:
			padding = RSA_PKCS1_OAEP_PADDING;
			break;
	}

	return padding;
}


/**
 * External public method.
 *
 * This method implements the generation of an RSA key with the
 * specified parameters.
 *
 * \param this		A pointer to the key object for which a key
 *			is being generated.
 *
 * \param size		The size of the key in bits.
 *
 *
 * \return	If the generation of the RSA key faileds for any reason
 *		a falsed value is returned to the caller.  A true
 *		value indicates the key has been generated and is
 *		available for use by the object.
 */

static _Bool generate_key(CO(RSAkey, this), int size)


{
	STATE(S);

	_Bool retn = false;

	BIGNUM *exp = NULL;


	/*
	 * Initialize a big number structure for the exponent and
	 * set it to the standard exponent value of F4 or 65537.
	 */
	if ( (exp = BN_new()) == NULL )
		ERR(goto done);
	if ( BN_set_word(exp, RSA_F4) == 0 )
		ERR(goto done);


	/* Initialize and generate the key. */
	if ( (S->key = RSA_new()) == NULL )
		ERR(goto done);

	if ( RSA_generate_key_ex(S->key, size, exp, NULL) == 0 )
		ERR(goto done);

	S->type = generated;
	retn = true;


 done:
	if ( exp != NULL )
		BN_free(exp);
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for extracting a public key
 * from the object.
 *
 * \param this		A pointer to the key object for which a key
 *			is to be extracted
 *
 * \param bufr		The object which the key is to be placed
 *			into.
 *
 * \return	If the extraction of a key fails for any reason
 *		a false value is returned to the caller.  A true
 *		value indicates the target object has a valid key
 *		in it.
 */

static _Bool get_public_key(CO(RSAkey, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	char *mp = NULL;

	size_t ms;

	BIO *mb = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type == no_key )
		ERR(goto done);
	if ( (S->type != generated) && (S->type != public_key) )
		ERR(goto done);


	/* Write the key to a memory based BIO.*/
	if ( (mb = BIO_new(BIO_s_mem())) == NULL )
		ERR(goto done);
	if ( PEM_write_bio_RSA_PUBKEY(mb, S->key) == 0 )
		ERR(goto done);

	ms = BIO_get_mem_data(mb, &mp);
	if ( !bufr->add(bufr, (unsigned char *) mp, ms) )
		ERR(goto done);
	retn = true;


 done:
	if ( mb != NULL )
		BIO_free(mb);
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for extracting a private key
 * from the object.
 *
 * \param this		A pointer to the key object for which a key
 *			is to be extracted
 *
 * \param bufr		The object which the key is to be placed
 *			into.
 *
 * \return	If the extraction of a key fails for any reason
 *		a false value is returned to the caller.  A true
 *		value indicates the target object has a valid key
 *		in it.
 */

static _Bool get_private_key(CO(RSAkey, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	char *mp = NULL;

	size_t ms;

	BIO *mb = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type == no_key )
		ERR(goto done);
	if ( (S->type != generated) && (S->type != private_key) )
		ERR(goto done);


	/* Write the key to a memory based BIO.*/
	if ( (mb = BIO_new(BIO_s_mem())) == NULL )
		ERR(goto done);
	if ( PEM_write_bio_RSAPrivateKey(mb, S->key, NULL, NULL, 0, NULL, \
					 NULL) == 0 )
		ERR(goto done);

	ms = BIO_get_mem_data(mb, &mp);
	if ( !bufr->add(bufr, (unsigned char *) mp, ms) )
		ERR(goto done);
	retn = true;


 done:
	if ( mb != NULL )
		BIO_free(mb);
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA private key and sets
 * the object type to be a private key object.
 *
 * \param this		A pointer to the key object whose private key
 *			is to be loaded.
 *
 * \param source	The identifier for the source of the private
 *			key.  In the case of a file this will be the
 *			name of the file containing the PEM encoded
 *			key.  In the case of a hardware token this
 *			will be the slot identifier of the token.
 *
 * \param prompt	A pointer to a null-terminated character
 *			buffer containing the prompt to be used
 *			to request the pincode or password from
 *			the user.  A NULL value will cause the
 *			default prompt to be used.
 *
 * \return	If the load of the private key failed for any reason
 *		a falsed value is returned to the caller.  A true
 *		value indicates the key has been loaded and the
 *		object is ready for use.
 */

static _Bool load_private(CO(RSAkey, this), CO(Buffer, bufr))


{
	STATE(S);

	_Bool retn = false;

	BIO *key = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type != no_key )
		ERR(goto done);

	/* Load key from a memory based BIO based on the Buffer object. */
	key = BIO_new_mem_buf(bufr->get(bufr), bufr->size(bufr));

	if ( PEM_read_bio_RSAPrivateKey(key, &S->key, NULL, NULL) == NULL )
		ERR(goto done);

	retn	= true;
	S->type = private_key;


 done:
	if ( key != NULL )
		BIO_free(key);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA public key and sets
 * the object type to be a public key object.
 *
 * \param this		A pointer to the key object whose public key
 *			is to be loaded.
 *
 * \param key		The object containing the public key.
 *
 * \return	If the load of the public key failed for any reason
 *		a falsed value is returned to the caller.  A true
 *		value indicates the key has been loaded and the
 *		object is ready for use.
 */

static _Bool load_public(CO(RSAkey, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	BIO *key = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type != no_key )
		ERR(goto done);

	/* Load key from a memory based BIO based on the Buffer object. */
	key = BIO_new_mem_buf(bufr->get(bufr), bufr->size(bufr));

	if ( PEM_read_bio_RSA_PUBKEY(key, &S->key, NULL, NULL) == NULL )
		ERR(goto done);

	retn	= true;
	S->type = public_key;


 done:
	if ( key != NULL )
		BIO_free(key);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA private key from a file
 * source and sets the object type to be a private key object.  This
 * function is currently not implemented in enclave context.
 *
 * \param this		A pointer to the key object whose private key
 *			is to be loaded.
 *
 * \param source	The identifier for the source of the private
 *			key.  In the case of a file this will be the
 *			name of the file containing the PEM encoded
 *			key.  In the case of a hardware token this
 *			will be the slot identifier of the token.
 *
 * \param prompt	A pointer to a null-terminated character
 *			buffer containing the prompt to be used
 *			to request the pincode or password from
 *			the user.  A NULL value will cause the
 *			default prompt to be used.
 *
 * \return	If the load of the private key failed for any reason
 *		a falsed value is returned to the caller.  A true
 *		value indicates the key has been loaded and the
 *		object is ready for use.
 */

static _Bool load_private_key(CO(RSAkey, this), CO(char *, source), \
			      CO(char *, prompt))

{
	ERR(return false);
}


/**
 * External public method.
 *
 * This method implements loading of an RSA public key from a file
 * source and sets the object type to be a public key object.  This
 * method is currently not implemented in enclave context.
 *
 * \param this		A pointer to the key object whose public key
 *			is to be loaded.
 *
 * \param source	The identifier for the source of the public
 *			key.  In the case of a file this will be the
 *			name of the file containing the PEM encoded
 *			key.  In the case of a hardware token this
 *			will be the slot identifier of the token.
 *
 * \param prompt	A pointer to a null-terminated character
 *			buffer containing the prompt to be used
 *			to request the pincode or password from
 *			the user.  A NULL value will cause the
 *			default prompt to be used.
 *
 * \return	If the load of the public key failed for any reason
 *		a falsed value is returned to the caller.  A true
 *		value indicates the key has been loaded and the
 *		object is ready for use.
 */

static _Bool load_public_key(CO(RSAkey, this), CO(char *, file), \
			     CO(char *, prompt))

{
	ERR(return false);
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
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with private key. */
	switch ( S->type ) {
	case no_key:
	case generated:
		ERR(goto done);
		break;
	case private_key:
		enc_status = RSA_private_encrypt(payload->size(payload), \
						 payload->get(payload),	 \
						 output, S->key, _padding(S));
		break;
	case public_key:
		enc_status = RSA_public_encrypt(payload->size(payload), \
						payload->get(payload),	\
						output, S->key, _padding(S));
		break;
	case hardware_key:
		enc_status = RSA_public_encrypt(payload->size(payload),	 \
						payload->get(payload),	 \
						output, S->key, _padding(S));
		break;
	}

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
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with the relevant key. */
	switch ( S->type ) {
	case no_key:
	case generated:
		ERR(goto done);
		break;
	case private_key:
		status = RSA_private_decrypt(payload->size(payload),	    \
					     payload->get(payload), output, \
					     S->key, _padding(S));
		break;
	case public_key:
		status = RSA_public_decrypt(payload->size(payload),	   \
					    payload->get(payload), output, \
					    S->key, _padding(S));
		break;
	case hardware_key:
		status = RSA_private_decrypt(payload->size(payload),	    \
					     payload->get(payload), output, \
					     S->key, _padding(S));
		break;
	}

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
 * This method implements initialization of an alternate engine for
 * executing the RSA key operations.  The engine is specifically
 * attached to the current RSA key instance.
 *
 * \param this	The key which is requesting initialization of the
 *		engine.
 *
 * \param cmds	A pointer to an array of strings which contain the
 *		commands needed to initialize the engine.  The end
 *		of the array is indicated by two consecutive NULL
 *		pointers.
 *
 * \return	A boolean value is returned to indicate the status of
 *		the engine initialization request.  A false value
 *		indicates the operation was unsuccessful while a true
 *		value indicates the engine has been initialized and
 *		attached to the key.
 */

static _Bool init_engine(CO(RSAkey, this), CO(char **, cmds))

{
	STATE(S);

	unsigned int lp = 0;

	_Bool retn = false;


	if ( S->poisoned )
		ERR(goto done);

	/* Initialize a functional reference to the dynamic engine. */
	ENGINE_load_dynamic();
	if ( (S->engine = ENGINE_by_id("dynamic")) == NULL )
		ERR(goto done);

	/* Issue the commands needed to initialize the engine. */
	if ( cmds == NULL ) {
		retn = true;
		goto done;
	}

	while ( cmds[lp] != NULL ) {
		if ( !ENGINE_ctrl_cmd_string(S->engine, cmds[lp], \
					     cmds[lp+1], 0) )
			ERR(goto done);
		lp += 2;
	}

	/* Install engine support for this instance of the key. */
	RSA_free(S->key);
	if ( (S->key = RSA_new_method(S->engine)) == NULL )
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
 * This method implements setting the type of padding to be used for
 * the RSA key object.
 *
 * \param this	The key whose padding type is to be set.
 *
 * \param type	The type of padding which is constrained to the
 *		enumerated types defined in the header file for this
 *		boject.
 *
 * \return	A boolean value is returned to indicate the status of
 *		configuring the padding type.  A false value indicates
 *		an invalid padding type was specified.
 */

static _Bool set_padding(CO(RSAkey, this), const int type)

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		return retn;

	switch ( type ) {
		case RSAkey_pad_none:
		case RSAkey_pad_pkcs1:
		case RSAkey_pad_oaep:
			S->padding = type;
			retn = true;
			break;
	}

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

	char *mp = NULL;

	size_t ms;

	BIO *output;


	if ( S->poisoned ) {
		fputs("Object is poisoned.\n", stdout);
		return;
	}
	if ( S->type == no_key ) {
		fputs("Object has no key.\n", stdout);
		return;
	}

	if ( (output = BIO_new(BIO_s_mem())) == NULL )
		ERR(goto done);

	if ( !RSA_print(output, S->key, 0) )
		ERR(goto done);

	ms = BIO_get_mem_data(output, &mp);
	if ( ms == 0 )
		ERR(goto done);

	fprintf(stdout, "%s", mp);


 done:
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


	if ( S->engine != NULL )
		ENGINE_free(S->engine);
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
	this->generate_key    = generate_key;
	this->get_public_key  = get_public_key;
	this->get_private_key = get_private_key;

	this->load_public  = load_public;
	this->load_private = load_private;

	this->load_private_key = load_private_key;
	this->load_public_key  = load_public_key;

	this->encrypt = encrypt;
	this->decrypt = decrypt;

	this->init_engine = init_engine;
	this->set_padding = set_padding;

	this->size  = size;
	this->print = print;
	this->whack = whack;

	return this;
}
