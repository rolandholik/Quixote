/** \file
 * This file implements methods for managing and manipulating
 * operations using assymetric RSA keys.  The RSAkey.h file provides
 * the API definitions and contracts for this object.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <mbedtls/rsa.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "HurdLib.h"
#include "SHA256.h"
#include "RSAkey.h"


/* State definition macro. */
#define STATE(var) CO(RSAkey_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_RSAkey_OBJID)
#error Object identifier not defined.
#endif


/** RSAkey private state information. */
struct HurdLib_RSAkey_State
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
	enum {
		no_key,
		public_key,
		private_key,
		hardware_key,
		generated,
		certificate
	} type;

	/* Type of padding. */
	RSAkey_padding padding;

	/* RSA key context. */
	mbedtls_pk_context key;

#if 0
	/* Certificate pointer for public key from certificate. */
	X509 *certificate;
#endif
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the HurdLib_RSAkey_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
v */

static void _init_state(CO(RSAkey_State, S))

{
	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_RSAkey_OBJID;

	S->poisoned = false;

	S->type	   = no_key;
	S->padding = RSAkey_pad_pkcs1;

	memset(&S->key, '\0', sizeof(S->key));
#if 0
	S->certificate = NULL;
#endif

	return;
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


#if 0
 done:
#endif
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


 #if 0
done:
#endif
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


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for extracting the modulus of
 * a public/private keypair.
 *
 * \param this		A pointer to the key object whose modulus is
 *			to be extracted.
 *
 * \param bufr		The object which the big-endian value of
 *			the modulus is to be loaded into.
 *
 * \return	If extraction of the modulus fails for any reason
 *		a false value is returned to the caller and the output
 *		object is considered to be in an indeterminate state.
 *		A true value indicates the output object can be
 *		considered to have a valid modulus value.
 */

static _Bool get_modulus(CO(RSAkey, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type == no_key )
		ERR(goto done);
	if ( (S->type != generated) && (S->type != private_key) && \
	     (S->type != public_key) )
		ERR(goto done);


 done:
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

	unsigned char *p;

	int rc;

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->type != no_key )
		ERR(goto done);
	if ( bufr->size(bufr) == 0 )
		ERR(goto done);


	/* Verify that the buffer is null-terminated. */
	p = bufr->get(bufr) + bufr->size(bufr) - 1;
	if ( *p != NULL ) {
		if ( !bufr->add(bufr, (void *) "\0", 1) )
			goto done;
	}


	/* Load the DER encoded key from the PEM envelope. */
	/* See pkparse.c */
	if ( mbedtls_pk_parse_public_key(&S->key, bufr->get(bufr), \
					 bufr->size(bufr)) != 0 )
		goto done;

	S->type = public_key;
	retn = true;


 done:
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


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type != no_key )
		ERR(goto done);


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading of an RSA public key from a
 * certificate.  The primary purpose of this method is to support
 * validation of a signature generated against the private key
 * of a certificate.  Since a certificate is defined as containing
 * a public key this method sets the object type to public_key.
 *
 * \param this		A pointer to the key object whose public key
 *			is to be loaded from the provided certificate.
 *
 * \param certificate	The object containing the certificate that
 *			will be used to supply the public key.  The
 *			incoming object is assumed to be PEM encoded.
 *
 * \return	If the load of the certificate based private key fails
 *		for any reason a false value is returned to the caller.
 *		A true value indicates the key has been loaded and the
 *		object is ready for use.
 */

static _Bool load_certificate(CO(RSAkey, this), CO(Buffer, bufr))


{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( S->type != no_key )
		ERR(goto done);


 done:
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

static _Bool load_private_key(CO(RSAkey, this), CO(char *, source), \
			      CO(char *, prompt))

{
	STATE(S);

	_Bool retn = false;



#if 0
 done:
#endif
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
	STATE(S);

	_Bool retn = false;


#if 0
 done:
#endif
	if ( !retn )
		S->poisoned = true;

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


	/* Sanity checks. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with private key. */
	switch ( S->type ) {
	case no_key:
	case generated:
	case certificate:
		ERR(goto done);
		break;
	case private_key:
		break;
	case public_key:
		break;
	case hardware_key:
		break;
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


	/* Sanity checks. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (payload == NULL) || payload->poisoned(payload) )
		ERR(goto done);


	/* Encrypt with the relevant key. */
	switch ( S->type ) {
	case no_key:
	case generated:
	case certificate:
		ERR(goto done);
		break;
	case private_key:
		break;
	case public_key:
		break;
	case hardware_key:
		break;
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
 * This method implements verification of a signature using a public
 * key.
 *
 * \param this		A pointer to the object describing the key that
 *			is to be used for verifying a signature.
 *
 * \param signature	The object containing the signature that is to
 *			be verified.
 *
 * \param data		The object containing the data whose signature
 *			is to be verified.
 *
 * \param status	A pointer to a boolean value used to indicate
 *			whether or not the provided signature was
 *			correct.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the verification process.  A false
 *			value implies an error was encountered and
 *			no assumptions can be made about the status
 *			value.  A true value indicates the process
 *			succeeded and the status variable will be
 *			updated to reflect the status of the
 *			signature verification.
 */

static _Bool verify(CO(RSAkey, this), CO(Buffer, signature), \
		    CO(Buffer, data), _Bool *status)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	Sha256 sha256 = NULL;



	/* Verify object status. */
	if ( signature == NULL )
		ERR(goto done);
	if ( signature->poisoned(signature) )
		ERR(goto done);
	if ( data == NULL )
		ERR(goto done);
	if ( data->poisoned(data) )
		ERR(goto done);
	if ( S->type != public_key )
		ERR(goto done);


	/* Hash the data to be verified. */
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	if ( !sha256->add(sha256, data) )
		ERR(goto done);
	if ( !sha256->compute(sha256) )
		ERR(goto done);


	/* Verify the signature. */
	rc = mbedtls_pk_verify(&S->key, MBEDTLS_MD_SHA256, \
			       sha256->get(sha256), 0,	   \
			       signature->get(signature),  \
			       signature->size(signature));

	if ( rc == MBEDTLS_ERR_RSA_VERIFY_FAILED ) {
		*status = false;
		retn = true;
		goto done;
	}

	if ( rc != 0 )
		goto done;

	*status = true;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = false;

	WHACK(sha256);

	return retn;
}


/**
 * External public method.
 *
 * This method implements signing of a block of data with the private
 * key assigned to an object.
 *
 * \param this		A pointer to the object describing the key that
 *			is to be used for generating the signature.
 *
 * \param data		The object containing the data whose signature
 *			is to be generated.
 *
 * \param signature	The object which the signature will be loaded
 *			into.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the signature generation.  A false
 *			value implies an error was encountered and
 *			no assumptions can be made about the data
 *			in the output object.  A true value indicates
 *			the signing succeeded and the output object
 *			contains a valid signature.
 */

static _Bool sign(CO(RSAkey, this), CO(Buffer, data), CO(Buffer, signature))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( data == NULL )
		ERR(goto done);
	if ( data->poisoned(data) )
		ERR(goto done);
	if ( signature == NULL )
		ERR(goto done);
	if ( signature->poisoned(signature) )
		ERR(goto done);
	if ( signature->size(signature) != 0 )
		ERR(goto done);
	if ( S->type != private_key )
		ERR(goto done);


 done:
	if ( !retn )
		S->poisoned = false;

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
	_Bool retn = false;


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
	return 2048;
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


	if ( S->poisoned ) {
		fputs("Object is poisoned.\n", stdout);
		return;
	}
	if ( S->type == no_key ) {
		fputs("Object has no key.\n", stdout);
		return;
	}

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


	mbedtls_pk_free(&S->key);
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
	retn.object_size  = sizeof(struct HurdLib_RSAkey);
	retn.state_size   = sizeof(struct HurdLib_RSAkey_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_RSAkey_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;


	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	mbedtls_pk_init(&this->state->key);

	/* Method initialization. */
	this->generate_key    = generate_key;

	this->get_public_key  = get_public_key;
	this->get_private_key = get_private_key;
	this->get_modulus     = get_modulus;

	this->load_public  = load_public;
	this->load_private = load_private;

	this->load_certificate = load_certificate;

	this->load_private_key = load_private_key;
	this->load_public_key  = load_public_key;

	this->encrypt = encrypt;
	this->decrypt = decrypt;

	this->verify = verify;
	this->sign   = sign;

	this->init_engine = init_engine;
	this->set_padding = set_padding;

	this->size  = size;
	this->print = print;
	this->whack = whack;

	return this;
}
