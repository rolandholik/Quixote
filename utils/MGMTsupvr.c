/** \file
 * This file contains the method implementations for an object which
 * manages the platform specific configuration.  This configuration is
 * implemented through a filesystem which is mounted in the following
 * location:
 *
 * /usr/local/etc/conf
 *
 * A default filesystem implementation is mounted on this directory
 * during system initialization.  The encrypted filesystem image is
 * in the /boot/platform file of the root filesystem.  The encryption
 * key for the filesystem image is sealed to the platform measurement
 * status and is held in the /boot/platform.seal file.
 *
 * The mgmt-supvr daemon is started as a component of the system
 * initialization process and is responsible for monitoring and
 * reacting to the insertion of a hardware key token.  The key token
 * is used to decrypt the management token which is located in the
 * following location:
 *
 * /etc/conf/platform.mtk
 *
 * This token contains a copy of the encryption key used to
 * encrypt/decrypt the filesystem image.
 *
 * After successful modification of the platform configuration the
 * block device is encrypted and used to replace the
 * /mnt/boot/platform file which is the runtime location for the
 * platform configuration.
 */


/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */

/*
 * The location of the file containing the platform configuration
 * encryption parameters.
 */
#define CONFIG "/etc/conf/config.enc"

/*
 * The magic number used to verify the DER encoding of the encryption
 * parameters.
 */
#define MAGIC 0xbeaf


/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <RSAkey.h>

#include "NAAAIM.h"
#include "MGMTsupvr.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_MGMTsupvr_OBJID)
#error Object identifier not defined.
#endif

/* Macro to extract state state information into the specified variable. */
#define STATE(var) CO(MGMTsupvr_State, var) = this->state


/** MGMTsupvr private state information. */
struct NAAAIM_MGMTsupvr_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Token. */
	Buffer token;

	/* Platform encryption initialization vector and key. */
	Buffer iv;
	Buffer key;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the symmetric key and initialization vector
 * which is used to encrypt/decrypt the platform configuration filesystem
 * image.
 */
typedef struct {
	ASN1_INTEGER *magic;
	ASN1_OCTET_STRING *iv;
	ASN1_OCTET_STRING *key;
} asn1_key;

ASN1_SEQUENCE(asn1_key) = {
	ASN1_SIMPLE(asn1_key, magic,	ASN1_INTEGER),
	ASN1_SIMPLE(asn1_key, iv,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_key, key,	ASN1_OCTET_STRING),

} ASN1_SEQUENCE_END(asn1_key)

IMPLEMENT_ASN1_FUNCTIONS(asn1_key)

#define ASN1_BUFFER_ENCODE(b, e, err) \
	if ( ASN1_OCTET_STRING_set(e, b->get(b), b->size(b)) != 1 ) \
		err

#define ASN1_BUFFER_DECODE(b, e, err) \
	if ( !b->add(b, ASN1_STRING_get0_data(e), ASN1_STRING_length(e)) ) \
 		err


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_MGMTsupvr_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(MGMTsupvr_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_MGMTsupvr_OBJID;

	S->poisoned = false;

	S->token = NULL;

	S->iv  = NULL;
	S->key = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This function is responsible for DER encoding of the initialization
 * vector and key.
 *
 * \parm this	The object whose encryption parameters are to be
 *		encoded.
 *
 * \param bufr	The object which will be loaded with the DER encoded
 *		representation of the encryption parameters.
 *
 * \return	A boolean value is used to indicate the success of
 *		the encoding operation.  A false value indicates the
 *		encoding failed while a true value indicates the
 *		supplied Buffer object contains a valid encoding of
 *		the initialization vector and key.
 */

static _Bool _encode_key(CO(MGMTsupvr, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int asn_size;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	asn1_key *enc = NULL;


	/* Arguement validation. */
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;


	/* Encode the request. */
	if ( (enc = asn1_key_new()) == NULL )
		goto done;

	if ( ASN1_INTEGER_set(enc->magic, MAGIC) != 1 )
		goto done;

	ASN1_BUFFER_ENCODE(S->iv, enc->iv, goto done);
	ASN1_BUFFER_ENCODE(S->key, enc->key, goto done);


	/* Load the ASN1 encoding into the supplied buffer. */
        asn_size = i2d_asn1_key(enc, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;

 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This function is responsible for decoding of the DER encoded
 * encryption initialization vector and key.
 *
 * \param token	The object containing the decrypted token which is to
 *		be decoded.
 *
 * \param iv	The object which will be loaded with the initialization
 *		vector used to encrypt/decrypt the management filesystem.
 *
 * \param key	The object which will be loaded with the encryption key
 *		used to encrypt/decrypt the management filesystem.
 *
 * \return	A boolean value is used to indicate the success of
 *		the decoding operation.  A false value indicates the
 *		decoding failed while a true value indicates the
 *		supplied Buffer objects contain valid data.
 */

static _Bool _decode_key(CO(Buffer, token), CO(Buffer, iv), CO(Buffer, key))

{
	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	asn1_key *enc = NULL;


	/* Arguement validation. */
	if ( (iv == NULL) || iv->poisoned(iv) )
		ERR(goto done);
	if ( (key == NULL) || key->poisoned(key) )
		ERR(goto done);

	p = token->get(token);
        if ( !d2i_asn1_key(&enc, &p, token->size(token)) )
                ERR(goto done);

	/* Verify the magic number of the encoding. */
	if ( ASN1_INTEGER_get(enc->magic) != MAGIC )
		ERR(goto done);

	/* Decode the initialization vector and key. */
	ASN1_BUFFER_DECODE(iv, enc->iv, goto done);
	ASN1_BUFFER_DECODE(key, enc->key, goto done);

	retn = true;

 done:
	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for loading the symmetric encryption key
 * which is used to encrypt the platform configuration filesystem image.
 *
 * \param this		The object which is to load the key.
 *
 * \param rsa		A pointer to a null-terminated buffer containing
 *			the name of the rsa key.  This may be a filename
 *			in the case of a PEM encoded RSA key or a slot
 *			identifier for a hardware token.
 *
 * \param engine	A pointer to an array of null-terminated character
 *			buffers containing the commands needed to initialize
 *			an OpenSSL hardware engine.  This value may be
 *			null which will cause the native RSA methods to
 *			be used.
 *
 * \param prompt	A pointer to a null-terminated buffer containing
 *			the prompt to be issued to request the user to
 *			enter the security password/pin to release the
 *			RSA key.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the key was successfully loaded.  A false
 *		value indicates failure while a true value indicates
 *		the key was successfully interrogated.
 */

static _Bool load_key(CO(MGMTsupvr, this), CO(char *, rsa), \
		      CO(char **, engine), CO(char *, prompt))

{
	STATE(S);

	_Bool retn = false;

	Buffer token = NULL;

	RSAkey rsakey = NULL;

	File token_file = NULL;


        if ( S->poisoned )
		ERR(goto done);

	INIT(HurdLib, Buffer, token, goto done);
	INIT(HurdLib, File, token_file, goto done);
	if ( !token_file->open_ro(token_file, CONFIG) )
		ERR(goto done);
	if ( !token_file->slurp(token_file, token) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, rsakey, goto done);
	if ( engine != NULL ) {
		if ( !rsakey->init_engine(rsakey, engine) )
			ERR(goto done);
	}
	if ( !rsakey->load_private_key(rsakey, rsa, prompt) )
		ERR(goto done);
	if ( !rsakey->decrypt(rsakey, token) )
		ERR(goto done);

	INIT(HurdLib, Buffer, S->iv, goto done);
	INIT(HurdLib, Buffer, S->key, goto done);
	if ( !_decode_key(token, S->iv, S->key) )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(token);
	WHACK(rsakey);
	WHACK(token_file);

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for writing the symmetric encryption key
 * which is used to encrypt the platform configuration filesystem image.
 *
 * \param this		The object which is to load the key.
 *
 * \param rsa		A pointer to a null-terminated buffer containing
 *			the name of the rsa key.  This may be a filename
 *			in the case of a PEM encoded RSA key or a slot
 *			identifier for a hardware token.
 *
 * \param engine	A pointer to an array of null-terminated character
 *			buffers containing the commands needed to initialize
 *			an OpenSSL hardware engine.  This value may be
 *			null which will cause the native RSA methods to
 *			be used.
 *
 * \param prompt	A pointer to a null-terminated buffer containing
 *			the prompt to be issued to request the user to
 *			enter the security password/pin to release the
 *			RSA key.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the key was successfully written.  A false
 *		value indicates failure while a true value indicates
 *		the key was successfully interrogated.
 */

static _Bool write_key(CO(MGMTsupvr, this), CO(char *, rsa), \
		       CO(char **, engine), CO(char *, prompt))

{
	STATE(S);

	_Bool retn = false;

	Buffer token = NULL;

	RSAkey rsakey = NULL;

	File token_file = NULL;


        /* Status checks. */
        if ( S->poisoned )
		ERR(goto done);

	/* Encode IV and key. */
	INIT(HurdLib, Buffer, token, goto done);
	if ( !_encode_key(this, token) )
		ERR(goto done);

	/* Encrypt the encoded token. */
	INIT(NAAAIM, RSAkey, rsakey, goto done);
	if ( engine != NULL ) {
		if ( !rsakey->init_engine(rsakey, engine) )
			ERR(goto done);
	}
	if ( !rsakey->load_public_key(rsakey, rsa, NULL) )
		ERR(goto done);
	if ( !rsakey->encrypt(rsakey, token) )
		ERR(goto done);

	/* Write the token to the output file. */
	INIT(HurdLib, File, token_file, goto done);
	if ( !token_file->open_rw(token_file, CONFIG) )
		ERR(goto done);
	if ( !token_file->write_Buffer(token_file, token) )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(token);
	WHACK(rsakey);
	WHACK(token_file);

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for setting the initialization vector and
 * encryption key which will be used for the token.  This method is
 * primarily used to set the object up for writing a new token.
 *
 * \param this		The object whose initialization vector and key
 *			are to be set.
 *
 * \param iv		The object containing the initialization vector.
 *
 * \param key		The object containing the encryption key.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the initialization vector and key were successfully set.
 *		A false value indicates failure while a true value
 *		indicates the key was successfully interrogated.
 */

static _Bool set_iv_key(CO(MGMTsupvr, this), CO(Buffer, iv), CO(Buffer, key))

{
	STATE(S);

	_Bool retn = false;


        /* Status checks. */
        if ( S->poisoned )
		ERR(goto done);
	if ( (iv == NULL ) || iv->poisoned(iv) )
		ERR(goto done);
        if ( (key == NULL) || key->poisoned(key) )
                ERR(goto done);

	/* Transfer the incoming Buffers to the internal objects. */
	INIT(HurdLib, Buffer, S->iv, goto done);
	INIT(HurdLib, Buffer, S->key, goto done);

	if ( !S->iv->add_Buffer(S->iv, iv) )
		ERR(goto done);
	if ( !S->key->add_Buffer(S->key, key) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for dumping the current object status.

 * \param this		The object whose status is to be dumped.

 *
 * \return	No return value is defined.
 */

static void dump(CO(MGMTsupvr, this))

{
	STATE(S);


	fprintf(stdout, "Status: %s\n", S->poisoned ? "POISONED" : "OK");

	fputs("IV : ", stdout);
	S->iv->print(S->iv);
	fputs("Key: ", stdout);
	S->key->print(S->key);


	return;
}


/**
 * External public method.
 *
 * This function returns the status of the object.
 *
 * \param this	A point to the object whose status is being requested.
 */
static _Bool poisoned(CO(MGMTsupvr, this))

{
	STATE(S);

	return S->poisoned;
}
	

/**
 * External public method.
 *
 * This method implements a destructor for a MGMTsupvr object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(MGMTsupvr, this))

{
	STATE(S);


	WHACK(S->token);

	WHACK(S->iv);
	WHACK(S->key);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a MGMTsupvr object.
 *
 * \return	A pointer to the initialized MGMTsupvr.  A null value
 *		indicates an error was encountered in object generation.
 */

extern MGMTsupvr NAAAIM_MGMTsupvr_Init(void)

{
	Origin root;

	MGMTsupvr this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_MGMTsupvr);
	retn.state_size   = sizeof(struct NAAAIM_MGMTsupvr_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_MGMTsupvr_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->load_key	= load_key;
	this->write_key	= write_key;

	this->set_iv_key = set_iv_key;

	this->dump = dump;

	this->poisoned = poisoned;
	this->whack    = whack;

	return this;
}
