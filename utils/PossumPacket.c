/** \file
 * This file implements an object which creates and decodes the exchange
 * packets which implement the POSSUM protocol.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
/* Object initialization macros. */
#define CCALL(lib,obj,init) lib##_##obj##_##init
#define INIT(lib, obj, var, action) \
	if ( (var = CCALL(lib,obj,Init)()) == NULL ) action

#define BIRTHDATE 1396167420


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "IDtoken.h"
#include "AES256_cbc.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "OTEDKS.h"

#include "PossumPacket.h"

#define STATE(var) CO(PossumPacket_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PossumPacket_OBJID)
#error Object identifier not defined.
#endif


/** PossumPacket private state information. */
struct NAAAIM_PossumPacket_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/**
	 * The replay nonce which will be used as the key to generate
	 * the shared secret from the diffie-hellman based key.
	 */
	RandomBuffer nonce;

	/**
	 * The Buffer object which holds the concantenation of the identity
	 * NONE and the SCRYPT hash using that salt.
	 */
	Buffer identity;

	/**
	 * Requested authentication time.
	 */
	time_t auth_time;

	/* The Buffer object holding the identity authenticator. */
	Buffer authenticator;

};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the authenticator which will be transmitted over
 * the wire.
 */
typedef struct {
	ASN1_OCTET_STRING *identity;
	ASN1_INTEGER *auth_time;
	ASN1_OCTET_STRING *authenticator;
} packet1_payload;

ASN1_SEQUENCE(packet1_payload) = {
	ASN1_SIMPLE(packet1_payload, identity,  ASN1_OCTET_STRING),
	ASN1_SIMPLE(packet1_payload, auth_time, ASN1_INTEGER),
	ASN1_SIMPLE(packet1_payload, authenticator, \
		    ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(packet1_payload)

IMPLEMENT_ASN1_FUNCTIONS(packet1_payload)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_PossumPacket_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(PossumPacket_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PossumPacket_OBJID;

	S->poisoned = false;
	S->nonce	 = NULL;
	S->identity	 = NULL;
	S->authenticator = NULL;

	return;
}


/**
 * Internal private function.
 *
 * This function implements the creation of the authenticator object.
 *
 * This object contains the following elements:
 *
 *	Diffie-Hellman private key.
 *	Replay NONCE.
 *	Hardware quote.
 *
 * And is encrypted with an OTEDKS key based on the identity provided
 * to the object and the authentication time specified for the
 * object.
 *
 * \param state		The state of the object for which the
 *			authenticator is being built.
 *
 * \param idkey		A Buffer object containing the identity key.
 *
 * \param idhash	A Buffer object containing the hash of the
 *			identity.
 *
 * \return		If an error is encountered a false value is
 *			returned, a true value indicates the authenticator
 *			was constructed.
 */

static _Bool create_authenticator(CO(PossumPacket_State, S), \
				  CO(Buffer, idkey), CO(Buffer, idhash))

{
	_Bool retn = false;

	unsigned int lp;

	Buffer key,
	       iv,
	       auth;

	OTEDKS otedks;

	AES256_cbc cipher;


	/* Generate and load Diffie Hellman key. */
	INIT(HurdLib, Buffer, auth, goto done);
	for (lp= 0; lp < 32 / 4; ++ lp)
		auth->add_hexstring(auth, "feadbeef");

	/* Add the replay NONCE. */
	INIT(NAAAIM, RandomBuffer, S->nonce, goto done);
	if ( !S->nonce->generate(S->nonce, 32) )
		goto done;
	auth->add_Buffer(auth, S->nonce->get_Buffer(S->nonce));

	/* Add the hardware quote. */
	if ( !auth->add_hexstring(auth, "0000fead0000beaf") )
		goto done;

	/* Generate the OTEDKS key. */
	if ( (otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto done;
	S->auth_time = time(NULL);
	if ( !otedks->compute(otedks, S->auth_time, idkey, idhash) )
		goto done;
	key = otedks->get_key(otedks);
	iv  = otedks->get_iv(otedks);

	/* Encrypt the authenticator. */
	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		goto done;
	if ( cipher->encrypt(cipher, auth) == NULL )
		goto done;

	if ( S->authenticator->add_Buffer(S->authenticator, \
					  cipher->get_Buffer(cipher)) )
		retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	WHACK(auth);
	WHACK(otedks);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of the first POSSUM exchange
 * packet.  This packet is sent by the client to identify and attest
 * the state of the client.
 *
 * \param this	The object whose packet 1 state is to be created.
 *
 * \param token	The identity token to be used to create the state.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of creating the packet.  A false value
 *		indicates creation failed while a true indicates it
 *		was successful.
 */

static _Bool create_packet1(CO(PossumPacket, this), CO(IDtoken, token))

{

	STATE(S);

	_Bool retn = false;

	Buffer b,
	       key;

	RandomBuffer nonce = NULL;

	SHA256 hash = NULL;

	SHA256_hmac hmac = NULL;


	if ( S->poisoned )
		goto done;

	/* Load the identification challenge nonce. */
	INIT(NAAAIM, RandomBuffer, nonce, goto done);
	nonce->generate(nonce, 256 / 8);
	S->identity->add_Buffer(S->identity, nonce->get_Buffer(nonce));


	/* Hash the organization key and identity with the nonce. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(S->identity)) == NULL )
		goto done;

	if ( (b = token->get_element(token, IDtoken_orgkey)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, b);

	if ( (b = token->get_element(token, IDtoken_orgid)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, b);

	hmac->compute(hmac);
	if ( !S->identity->add_Buffer(S->identity, hmac->get_Buffer(hmac)) )
		goto done;


	/* Build the authenticator. */
	INIT(NAAAIM, SHA256, hash, goto done);
	if ( (b = token->get_element(token, IDtoken_id)) == NULL )
		goto done;
	hash->add(hash, b);
	if ( !hash->compute(hash) )
		goto done;

	if ( (key = token->get_element(token, IDtoken_key)) == NULL )
		goto done;

	if ( !create_authenticator(S, key, hash->get_Buffer(hash)) )
		goto done;

	retn = true;


 done:
	WHACK(nonce)
	WHACK(hash);
	WHACK(hmac);

	if ( retn == false )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieval of the authenticator from a decoded
 * POSSUM packet.
 *
 * \param this	The packets whose authenticator is to be retrived.
 *
 * \param token	The identity token which contains the identity
 *		representation of the host which will be used to
 *		decode the packet.  In this application the token is
 *		assumed to hold the SHA256 based hash of the
 *		actually device identity.
 *
 * \param bufr	The buffer object which will hold the authentication
 *		identity elements.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future activity.
 */

static _Bool get_authenticator(CO(PossumPacket, this), CO(IDtoken, token), \
			       CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	Buffer idkey,
	       idhash,
	       iv,
	       key;

	OTEDKS otedks = NULL;

	AES256_cbc cipher = NULL;


	/* Condition checks. */
	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;
	if ( S->authenticator->size(S->authenticator) == 0 )
		goto done;

	/* Extract the identity key and hash of the identity. */
	idkey  = token->get_element(token, IDtoken_key);
	idhash = token->get_element(token, IDtoken_id);
	if ( (idkey == NULL) || (idhash == NULL) )
		goto done;

	/* Compute the key from the host identity. */
	if ( (otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto done;
	if ( !otedks->compute(otedks, S->auth_time, idkey, idhash) )
		goto done;
	iv  = otedks->get_iv(otedks);
	key = otedks->get_key(otedks);

	/*
	 * Decrypt the authenticator and load it back into the supplied
	 * buffer.
	 */
	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		goto done;
	if ( !cipher->decrypt(cipher, S->authenticator) )
		goto done;
	
	if ( bufr->add_Buffer(bufr, cipher->get_Buffer(cipher)) )
		retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;
	WHACK(otedks);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements adding the identity elements which are to be
 * authenticated.
 *
 * \param this	The authenticator to which an element is to be added.
 *
 * \param bufr	The element which is to be added.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future use.
 */

static _Bool add_element(CO(PossumPacket, this), CO(Buffer, element))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned || element->poisoned(element) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieving the identity elements have been
 * authenticated.
 *
 * \param this	The authenticator to from which the elements are to
 *		be retroeved. an element is to be added.
 *
 * \param bufr	The Buffer object which is to be loaded with the
 *		authenicated identity elements.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future use.
 */

static _Bool get_element(CO(PossumPacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is responsible for generating a single use key for
 * encrypting the identity elements which are to be authenticated by
 * the target identifying organization.  The symmetric key is itself
 * encrypted in the authenticator's private RSA key.
 *
 * \param this	The PossumPacket object whose elements are to be
 *		encrypted.
 *
 * \param rsa	A pointer to a null-terminated buffer containing the
 *		RSA private key to be used for encrypting the
 *		symmetric key.
 *
 * \return	A boolean value is used to return success or failure of
 *		key generation.  A true value is used to indicate
 *		success.
 */

static _Bool encrypt(CO(PossumPacket, this))

{
#if 0
	STATE(S);

	_Bool retn = false;

	Buffer encrypted,
		    iv = NULL;

	RandomBuffer randbufr = NULL;

	AES256_cbc aes256 = NULL;


	/* Sanity checks. */
	if ( S->poisoned )
		goto done;


	/* Generate the random key and initialization vector. */
	if ( (randbufr = NAAAIM_RandomBuffer_Init()) == NULL )
		goto done;
	randbufr->generate(randbufr, (256 / 2) / 8);

	if ( (iv = HurdLib_Buffer_Init()) == NULL )
		goto done;
	iv->add_Buffer(iv, randbufr->get_Buffer(randbufr));

	randbufr->generate(randbufr, 256 / 8);
	S->key->add_Buffer(S->key, randbufr->get_Buffer(randbufr));


	/* Encrypt the elements. */
	if ( (aes256 = NAAAIM_AES256_cbc_Init_encrypt(S->key, iv)) == NULL )
		goto done;
	if ( (encrypted = aes256->encrypt(aes256, S->elements)) == NULL )
		goto done;

	S->elements->reset(S->elements);
	if ( !S->elements->add_Buffer(S->elements, encrypted) )
		goto done;


	/* Encrypt the random key. */
	S->key->add_Buffer(S->key, iv);
		
	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	if ( iv != NULL )
		iv->whack(iv);
	if ( randbufr != NULL )
		randbufr->whack(randbufr);
	if ( aes256 != NULL )
		aes256->whack(aes256);

	return retn;
#endif
	return 1;
}


/**
 * External public method.
 *
 * This method is responsible for decrypting a previously encrypted
 * authenticator payload.  The symmetric key and initialization vector
 * are obtained from the RSA encrypted key package and used to
 * decrypt the target identity elements.
 *
 * \param this	The PossumPacket object whose elements are to be
 *		decrypted..
 *
 * \param rsa	A pointer to a null-terminated buffer containing the
 *		RSA public key to be used for decrypting the symmetric
 *		key and initialization vector.
 *
 * \return	A boolean value is used to return success or failure of
 *		key generation.  A true value is used to indicate
 *		success.
 */

static _Bool decrypt(CO(PossumPacket, this))

{
#if 0
	STATE(S);

	_Bool retn = false;

	Buffer decrypted,
		    iv = NULL;

	AES256_cbc aes256 = NULL;


	/* Sanity checks. */
	if ( S->poisoned )
		goto done;


	/* Decrypt the initialization vector and symmetric key. */
	if ( (iv = HurdLib_Buffer_Init()) == NULL )
		goto done;

	iv->add(iv, S->key->get(S->key) + (256 / 8), 128 / 8);
	S->key->shrink(S->key, 128 / 8);


	/* Encrypt the elements. */
	if ( (aes256 = NAAAIM_AES256_cbc_Init_decrypt(S->key, iv)) == NULL )
		goto done;
	if ( (decrypted = aes256->decrypt(aes256, S->elements)) == NULL )
		goto done;

	S->elements->reset(S->elements);
	if ( !S->elements->add_Buffer(S->elements, decrypted) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	if ( iv != NULL )
		iv->whack(iv);
	if ( aes256 != NULL )
		aes256->whack(aes256);

	return retn;
#endif
	return 1;
}


/**
 * External public method.
 *
 * This method implements the encoding of the contents of the
 * PossumPacket object into an ASN1 structure.  The binary encoding
 * is loaded into a Buffer object provided by the caller.
 *
 * \param this	The packet1 payload whose elements are to be
 *		encoded for transmission.
 *
 * \param bufr	The Buffer object which the payload is to be encoded
 *		into.
 *
 * \return	A boolean value is used to return success or failure of
 *		the encoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool encode_packet1(CO(PossumPacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	int asn_size;

	packet1_payload *packet1 = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	if ( (packet1 = packet1_payload_new()) == NULL )
		goto done;

        if ( ASN1_OCTET_STRING_set(packet1->identity,			\
				   S->identity->get(S->identity),	\
                                   S->identity->size(S->identity)) != 1 )
                goto done;

	if ( ASN1_INTEGER_set(packet1->auth_time, S->auth_time) != 1 )
		goto done;

        if ( ASN1_OCTET_STRING_set(packet1->authenticator,		     \
				   S->authenticator->get(S->authenticator),  \
                                   S->authenticator->size(S->authenticator)) \
	     != 1 )
                goto done;

        asn_size = i2d_packet1_payload(packet1, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( retn == false )
		S->poisoned = true;
	if ( packet1 != NULL )
		packet1_payload_free(packet1);

	return retn;
}


/**
 * External public method.
 *
 * This method implements decoding the contents of a DER encoded ASN1
 * structure into an PossumPacket object.  The binary encoding is
 * provided by a Buffer supplied by the caller.
 *
 * \param this	The PossumPacket object which is to receive the
 *		encoded object.
 *
 * \param bufr	A buffer object containing the encoded structure to
 *		loaded.
 *
 * \return	A boolean value is used to return success or failure of
 *		the decoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool decode_packet1(CO(PossumPacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	int asn_size;

	packet1_payload *packet1 = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_packet1_payload(&packet1, &p, asn_size) )
                goto done;	

	S->identity->add(S->identity, ASN1_STRING_data(packet1->identity), \
		       ASN1_STRING_length(packet1->identity));

	S->auth_time = ASN1_INTEGER_get(packet1->auth_time);

	S->authenticator->add(S->authenticator, \
			      ASN1_STRING_data(packet1->authenticator), \
			      ASN1_STRING_length(packet1->authenticator));

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( packet1 != NULL )
		packet1_payload_free(packet1);
	return retn;
}


/**
 * External public method.
 *
 * This method prints the contents of an PossumPacket object.  The
 * status, ie, whether or not the object has been poisoned is also
 * indicated.
 *
 * \param this	A pointer to the object which is to be printed..
 */

static void print(CO(PossumPacket, this))

{
	STATE(S);


	if ( S->poisoned )
		fputs("* POISONED *\n", stdout);

	fputs("identity:\n", stdout);
	S->identity->print(S->identity);

	fprintf(stdout, "time: %d\n", (int) S->auth_time);

	fputs("authenticator:\n", stdout);
	S->authenticator->print(S->authenticator);

	return;
}


/**
 * External public method.
 *
 * This method implements resetting of an authenticator object.  It
 * allows an authenicator to be used multiple times.
 *
 * \param this	The object to be reset.
 */

static void reset(CO(PossumPacket, this))

{
	STATE(S);


	if ( S->poisoned )
		return;

	S->identity->reset(S->identity);
	S->auth_time = 0;
	S->authenticator->reset(S->authenticator);

	return;
}
     

/**
 * External public method.
 *
 * This method implements a destructor for a PossumPacket object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(PossumPacket, this))

{
	STATE(S);


	/* Release Buffer elements. */
	WHACK(S->nonce);
	WHACK(S->identity);
	WHACK(S->authenticator);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a PossumPacket object.
 *
 * \return	A pointer to the initialized PossumPacket.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PossumPacket NAAAIM_PossumPacket_Init(void)

{
	Origin root;

	PossumPacket this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PossumPacket);
	retn.state_size   = sizeof(struct NAAAIM_PossumPacket_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PossumPacket_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->identity, goto err);
	INIT(HurdLib, Buffer, this->state->authenticator, goto err);

	/* Method initialization. */
	this->create_packet1 = create_packet1;
	this->get_authenticator = get_authenticator;
	this->add_element  = add_element;
	this->get_element  = get_element;
	this->encrypt	   = encrypt;
	this->decrypt	   = decrypt;
	this->encode_packet1	   = encode_packet1;
	this->decode_packet1	   = decode_packet1;
	this->print	   = print;
	this->reset	   = reset;
	this->whack	   = whack;

	return this;

 err:
	whack(this);
	return NULL;
}
