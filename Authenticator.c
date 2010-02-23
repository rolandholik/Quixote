/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "RSAkey.h"
#include "IDtoken.h"
#include "Authenticator.h"
#include "AES256_cbc.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Authenticator_OBJID)
#error Object identifier not defined.
#endif


/** Authenticator private state information. */
struct NAAAIM_Authenticator_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Organizational identifier elements. */
	Buffer orgkey;
	Buffer orgid;

	/* Organizational identity. */
	Buffer id;

	/* Encryption key. */
	Buffer key;

	/* Identity elements. */
	Buffer elements;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the authenticator which will be transmitted over
 * the wire.
 */
typedef struct {
        ASN1_OCTET_STRING *orgkey;
        ASN1_OCTET_STRING *orgid;
        ASN1_OCTET_STRING *id;
	ASN1_OCTET_STRING *key;
	ASN1_OCTET_STRING *elements;
} authenticator_payload;

ASN1_SEQUENCE(authenticator_payload) = {
        ASN1_SIMPLE(authenticator_payload, orgkey,   ASN1_OCTET_STRING),
        ASN1_SIMPLE(authenticator_payload, orgid,    ASN1_OCTET_STRING),
        ASN1_SIMPLE(authenticator_payload, id,	     ASN1_OCTET_STRING),
        ASN1_SIMPLE(authenticator_payload, key,	     ASN1_OCTET_STRING),
        ASN1_SIMPLE(authenticator_payload, elements, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(authenticator_payload)

IMPLEMENT_ASN1_FUNCTIONS(authenticator_payload)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Authenticator_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const Authenticator_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Authenticator_OBJID;

	S->poisoned = false;
	S->orgkey   = NULL;
	S->orgid    = NULL;
	S->id	    = NULL;
	S->key	    = NULL;
	S->elements = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements setting the identity elements of the
 * authenticator objects.  These identity elements are the data items
 * needed for the authenticating entity to identity and authenticate
 * the identity.
 *
 * \param this	The authenticator whose identity elements are to be
 *		loaded.
 *
 * \param token	The identity token used as the source of the identifying
 *		elements.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future activity.
 */

static _Bool add_identity(const Authenticator const this, \
			  const IDtoken const token)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;


	/* Set the identity elements. */
	S->orgkey->add_Buffer(S->orgkey, \
			      token->get_element(token, IDtoken_orgkey));
	S->orgid->add_Buffer(S->orgid, \
			     token->get_element(token, IDtoken_orgid));
	S->id->add_Buffer(S->id, token->get_element(token, IDtoken_id));

	if ( S->orgkey->poisoned(S->orgkey) || S->orgid->poisoned(S->orgid) \
	     || S->id->poisoned(S->id) )
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
 * This method implements obtaiining the identity elements in the
 * authenticator in the form of an IDtoken object.  It is essentially
 * the reciprocal function of the add_identity method.
 *
 * \param this	The authenticator whose identity elements are to be
 *		retrieved.
 *
 * \param token	The identity token which will be loaded with the
 *		identity elements.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future activity.
 */

static _Bool get_identity(const Authenticator const this, \
			  const IDtoken const token)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;


	/* Set the identity components in the token. */
	if ( !token->set_element(token, IDtoken_orgkey, S->orgkey) )
		goto done;
	if ( !token->set_element(token, IDtoken_orgid, S->orgid) )
		goto done;
	if ( !token->set_element(token, IDtoken_id, S->id) )
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

static _Bool add_element(const Authenticator const this, \
			 const Buffer const element)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned || element->poisoned(element) )
		goto done;

	if ( !S->elements->add_Buffer(S->elements, element) )
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
 * \param this	The Authenticator object whose elements are to be
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

static _Bool encrypt(const Authenticator const this, const char * const rsa)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;

	auto Buffer encrypted,
		    iv = NULL;

	auto RandomBuffer randbufr = NULL;

	auto RSAkey rsakey = NULL;

	auto AES256_cbc aes256 = NULL;


	/* Sanity checks. */
	if ( S->poisoned || (S->elements->size(S->elements) == 0) )
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
	if ( (rsakey = NAAAIM_RSAkey_Init()) == NULL )
		goto done;

	S->key->add_Buffer(S->key, iv);
		
	rsakey->load_private_key(rsakey, rsa);
	if ( !rsakey->encrypt(rsakey, S->key) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	if ( iv != NULL )
		iv->whack(iv);
	if ( randbufr != NULL )
		randbufr->whack(randbufr);
	if ( rsakey != NULL )
		rsakey->whack(rsakey);
	if ( aes256 != NULL )
		aes256->whack(aes256);

	return retn;
}


/**
 * External public method.
 *
 * This method is responsible for decrypting a previously encrypted
 * authenticator payload.  The symmetric key and initialization vector
 * are obtained from the RSA encrypted key package and used to
 * decrypt the target identity elements.
 *
 * \param this	The Authenticator object whose elements are to be
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

static _Bool decrypt(const Authenticator const this, const char * const rsa)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;

	auto Buffer decrypted,
		    iv = NULL;

	auto RSAkey rsakey = NULL;

	auto AES256_cbc aes256 = NULL;


	/* Sanity checks. */
	if ( S->poisoned )
		goto done;


	/* Decrypt the initialization vector and symmetric key. */
	if ( (rsakey = NAAAIM_RSAkey_Init()) == NULL )
		goto done;
	rsakey->load_public_key(rsakey, rsa);
	if ( !rsakey->decrypt(rsakey, S->key) )
		goto done;

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
	if ( rsakey != NULL )
		rsakey->whack(rsakey);
	if ( aes256 != NULL )
		aes256->whack(aes256);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the encoding of the contents of the
 * Authenticator object into an ASN1 structure.  The binary encoding
 * is loaded into a Buffer object provided by the caller.
 *
 * \param this	The Authenticator object whose elements are to be
 *		encoded.
 *
 * \param bufr	A buffer object which the encoded structure will be
 *		loaded into.
 *
 * \return	A boolean value is used to return success or failure of
 *		the encoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool encode(const Authenticator const this, const Buffer const bufr)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto authenticator_payload *payload = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	if ( (payload = authenticator_payload_new()) == NULL )
		goto done;

        if ( ASN1_OCTET_STRING_set(payload->orgkey,		\
				   S->orgkey->get(S->orgkey),	\
                                   S->orgkey->size(S->orgkey)) != 1 )
                goto done;
        if ( ASN1_OCTET_STRING_set(payload->orgid, S->orgid->get(S->orgid), \
                                   S->orgid->size(S->orgid)) != 1 )
                goto done;
        if ( ASN1_OCTET_STRING_set(payload->id, S->id->get(S->id), \
				   S->id->size(S->id)) != 1 )
                goto done;
        if ( ASN1_OCTET_STRING_set(payload->key, S->key->get(S->key), \
                                   S->key->size(S->key)) != 1 )
                goto done;
        if ( ASN1_OCTET_STRING_set(payload->elements, \
				   S->elements->get(S->elements),
                                   S->elements->size(S->elements)) != 1 )
                goto done;

        asn_size = i2d_authenticator_payload(payload, p);
        if ( asn_size < 0 )
                goto done;

	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;
	retn = true;
	

 done:
	if ( retn == false )
		S->poisoned = true;
	if ( payload != NULL )
		authenticator_payload_free(payload);

	return retn;
}


/**
 * External public method.
 *
 * This method implements decoding the contents of a DER encoded ASN1
 * structure into an Authenticator object.  The binary encoding is
 * provided by a Buffer supplied by the caller.
 *
 * \param this	The Authenticator object which is to receive the
 *		encoded object.
 *
 * \param bufr	A buffer object containing the encoded structure to
 *		loaded.
 *
 * \return	A boolean value is used to return success or failure of
 *		the decoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool decode(const Authenticator const this, const Buffer const bufr)

{
	auto const Authenticator_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto int asn_size;

	auto authenticator_payload *payload = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_authenticator_payload(&payload, &p, asn_size) )
                goto done;	

	S->orgkey->add(S->orgkey, ASN1_STRING_data(payload->orgkey), \
		       ASN1_STRING_length(payload->orgkey));
	S->orgid->add(S->orgid, ASN1_STRING_data(payload->orgid), \
		      ASN1_STRING_length(payload->orgid));
	S->id->add(S->id, ASN1_STRING_data(payload->id), \
		   ASN1_STRING_length(payload->id));
	S->key->add(S->key, ASN1_STRING_data(payload->key), \
		   ASN1_STRING_length(payload->key));
	S->elements->add(S->elements, ASN1_STRING_data(payload->elements), \
		   ASN1_STRING_length(payload->elements));

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( payload != NULL )
		authenticator_payload_free(payload);

	return retn;
}


/**
 * External public method.
 *
 * This method prints the contents of an Authenticator object.  The
 * status, ie, whether or not the object has been poisoned is also
 * indicated.
 *
 * \param this	A pointer to the object which is to be printed..
 */

static void print(const Authenticator const this)

{
	auto const Authenticator_State const S = this->state;


	if ( S->poisoned )
		fputs("* POISONED *\n", stdout);

	fputs("orgkey:\n", stdout);
	S->orgkey->print(S->orgkey);
	fputs("orgid:\n", stdout);
	S->orgid->print(S->orgid);

	fputs("id:\n", stdout);
	S->id->print(S->id);

	fputs("key:\n", stdout);
	S->key->print(S->key);

	fputs("elements\n", stdout);
	S->elements->print(S->elements);

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

static void reset(const Authenticator const this)

{
	auto const Authenticator_State const S = this->state;


	if ( S->poisoned )
		return;

	S->orgkey->reset(S->orgkey);
	S->orgid->reset(S->orgid);
	S->id->reset(S->id);
	S->key->reset(S->key);
	S->elements->reset(S->elements);

	return;
}
     

/**
 * External public method.
 *
 * This method implements a destructor for a Authenticator object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const Authenticator const this)

{
	auto const Authenticator_State const S = this->state;


	/* Release Buffer elements. */
	if ( S->orgkey != NULL )
		S->orgkey->whack(S->orgkey);
	if ( S->orgid != NULL )
		S->orgid->whack(S->orgid);
	if ( S->id != NULL )
		S->id->whack(S->id);
	if ( S->key != NULL )
		S->key->whack(S->key);
	if ( S->elements != NULL )
		S->elements->whack(S->elements);


	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Authenticator object.
 *
 * \return	A pointer to the initialized Authenticator.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Authenticator NAAAIM_Authenticator_Init(void)

{
	auto Origin root;

	auto Authenticator this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Authenticator);
	retn.state_size   = sizeof(struct NAAAIM_Authenticator_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Authenticator_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	if ( (this->state->orgkey = HurdLib_Buffer_Init()) == NULL )
		goto err;
	if ( (this->state->orgid = HurdLib_Buffer_Init()) == NULL )
		goto err;
	if ( (this->state->id = HurdLib_Buffer_Init()) == NULL )
		goto err;
	if ( (this->state->key = HurdLib_Buffer_Init()) == NULL )
		goto err;
	if ( (this->state->elements = HurdLib_Buffer_Init()) == NULL )
		goto err;

	/* Method initialization. */
	this->add_identity = add_identity;
	this->get_identity = get_identity;
	this->add_element  = add_element;
	this->encrypt	   = encrypt;
	this->decrypt	   = decrypt;
	this->encode	   = encode;
	this->decode	   = decode;
	this->print	   = print;
	this->reset	   = reset;
	this->whack	   = whack;

	return this;

 err:
	whack(this);
	return NULL;
}
