/** \file
 * This file contains the implementation of an object that is used to
 * create sealed 'blobs' of data.  The data receives confidentiality
 * through the use of the AES256 encryption algorithm.  The encrypted
 * data is integrity protected with a SHA256-HMAC checksum.
 *
 * The keying elements, initialization vector and encryption key, are
 * generated with a <code>SEALkey</code> object.  This object uses the
 * ENCLU[EGETKEY] instruction to generate the necessary keying
 * elements.
 *
 * The generated keying elements are dependent on the contents of the
 * SGX_keyrequest structure that contains characterizing elements of
 * the Trusted Computing Base of the enclave.  Reproduction of an
 * identical key is dependent on these structure elements.  The
 * <code>SEALkey</code> object creates an ASN1 DER encoded
 * representation of this structure.
 *
 * The DER encoded structure is prepended to the encrypted data.  A
 * statically generated key is used to shroud the identity of the DER
 * encoded structure.  The integrity checksum is generated over the
 * shrouded version of the data blob.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <AES256_cbc.h>
#include <SHA256.h>
#include <SHA256_hmac.h>

#include <SRDE.h>

#include "NAAAIM.h"
#include "SEALkey.h"
#include "SEALEDblob.h"


/* Object state extraction macro. */
#define STATE(var) CO(SEALEDblob_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SEALEDblob_OBJID)
#error Object identifier not defined.
#endif

/* Size of encrypted blob header. */
#define VERSION1_SIZE 128

/* Version/magic number for the sealed image. */
#define VERSION1 0xD081B3E0

/* Size of payload MAC. */
#define MACSIZE 32

/** Static key identifier. */
const uint8_t keyid_v1[32] = {
	0x34, 0x02, 0x77, 0x1b, 0x71, 0xc3, 0x8c, 0x01, \
	0xdf, 0x08, 0x6d, 0xd8, 0xde, 0xf1, 0x3a, 0x84, \
	0xef, 0x01, 0xeb, 0x6a, 0x9f, 0x30, 0x74, 0x2d, \
	0x5e, 0x7a, 0xf2, 0xc6, 0x9e, 0xc4, 0xa4, 0x6c  \
};


/** SEALEDblob private state information. */
struct NAAAIM_SEALEDblob_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/** The object containing the sealed image. */
	Buffer blob;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SEALEDblob_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(CO(SEALEDblob_State, S))

{

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SEALEDblob_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the ability to add data that will be a
 * component of the sealed image.  It may be called multiple times in
 * order to incrementally add data.
 *
 * \param this	A pointer to the object that is to have data added to
 *		it.
 *
 * \param bufr	A pointer to the object containing the data to be
 *		added.
 *
 * \return	A boolean value is used to indicate the status of
 *		the addition of data.  A false value indicates an
 *		error occurred and the object has not had data
 *		assigned to it.  A true value indicates the
 *		retrieval has succeeded and the provided object
 *		has been loaded with data.
 */

static _Bool add_Buffer(CO(SEALEDblob, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Add the contents of the incoming object. */
	if ( !S->blob->add_Buffer(S->blob, bufr) )
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
 * This method implements an accessor method for returning the
 * contents of the state object containing the sealed data.
 *
 * \param this	A pointer to the object that is to have data
 *		retrieved from it.
 *
 * \param bufr	A pointer to the object that will be loaded
 *		with the data.
 *
 * \return	A boolean value is used to indicate the status of
 *		data retrieval.  A false value indicates an error
 *		occurred and the supplied target object does not
 *		have valid data.  A true value indicates the
 *		retrieval has succeeded and the provided object
 *		has been loaded with data.
 *		added.
 */

static _Bool get_Buffer(CO(SEALEDblob, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Add the contents of the incoming object. */
	if ( !bufr->add_Buffer(bufr, S->blob) )
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
 * This method implements sealing of the data that has been added to
 * the object.  The current unprotected contents of the object state
 * is replaced with the sealed contents.
 *
 * \param this	A pointer to the object that is to have its data
 *		sealed.
 *
 * \return	A boolean value is used to indicate the status of
 *		the data sealing.  A false value indicates an error
 *		and the object state is indeterminate.  A true value
 *		indicates the data has been sealed and is capable of
 *		retrieval.
 */

static _Bool seal(CO(SEALEDblob, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t version = VERSION1;

	Buffer iv   = NULL,
	       key  = NULL,
	       skey = NULL,
	       hkey = NULL,
	       kreq = NULL,
	       blob = NULL;

	SEALkey sealkey = NULL;

	AES256_cbc cipher = NULL;

	Sha256 sha256 = NULL;

	SHA256_hmac hmac = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Generate a seal key and its components. */
	INIT(HurdLib, Buffer, iv,   ERR(goto done));
	INIT(HurdLib, Buffer, key,  ERR(goto done));
	INIT(HurdLib, Buffer, kreq, ERR(goto done));

	INIT(NAAAIM, SEALkey, sealkey, ERR(goto done));
	if ( !sealkey->generate_mrsigner(sealkey) )
		ERR(goto done);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);
	if ( !sealkey->get_request(sealkey, kreq) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, iv);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	INIT(HurdLib, Buffer, skey, ERR(goto done));
	if ( !skey->add_Buffer(skey, sha256->get_Buffer(sha256)) )
		ERR(goto done);


	/* Encrypt the buffer. */
	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		ERR(goto done);
	if ( !cipher->encrypt(cipher, S->blob) )
		ERR(goto done);

	INIT(HurdLib, Buffer, blob, ERR(goto done));
	if ( !blob->add_Buffer(blob, cipher->get_Buffer(cipher)) )
		ERR(goto done);

	WHACK(cipher);


	/* Create version number and key request header. */
	S->blob->reset(S->blob);

	version = htonl(version);
	if ( !S->blob->add(S->blob, (unsigned char *) &version, \
			   sizeof(version)) )
		ERR(goto done);

	if ( !S->blob->add_Buffer(S->blob, kreq) )
		ERR(goto done);

	while ( S->blob->size(S->blob) < VERSION1_SIZE )
		S->blob->add(S->blob, (unsigned char *) "\0", 1);


	/* Encrypt the header. */
	key->reset(key);
	if ( !key->add(key, keyid_v1, sizeof(keyid_v1)) )
		ERR(goto done);

	sealkey->reset(sealkey);
	if ( !sealkey->generate_static_key(sealkey, SRDE_KEYPOLICY_SIGNER, \
					   key) )
		ERR(goto done);

	iv->reset(iv);
	key->reset(key);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);

	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		ERR(goto done);

	if ( !cipher->encrypt(cipher, S->blob) )
		ERR(goto done);


	/* Add the header checksum. */
	sha256->reset(sha256);
	sha256->add(sha256, iv);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	INIT(HurdLib, Buffer, hkey, ERR(goto done));
	if ( !hkey->add_Buffer(hkey, sha256->get_Buffer(sha256)) )
		ERR(goto done);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(hkey)) == NULL )
		ERR(goto done);

	hmac->add_Buffer(hmac, cipher->get_Buffer(cipher));
	if ( !hmac->compute(hmac) )
		ERR(goto done);


	/* Combine the encrypted header, MAC and payload. */
	S->blob->reset(S->blob);
	if ( !S->blob->add_Buffer(S->blob, cipher->get_Buffer(cipher)) )
		ERR(goto done);
	if ( !S->blob->add_Buffer(S->blob, hmac->get_Buffer(hmac)) )
		ERR(goto done);
	if ( !S->blob->add_Buffer(S->blob, blob) )
		ERR(goto done);


	/* Compute sealing MAC. */
	hkey->reset(hkey);
	if ( !hkey->add_Buffer(hkey, skey) )
		ERR(goto done);

	hmac->reset(hmac);
	hmac->add_Buffer(hmac, S->blob);
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	if ( !S->blob->add_Buffer(S->blob, hmac->get_Buffer(hmac)) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(iv);
	WHACK(key);
	WHACK(skey);
	WHACK(hkey);
	WHACK(kreq);
	WHACK(blob);
	WHACK(sealkey);
	WHACK(cipher);
	WHACK(sha256);
	WHACK(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method implements unsealing of the data that has been added to
 * the object.  The current protected contents of the object state
 * is replaced with the unsealed contents.
 *
 * \param this	A pointer to the object that is to have its data
 *		sealed.
 *
 * \return	A boolean value is used to indicate the status of
 *		the data un sealing.  A false value indicates an
 *		error and the object state is indeterminate.  A
 *		true value indicates the data has been unsealed and
 *		is capable of retrieval.
 */

static _Bool unseal(CO(SEALEDblob, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t version = VERSION1;

	Buffer mac1 = NULL,
	       mac2 = NULL,
	       iv   = NULL,
	       key  = NULL,
	       hkey = NULL,
	       kreq = NULL;

	SEALkey sealkey = NULL;

	AES256_cbc cipher = NULL;

	Sha256 sha256 = NULL;

	SHA256_hmac hmac = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Abstract checksum and reduce payload size. */
	INIT(HurdLib, Buffer, mac2, ERR(goto done));

	if ( !mac2->add(mac2, S->blob->get(S->blob) + \
			(S->blob->size(S->blob) - MACSIZE) , MACSIZE) )
		ERR(goto done);
	S->blob->shrink(S->blob, MACSIZE);


	/* Decrypt the payload header request components. */
	INIT(HurdLib, Buffer, kreq, ERR(goto done));
	if ( !kreq->add(kreq, S->blob->get(S->blob), VERSION1_SIZE + 16 + \
			MACSIZE) )
		ERR(goto done);

	INIT(HurdLib, Buffer, mac1, ERR(goto done));
	if ( !mac1->add(mac1, kreq->get(kreq) + \
			(kreq->size(kreq) - MACSIZE) , MACSIZE) )
		ERR(goto done);
	kreq->shrink(kreq, MACSIZE);


	/* Generate header key. */
	INIT(HurdLib, Buffer, iv,   ERR(goto done));
	INIT(HurdLib, Buffer, key,  ERR(goto done));
	if ( !key->add(key, keyid_v1, sizeof(keyid_v1)) )
		ERR(goto done);

	INIT(NAAAIM, SEALkey, sealkey, ERR(goto done))
	if ( !sealkey->generate_static_key(sealkey, SRDE_KEYPOLICY_SIGNER, \
					   key) )
		ERR(goto done);

	key->reset(key);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);


	/* Verify MAC in blob header. */
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, iv);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	INIT(HurdLib, Buffer, hkey, ERR(goto done));
	if ( !hkey->add_Buffer(hkey, sha256->get_Buffer(sha256)) )
		ERR(goto done);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(hkey)) == NULL )
		ERR(goto done);
	hmac->add_Buffer(hmac, kreq);
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	if ( !mac1->equal(mac1, hmac->get_Buffer(hmac)) )
		ERR(goto done);


	/* Decrypt blob header. */
	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		ERR(goto done);
	if ( !cipher->decrypt(cipher, kreq) )
		ERR(goto done);

	mac1->reset(mac1);
	if ( !mac1->add_Buffer(mac1, cipher->get_Buffer(cipher)) )
		ERR(goto done);

	version = *(uint32_t *) mac1->get(mac1);
	if ( htonl(version) != VERSION1 )
		ERR(goto done);

	kreq->reset(kreq);
	if ( !kreq->add(kreq, mac1->get(mac1) + sizeof(version), \
			mac1->size(mac1) - sizeof(version)) )
		ERR(goto done);

	WHACK(cipher);


	/* Verify the blob MAC. */
	iv->reset(iv);
	key->reset(key);
	sealkey->reset(sealkey);
	if ( !sealkey->set_request(sealkey, kreq) )
		ERR(goto done);
	if ( !sealkey->generate_mrsigner(sealkey) )
		ERR(goto done);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);

	sha256->reset(sha256);
	sha256->add(sha256, iv);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	hkey->reset(hkey);
	if ( !hkey->add_Buffer(hkey, sha256->get_Buffer(sha256)) )
		ERR(goto done);

	hmac->reset(hmac);
	hmac->add_Buffer(hmac, S->blob);
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	if ( !mac2->equal(mac2, hmac->get_Buffer(hmac)) )
		ERR(goto done);


	/* Decrypt payload. */
	mac1->reset(mac1);
	if ( !mac1->add(mac1, S->blob->get(S->blob) + VERSION1_SIZE + 48, \
			S->blob->size(S->blob) - VERSION1_SIZE - 48) )
		ERR(goto done);

	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		ERR(goto done);
	if ( !cipher->decrypt(cipher, mac1) )
		ERR(goto done);

	S->blob->reset(S->blob);
	if ( !S->blob->add_Buffer(S->blob, cipher->get_Buffer(cipher)) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(mac1);
	WHACK(mac2);
	WHACK(iv);
	WHACK(key);
	WHACK(hkey);
	WHACK(kreq);
	WHACK(sealkey);
	WHACK(cipher);
	WHACK(sha256);
	WHACK(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a SEALEDblob object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SEALEDblob, this))

{
	STATE(S);


	WHACK(S->blob);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SEALEDblob object.
 *
 * \return	A pointer to the initialized SEALEDblob.  A NULL value
 *		indicates an error was encountered in object generation.
 */

extern SEALEDblob NAAAIM_SEALEDblob_Init(void)

{
	Origin root;

	SEALEDblob this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SEALEDblob);
	retn.state_size   = sizeof(struct NAAAIM_SEALEDblob_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SEALEDblob_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->blob, goto fail);

	/* Method initialization. */
	this->add_Buffer = add_Buffer;
	this->get_Buffer = get_Buffer;

	this->seal   = seal;
	this->unseal = unseal;

	this->whack = whack;

	return this;


 fail:
	root->whack(root, this, this->state);
	return NULL;
}
