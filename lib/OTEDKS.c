/** \file
 * This file contains the implementation of an object for creating and
 * managing One Time Identification (OTI) keys.  These keys are 256 bits
 * in length and are designed to be used as keys for the AES encryption
 * of OTI payloads.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

#include <krb5.h>

#include <Origin.h>
#include <Buffer.h>

#include "KerDAP.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "OTIkey.h"


/* Verify library/object header file inclusions. */
#if !defined(KerDAP_LIBID)
#error Library identifier not defined.
#endif

#if !defined(KerDAP_OTIkey_OBJID)
#error Object identifier not defined.
#endif

/* The size of the initialization vector. */
#define IV_SIZE 16


/** OTIkey private state information. */
struct KerDAP_OTIkey_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Identity epoch time. */
	time_t epoch;

	/* Identity epoch offset. */
	time_t offset;

	/* The number of key iteration rounds. */
	uint8_t rounds;

	/* The SHA256 digest to be used. */
	SHA256 digest;

	/* The SHA256 based MAC generator. */
	SHA256_hmac hmac;

	/* The HMAC key. */
	Buffer hmac_key;

	/* The OTI key. */
	Buffer key;

	/* The initialization vector. */
	Buffer iv;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the KerDAP_OTIkey_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information which
 *		is to be initialized.
 *
 * \parram epoch	The epoch time of the identity.
 */

static void _init_state(const OTIkey_State const S, time_t const epoch)
{
	S->libid = KerDAP_LIBID;
	S->objid = KerDAP_OTIkey_OBJID;

	S->epoch  = epoch;
	S->offset = 0;
	S->rounds = 0;

	return;
}


/**
 * Internal private method.
 *
 * This method implements the initialization of the aggregate objects
 * needed for the key generation process.
 *
 * \param S	A pointer to the object containing the state information which
 *		is to be initialized.
 *
 * \param	A boolean return value is used to indicate whether or not
 *		all the needed objects were created.  A positive return
 *		value indicates success.
 */

static _Bool _init_aggregates(const OTIkey_State const S)

{
	if ( (S->key = HurdLib_Buffer_Init()) == NULL )
		return false;

	if ( (S->iv = HurdLib_Buffer_Init()) == NULL )
		return false;

	if ( (S->hmac_key = HurdLib_Buffer_Init()) == NULL )
		return false;

	if ( (S->digest = KerDAP_SHA256_Init()) == NULL )
		return false;

	if ( (S->hmac = KerDAP_SHA256_hmac_Init(S->hmac_key)) == NULL )
		return false;

	return true;
}


/**
 * External public method.
 *
 * This method implements the creation of the first key vector.  This
 * vector is created from the user's key, the epoch time and the epoch time
 * offset.  The general formula for the vector is as follows:
 *
 * Hmac(Key, epoch time)
 *
 * Where Key is created by:
 *
 * Key = H(Ukey || epoch difference)
 *
 * Where || implies concantenation.
 *
 * \param this		The OTI object whose first vector is to be created.
 *
 * \param userkey	A Buffer containing a key created from the user
 *			password.
 *
 * \return		A boolean value is used to indicate success or
 *			failure of the vector generation process.  A
 *			true value indicates success.
 */

static _Bool create_vector1(const OTIkey const this, \
			    const Buffer const userkey)

{
	auto const OTIkey_State const S = this->state;

	auto uint32_t offset = htonl(S->offset),
		      epoch  = htonl(S->epoch);

	auto struct tm *epoch_tm;


	/* Create the HMAC key by salting the user key. */
	if ( !S->hmac_key->add_Buffer(S->hmac_key, userkey) )
		return false;
	if ( !S->hmac_key->add(S->hmac_key, (unsigned char *) &offset, \
			       sizeof(offset)) )
		return false;

#if 0

	fprintf(stdout, "Epoch time:  %d\n", (int) S->epoch);
	fprintf(stdout, "Epoch ofset: %d\n", (int) S->offset);

	fputs("User key    : ", stdout);
	userkey->print(userkey);

	fputs("Vector 1 key: ", stdout);
	S->hmac_key->print(S->hmac_key);
#endif


	/* Compute the MAC digest. */
	if ( !S->hmac->add(S->hmac, (unsigned char *) &epoch, sizeof(epoch)) )
		return false;
	if ( !S->hmac->compute(S->hmac) )
		return false;
	S->key->add_Buffer(S->key, S->hmac->get_Buffer(S->hmac));

#if 0
	fputs("Vector 1: ", stdout);
	S->hmac->print(S->hmac);
#endif


	/* Load the round count from the vector. */
	epoch_tm = gmtime(&S->epoch);
	// fprintf(stdout, "Epoch day: %d\n", epoch_tm->tm_mday);
	S->rounds = *(S->hmac->get(S->hmac) + (epoch_tm->tm_mday - 1));
	if ( S->rounds < 10 )
		S->rounds += 10;
	// fprintf(stdout, "Rounds: %02x\n", S->rounds);

	S->hmac->reset(S->hmac);
	S->hmac_key->reset(S->hmac_key);
	return true;
}


/**
 * External public method.
 *
 * This method implements the creation of the second key vector.  This
 * vector is created from a hash of the encrypted identity token, the
 * epoch time difference and the user key.
 *
 * The general formula for the vector is as follows:
 *
 * Hmac(Key, user key)
 *
 * Where Key is created by:
 *
 * Key = H(ID hash || epoch difference)
 *
 * Where || implies concantenation.
 *
 * \param this		The OTI object whose first vector is to be created.
 *
 * \param userkey	A Buffer containing the user key.
 *
 * \param tokenhash	A Buffer containing the user identity token.
 *
 * \return		A boolean value is used to indicate success or
 *			failure of the vector generation process.  A
 *			true value indicates success.
 */

static _Bool create_vector2(const OTIkey const this, \
			    const Buffer const userkey, \
			    const Buffer const tokenhash)

{
	auto const OTIkey_State const S = this->state;

	auto uint32_t offset = htonl(S->offset);

	auto Buffer tb;


	/* Compute the hash of the identity token. */
	S->hmac_key->add_Buffer(S->hmac_key, tokenhash);
	S->hmac_key->add(S->hmac_key, (unsigned char *) &offset, \
			 sizeof(offset));

#if 0
	fputs("Token hash: ", stdout);
	tokenhash->print(tokenhash);
	fputs("Token key:  ", stdout);
	S->hmac_key->print(S->hmac_key);
#endif


	/* Compute the HMAC vector. */
	if ( !S->hmac->add_Buffer(S->hmac, userkey) )
		return false;
	if ( !S->hmac->compute(S->hmac) )
		return false;


	/* Load the initialization vector. */
	tb = S->hmac->get_Buffer(S->hmac);
	if ( !S->iv->add(S->iv, tb->get(tb), IV_SIZE) )
		return false;
	S->key->add_Buffer(S->key, tb);

#if 0
	fputs("Vector 2: ", stdout);
	tb->print(tb);

	fputs("IV      : ", stdout);
	S->iv->print(S->iv);

	fputs("Full vector: ", stdout);
	S->key->print(S->key);
#endif


	S->hmac->reset(S->hmac);
	S->hmac_key->reset(S->hmac_key);
	return true;
}


/**
 * External public method.
 *
 * This method generates the final key by running the key vector through
 * N rounds of iterative hashing where N is the round value computed from
 * the first vector.
 *
 * \param this	The key object whose final key is to be generated.
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of the key generation process.  A true value indicates
 *		success.
 */

static _Bool iterate(const OTIkey const this)

{
	auto const OTIkey_State const S = this->state;

	auto int round = S->rounds;


	while ( round > 0 ) {
		if ( !S->digest->add(S->digest, S->key) )
			return false;
		if ( !S->digest->compute(S->digest) )
			return false;

		S->key->reset(S->key); 
		if ( !S->key->add_Buffer(S->key, \
					 S->digest->get_Buffer(S->digest)) )
			return false;

		S->digest->reset(S->digest);
		--round;
	}


	/*
	 * HACK
	 * Due to poor field deployment of SHA-256 the digest and MAC
	 * objects downgrade the digest size to SHA1 (160 bits) if the
	 * 256 bit digest is not available.
	 *
	 * For the purposes of the example code we detect this by
	 * examining the size of the digest object.  If it is 20 bytes
	 * in length we run one more iteration of the hash and add
	 * sufficient bytes to the key to get a full 32 byte (256 bit)
	 * key.
	 */
	if ( S->key->size(S->key) == 20 ) {
		if ( !S->digest->add(S->digest, S->key) )
			return false;
		if ( !S->digest->compute(S->digest) )
			return false;
		if ( !S->key->add(S->key, S->digest->get(S->digest), 12) )
			return false;
	}

	return true;
}


/**
 * External public method.
 *
 * This method implements computing the symmetic key for a One Time
 * Identification challenge.  It rolls up the three separate stages of
 * the key scheduling process into a single call.
 *
 * \param this		A pointer to the key object whose key is to
 *			be scheduled.
 *
 * \param userkey	A buffer key containing the user key to use in
 *			the scheduling process.
 *
 * \param token		The identity token which is to be used in the
 *			process.
 *
 * \return		If key scheduling is successful the Buffer object
 *			containing the key is returned to the caller.  If
 *			an error is detected a NULL value is returned.
 */

static Buffer compute(const OTIkey const this, time_t const authtime, \
		      const Buffer const userkey,  const Buffer const token)

{
	auto const OTIkey_State const S = this->state;


	/* Compute the epoch time offset. */
	if ( S->epoch < authtime )
		S->offset = authtime - S->epoch;
	else
		S->offset = S->epoch - authtime;


	/* Compute the vectors for the key scheduler. */
	if ( !create_vector1(this, userkey) )
		return NULL;
	if ( !create_vector2(this, userkey, token) )
		return NULL;


	/* Run the key iteration scheduler. */
	if ( !iterate(this) )
		return NULL;


	return this->state->key;
}


/**
 * This function implements an accessor function for returning the Buffer
 * containing the generated key.
 *
 * \param this	The OTI key scheduler whose key is to be returned.
 *
 * \return	If a key has been generated the Buffer containing the
 *		key is returned.  If a key has not been generated a NULL
 *		pointer is returned.
 */

static Buffer get_key(const OTIkey const this)

{
	auto const OTIkey_State const S = this->state;


	if ( S->key->size(S->key) == 0 )
		return NULL;

	return S->key;
}


/**
 * This function implements an accessor function for returning the Buffer
 * containing the initialization vector associated with the computed key.
 *
 * \param this	The OTI key scheduler whose initialization vector is to
 *		be returned.
 *
 * \return	If a key has been generated the Buffer containing the
 *		key is returned.  If a key has not been generated a NULL
 *		pointer is returned.
 */

static Buffer get_iv(const OTIkey const this)

{
	auto const OTIkey_State const S = this->state;


	if ( S->iv->size(S->iv) == 0 )
		return NULL;

	return S->iv;
}


/**
 * This function implements resetting of the key scheduler to prepare the
 * object for a computation of another key.
 *
 * \param this	The key scheduler which is to be reset.
 */

static void reset(const OTIkey const this)

{
	auto const OTIkey_State const S = this->state;

	S->offset = 0;
	S->rounds = 0;

	S->digest->reset(S->digest);
	S->hmac->reset(S->hmac);
	S->hmac_key->reset(S->hmac_key);
	S->key->reset(S->key);
	S->iv->reset(S->iv);

	return;
}
	

/**
 * External public method.
 *
 * This method implements a destructor for a OTIkey object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const OTIkey const this)

{
	auto const OTIkey_State const S = this->state;


	if ( S->key != NULL )
		S->key->whack(S->key);
	if ( S->iv != NULL )
		S->iv->whack(S->iv);
	if ( S->hmac_key != NULL )
		S->hmac_key->whack(S->hmac_key);
	if ( S->digest != NULL )
		S->digest->whack(S->digest);
	if ( S->hmac != NULL )
		S->hmac->whack(S->hmac);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a OTIkey object.
 *
 * \return	A pointer to the initialized OTIkey.  A null value
 *		indicates an error was encountered in object generation.
 * 
 * \param epoch		The epoch time of the pre-identification token.
 */

extern OTIkey KerDAP_OTIkey_Init(time_t const epoch)

{
	auto Origin root;

	auto OTIkey this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct KerDAP_OTIkey);
	retn.state_size   = sizeof(struct KerDAP_OTIkey_State);
	if ( !root->init(root, KerDAP_LIBID, KerDAP_OTIkey_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	_init_aggregates(this->state);

	/* Initialize object state. */
	_init_state(this->state, epoch);

	/* Method initialization. */
	this->create_vector1 = create_vector1;
	this->create_vector2 = create_vector2;
	this->iterate = iterate;

	this->compute  = compute;

	this->get_key = get_key;
	this->get_iv  = get_iv;

	this->reset = reset;
	this->whack = whack;

	return this;
}
