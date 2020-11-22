/** \file
 * This file contains the implementation of an object which is used to
 * implement the AES128-GCM algorithm used for data confidentiality.
 * It currently uses the Intel cryptography library until an OpenSSL
 * implementation can be developed.
 *
 * The encryption algorithm was verified with the following test vector:
 *
 * Key:  feffe9928665731c6d6a8f9467308308
 *
 * Iv:	 cafebabefacedbaddecaf888
 *
 * Aaad: feedfacedeadbeeffeedfacedeadbeefabaddad2
 *
 * Pt:   d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
 *
 * Yielding:
 *
 * Ct: d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
 *
 * Tag: 5bc94fbc3221a5db94fae95ae7121a47
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
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

#include <sgx_tcrypto.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SRDEaesgcm.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEaesgcm_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEaesgcm_OBJID)
#error Object identifier not defined.
#endif


/** SRDEaesgcm private state information. */
struct NAAAIM_SRDEaesgcm_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;
};


/**
 * External supplemental function.
 *
 * This function supplies functionality which normally is
 * provided by te SGX standard C library.  It is needed to
 * support the ECC routines.
 *
 * The function implements a 'safe' memory clearing routine.
 */
#if 0
static void * (* const volatile __memset_vp)(void *, int, size_t)
    = (memset);


int memset_s(void *s, size_t smax, int c, size_t n)

{
    int err = 0;

    if (s == NULL) {
        err = EINVAL;
        goto out;
    }
    if (smax > SIZE_MAX) {
        err = E2BIG;
        goto out;
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);

    out:
    if (err == 0)
        return 0;
    else {
        errno = err;
        /* XXX call runtime-constraint handler */
        return err;
    }
}


/**
 * External supplemental function.
 *
 * This function supplies functionality which normally is
 * provided by te SGX standard C library.  It is needed to
 * support the ECC routines.
 *
 * This function requests the provisioning of random numbers.
 */

int sgx_read_rand(unsigned char *out, size_t cnt)

{
	_Bool retn = SGX_ERROR_INVALID_PARAMETER;

	Buffer bufr = NULL;

	RandomBuffer rnd = NULL;


	INIT(NAAAIM, RandomBuffer, rnd, ERR(goto done));
	if ( !rnd->generate(rnd, cnt) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( (bufr = rnd->get_Buffer(rnd)) == NULL )
		ERR(goto done);

	memcpy(out, bufr->get(bufr), cnt);
	retn = 0;


 done:
	WHACK(rnd);
	WHACK(bufr);

	return retn;
}
#endif


/**
 * External supplemental function.
 *
 * This function supplies functionality which normally is
 * provided by te SGX standard C library.  It is needed to
 * support the ECC routines.
 *
 * The function implements a time constant memory comparison
 * function.
 */

int consttime_memequal(const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = b1, *c2 = b2;
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	 * Map 0 to 1 and [1, 256) to 0 using only constant-time
	 * arithmetic.
	 *
	 * This is not simply `!res' because although many CPUs support
	 * branchless conditional moves and many compilers will take
	 * advantage of them, certain compilers generate branches on
	 * certain CPUs for `!res'.
	 */
	return (1 & ((res - 1) >> 8));
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEaesgcm_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SRDEaesgcm_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEaesgcm_OBJID;


	S->poisoned = false;

	return;
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

static _Bool encrypt(CO(SRDEaesgcm, this), CO(Buffer, key), CO(Buffer, iv), \
		     CO(Buffer, payload), CO(Buffer, output),		    \
		     CO(Buffer, extra), CO(Buffer, mactag))

{
	STATE(S);

	_Bool retn = false;

	size_t size;

	sgx_aes_gcm_128bit_tag_t tag;

	sgx_aes_gcm_128bit_key_t lkey;

	sgx_status_t status;


	/* Object and input status verification. */
	if ( S->poisoned )
		ERR(goto done);
	if ( key->poisoned(key) )
		ERR(goto done);
	if ( iv->poisoned(iv) )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);
	if ( extra->poisoned(extra) )
		ERR(goto done);
	if ( mactag->poisoned(mactag) )
		ERR(goto done);


	/* Step the output buffer forward to match the message. */
	if ( (size = payload->size(payload)) == 0 )
		ERR(goto done);

	while ( size ) {
		output->add(output, (unsigned char *) "\0", 1);
		--size;
	}
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Encrypt the requested data. */
	memcpy(lkey, key->get(key), sizeof(lkey));
	status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) \
					    &lkey,			      \
					    (uint8_t *) payload->get(payload),\
					    payload->size(payload),	      \
					    output->get(output),	      \
					    iv->get(iv), iv->size(iv),	      \
					    extra->get(extra),		      \
					    extra->size(extra), &tag);
	if ( status != SGX_SUCCESS )
		ERR(goto done);

	if ( !mactag->add(mactag, tag, sizeof(tag)) )
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
 * This method implements AES128-GCM decryption of the supplied message.
 *
 * \param this		A pointer to the object managing the decryption
 *			object.
 *
 * \param key		The object containing the binary encryption key.
 *
 * \param iv		The object containing the initialization vector.
 *
 * \param payload	The object which contains encrypted data to be
 *			decrypted.
 *
 * \param extra		The object containing additional data to be
 *			included into the authentication tag.
 *
 * \return	If an error is encountered processing the decryption
 *		request a false value is returned.  A true value
 *		indicates the output object has valid decrypted data.
 */

static _Bool decrypt(CO(SRDEaesgcm, this), CO(Buffer, key), CO(Buffer, iv), \
		     CO(Buffer, payload), CO(Buffer, output),		    \
		     CO(Buffer, extra), CO(Buffer, mactag))

{
	STATE(S);

	_Bool retn = false;

	size_t size;

	sgx_aes_gcm_128bit_tag_t tag;

	sgx_aes_gcm_128bit_key_t lkey;

	sgx_status_t status;


	/* Object and input status verification. */
	if ( S->poisoned )
		ERR(goto done);
	if ( key->poisoned(key) )
		ERR(goto done);
	if ( iv->poisoned(iv) )
		ERR(goto done);
	if ( payload->poisoned(payload) )
		ERR(goto done);
	if ( output->poisoned(output) )
		ERR(goto done);
	if ( extra->poisoned(extra) )
		ERR(goto done);
	if ( mactag->poisoned(mactag) )
		ERR(goto done);


	/* Step the output buffer forward to match the message. */
	if ( (size = payload->size(payload)) == 0 )
		ERR(goto done);

	while ( size ) {
		output->add(output, (unsigned char *) "\0", 1);
		--size;
	}
	if ( output->poisoned(output) )
		ERR(goto done);


	/* Decrypt the requested data and verify integrity. */
	memcpy(lkey, key->get(key), sizeof(lkey));
	memcpy(tag, mactag->get(mactag), sizeof(tag));
	status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) \
					    &lkey,			      \
					    (uint8_t *) payload->get(payload),\
					    payload->size(payload),	      \
					    output->get(output),	      \
					    iv->get(iv), iv->size(iv),	      \
					    extra->get(extra),		      \
					    extra->size(extra),
					    (const sgx_aes_gcm_128bit_tag_t *)\
					    &tag);
	if ( status != SGX_SUCCESS )
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
 * This method implements a destructor for the SRDEaesgcm object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEaesgcm, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEaesgcm object.
 *
 * \return	A pointer to the initialized SRDEaesgcm.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEaesgcm NAAAIM_SRDEaesgcm_Init(void)

{
	Origin root;

	SRDEaesgcm this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEaesgcm);
	retn.state_size   = sizeof(struct NAAAIM_SRDEaesgcm_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEaesgcm_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->encrypt = encrypt;
	this->decrypt = decrypt;

	this->whack = whack;

	return this;
}
