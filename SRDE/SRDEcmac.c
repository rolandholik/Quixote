/** \file
 * This file contains the implementation of an object which is used to
 * implement the AES128-CMAC algorithm used to generate message
 * authentication signatures.  It currently uses the Intel cryptography
 * library until an OpenSSL implementation can be developed.
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

#include <sgx_tcrypto.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SRDEcmac.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEcmac_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEcmac_OBJID)
#error Object identifier not defined.
#endif


/** SRDEcmac private state information. */
struct NAAAIM_SRDEcmac_State
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
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEcmac_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SRDEcmac_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEcmac_OBJID;


	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the verification of an ECDSA signature.
 *
 * \param this		A pointer to the provisioning object which
 *			is to be opened.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool compute(CO(SRDEcmac, this), CO(Buffer, key), CO(Buffer, msg), \
		     CO(Buffer, mac))

{
	STATE(S);

	_Bool retn = false;

	sgx_cmac_128bit_tag_t output;

	sgx_cmac_128bit_key_t lkey;

	sgx_status_t status;


	/* Object status verification. */
	if ( S->poisoned )
		ERR(goto done);


	/* Verify the signature. */
	memcpy(lkey, key->get(key), sizeof(lkey));
	status = sgx_rijndael128_cmac_msg((const sgx_cmac_128bit_key_t *)   \
					  &lkey, (uint8_t *) msg->get(msg), \
					  msg->size(msg), &output);
	if ( status != SGX_SUCCESS )
		ERR(goto done);

	if ( !mac->add(mac, output, sizeof(output)) )
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
 * This method implements a destructor for the SRDEcmac object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEcmac, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEcmac object.
 *
 * \return	A pointer to the initialized SRDEcmac.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEcmac NAAAIM_SRDEcmac_Init(void)

{
	Origin root;

	SRDEcmac this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEcmac);
	retn.state_size   = sizeof(struct NAAAIM_SRDEcmac_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEcmac_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->compute = compute;

	this->whack = whack;

	return this;
}
