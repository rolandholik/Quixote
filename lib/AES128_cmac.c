/** \file
 * This file contains the implementation of an object that implements
 * the AES128 based cipher message authentication code.  This object
 * is a wrapper object around the OpenSSL implementation of the
 * CMAC.
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
#include <string.h>

#include <openssl/cmac.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "AES128_cmac.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_AES128_cmac_OBJID)
#error Object identifier not defined.
#endif


/* Object state extraction macro. */
#define STATE(var) CO(AES128_cmac_State, var) = this->state


/** AES128_cmac private state information. */
struct NAAAIM_AES128_cmac_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* OpenSSL CMAC context. */
	CMAC_CTX *context;

	/* CMAC key. */
	Buffer key;

	/* Message authentication code. */
	Buffer mac;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_AES128_cmac_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(const AES128_cmac_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_AES128_cmac_OBJID;

	S->poisoned = false;

	S->key	   = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the initialization of the object for
 * computation of the message authentication code.
 *
 * \param this	A pointer to the object which is to be
 *		initialized.
 *
 * \param key	The object containing the key to be used for
 *		initializing the checksum.
 *
 * \return	If an error occurs with initialization of the
 *		object a false value is returned.  In this event
 *		the object is poisoned an is unusable.  A true
 *		value indicates the initialization succeeded and
 *		the object is ready to have data added to it.
 */

static _Bool set_key(CO(AES128_cmac, this), CO(Buffer, key))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( key == NULL )
		ERR(goto done);
	if ( key->poisoned(key) )
		ERR(goto done);
	if ( key->size(key) != 16 )
		ERR(goto done);


	/* Initialize the OpenSSL object. */
	if ( CMAC_Init(S->context, key->get(key), key->size(key), \
		       EVP_aes_128_cbc(), NULL) != 1 )
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
 * This method implements adding message content to the current
 * MAC value being computed.
 *
 * \param this	A pointer to the object which is to have input
 *		added to it.
 *
 * \param in	A pointer the the area of memory containing the
 *		message to be added.
 *
 * \param amt	The amount of memory to be added.
 *
 * \return	If an error occurs while adding the input a false
 *		value is returned.  The object is poisoned and is
 *		no longer usable.  A true value indicates the input
 *		succeeded.
 */

static _Bool add(CO(AES128_cmac, this), CO(uint8_t *, in), const size_t amt)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object state and arguements. */
	if ( S->poisoned )
		ERR(goto done);

	/* Add the message to the current context. */
	if ( CMAC_Update(S->context, in, amt) != 1 )
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
 * This method implements computing the message authentication code
 * based on the message stream that has been input.
 *
 * \param this	A pointer to the object which is to have its MAC
 *		value computed.
 *
 * \return	If an error occurs while computing the MAC value a
 *		false value is returned and the object is poisoned.
 *		If the computation is successful a true value is
 *		returned and the MAC value can be retrieved from
 *		the object.
 */

static _Bool compute(CO(AES128_cmac, this))

{
	STATE(S);

	_Bool retn = false;

	uint8_t mac[16];

	size_t length;


	/* Verify object state and arguements. */
	if ( S->poisoned )
		ERR(goto done);

	/* Add the message to the current context. */
	if ( CMAC_Final(S->context, mac, &length) != 1 )
		ERR(goto done);
	if ( !S->mac->add(S->mac, mac, length) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	memset(mac, '\0', sizeof(mac));

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the object that contains the
 * computed MAC value.  An object will also be returned but should
 * only be considered valid after a successful ->compute method call.
 *
 * \param this	A pointer to the object which is to have its
 *		MAC object returned.
 *
 * \return	A <code>Buffer</code> object that contains the
 *		generated MAC value.
 */

static Buffer get_Buffer(CO(AES128_cmac, this))

{
	STATE(S);

	return S->mac;
}


/**
 * External public method.
 *
 * This method implements a destructor for an AES128_cmac object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(AES128_cmac, this))

{
	STATE(S);


	WHACK(S->key);
	WHACK(S->mac);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements the constructor call for a AES128_cmac
 * object.
 *
 * \return	A pointer to the initialized AES128_cmac.  A null value
 *		indicates an error was encountered in object generation.
 */

extern AES128_cmac NAAAIM_AES128_cmac_Init(void)

{
	Origin root;

	AES128_cmac this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_AES128_cmac);
	retn.state_size   = sizeof(struct NAAAIM_AES128_cmac_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_AES128_cmac_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->key, goto fail);
	INIT(HurdLib, Buffer, this->state->mac, goto fail);

	if ( (this->state->context = CMAC_CTX_new()) == NULL )
		goto fail;

	/* Method initialization. */
	this->set_key = set_key;

	this->add = add;

	this->compute	 = compute;
	this->get_Buffer = get_Buffer;

	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->key);
	WHACK(this->state->mac);

	root->whack(root, this, this->state);
	return NULL;
}
