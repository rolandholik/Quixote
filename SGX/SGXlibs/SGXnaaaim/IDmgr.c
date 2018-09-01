/** \file
 * This file is designed to to provide a functionality stub for
 * an enclave based version of the PossumPipe object.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
/* Maximum lenth of an identity name. */
#define NAME_LENGTH 64


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "IDtoken.h"
#include "IDmgr.h"


/* State definition macro. */
#define STATE(var) CO(IDmgr_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDmgr_OBJID)
#error Object identifier not defined.
#endif


/**
 * Reference to the device identity provided.
 */
extern size_t Identity_size;
extern unsigned char *Identity;


/** IDmgr private state information. */
struct NAAAIM_IDmgr_State
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

/* Structure for the shared memory region. */
struct IDmgr_ipc
{
	pid_t pid;

	_Bool valid;

	IDmgr_type type;

	char name[NAME_LENGTH];

	unsigned char assertion_key[NAAAIM_IDSIZE],
		      assertion_id[NAAAIM_IDSIZE];

	unsigned char idkey[NAAAIM_IDSIZE];

	unsigned char idhash[NAAAIM_IDSIZE];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDmgr_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(IDmgr_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDmgr_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the setup of the server side of the identity
 * manager.  The IPC object is created and initialized and within
 * the defined shared memory region the process communications
 * structure is initialized.
 *
 * \param this	A pointer to the identity manager object which is
 *		being created.
 *
 * \return	If the identity manager is successfully created and
 *		initialized a true value is returned.  If a failure
 *		occurs during the setup a false value is returned.
 */

static _Bool setup(CO(IDmgr, this))

{
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements attachment to the identity manager by
 * a client.
 *
 * \param this	A pointer to the identity manager object which is
 *		to be attached to the identity manager.
 *
 * \return	If the attachment is successfully created a true value
 *		is returned.  If a failure occurs during the setup a
 *		false value is returned.
 */

static _Bool attach(CO(IDmgr, this))

{
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning the manifestation
 * type of the identity which is being requested.
 *
 * \param this	A pointer to the identity manager object which is
 *		requesting the identity type.
 *
 * \return	The type of the identity request is returned.  On error
 *		the enumerated type indicating no identity is present
 *		is returned.
 */

static IDmgr_type get_idtype(CO(IDmgr, this))

{
        IDmgr_type retn = IDmgr_none;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for determining the name of the
 * identity which is being requested by the client.
 *
 * \param this	A pointer to the identity manager object which is
 *		requesting the identity name.
 *
 * \param name	The object which will be loaded with the name of
 *		the identity being requested.
 *
 * \return	If the name retrieval succeeds a true value is returned.
 *		If an error is encountered a false value is returned.
 */

static _Bool get_idname(CO(IDmgr, this), CO(String, name))

{
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method an accessor method for sending an identity being held
 * under management.
 *
 * \param this		A pointer to the identity manager object which
 *			is sending the identity
 *
 * \param token		The IDtoken object containing the identity
 *			which is to be sent.
 *
 * \return		A true value is returned if the identity was
 *			successfully conveyed.  A false value
 *			indicates the identity was conveyed.
 */

static _Bool set_idtoken(CO(IDmgr, this), CO(IDtoken, token))

{
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for obtaining an identity
 * from the identity manager.
 *
 * \param this		A pointer to the identity manager object which
 *			is requesting the identity.
 *
 * \param name		A String object containing the name of the
 *			identity whose token is to be loaded.
 *
 * \param token		The IDtoken object which will be loaded with
 *			the identity obtained from the broker.
 *
 * \return		A true value is returned if the query for the
 *			identity was successful.  A false value indicated
 *			the request failed.
 */

static _Bool get_idtoken(CO(IDmgr, this), CO(String, name), CO(IDtoken, token))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, Identity, Identity_size) )
		ERR(goto done);

	if ( !token->decode(token, bufr) )
		ERR(goto done);
	if ( !token->to_verifier(token) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method an accessor method for returning the hash of the
 * identity implementation and the identity authentication element.
 * The primary consumer of this is generation of an OTEDKS key.
 *
 * \param this		A pointer to the identity manager object which
 *			the identity elements are requested from.
 *
 * \param name		A String object containing the name of the
 *			identity whose identity implementation hash
 *			and authentication element are to be returned.
 *
 * \param idhash	The Buffer object which will be loaded with
 *			the hash of the identity implementation.
 *
 * \param idkey		The Buffer object which will be loaded with
 *			the identity authenticator.
 *
 * \return		A true value is returned if the query for the
 *			key was successful.  A false value indicated
 *			the query failed.
 */

static _Bool get_id_key(CO(IDmgr, this), CO(String, name), \
			CO(Buffer, idhash), CO(Buffer, idkey))

{
	_Bool retn  = true;

	return retn;
}


/**
 * External public method.
 *
 * This method an accessor method for sending the hash of the
 * identity implementation and the identity authentication element to
 * a client.
 *
 * \param this		A pointer to the identity manager object which
 *			the identity elements are requested from.
 *
 * \param idtoken	The identity object whose identity hash
 *			implementation and key will be returned to
 *			the client.
 *
 * \return		A true value is returned if the identity
 *			elements were successfuly conveyed to the
 *			consumer.
 */

static _Bool set_id_key(CO(IDmgr, this), CO(IDtoken, idtoken))

{
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDmgr object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(IDmgr, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a IDmgr object.
 *
 * \return	A pointer to the initialized IDmgr.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDmgr NAAAIM_IDmgr_Init(void)

{
	auto Origin root;

	auto IDmgr this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDmgr);
	retn.state_size   = sizeof(struct NAAAIM_IDmgr_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDmgr_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->setup  = setup;
	this->attach = attach;

	this->get_idtype = get_idtype;
	this->get_idname = get_idname;

	this->set_idtoken = set_idtoken;
	this->get_idtoken = get_idtoken;

	this->get_id_key = get_id_key;
	this->set_id_key = set_id_key;

	this->whack = whack;

	return this;
}