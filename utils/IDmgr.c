/** \file
 * This file implements the methods for implementing transactions
 * against the identity manager daemon.  Communications is carried
 * out through a POSIX shared memory region.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "IDtoken.h"
#include "IPC.h"
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

	/* Identity manager IPC object.*/
	IPC ipc;
};

/* Structure for the shared memory region. */
struct IDmgr_ipc
{
	pid_t pid;

	_Bool valid;

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
	STATE(S);

	_Bool retn = false;

	struct IDmgr_ipc *idipc;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->create(S->ipc, "IDmgr", sizeof(struct IDmgr_ipc)) )
		goto done;

	idipc = S->ipc->get(S->ipc);
	memset(idipc, '\0', sizeof(struct IDmgr_ipc));
	idipc->pid = getpid();

	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
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
 &		false value is returned.
 */

static _Bool attach(CO(IDmgr, this))

{
	STATE(S);

	_Bool retn = false;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->attach(S->ipc, "IDmgr") )
		goto done;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
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
	STATE(S);

	_Bool retn = false;

	struct IDmgr_ipc *ipc;

	Buffer b;


	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;

	ipc = S->ipc->get(S->ipc);

	b = token->get_element(token, IDtoken_orgkey);
	memcpy(ipc->assertion_key, b->get(b), b->size(b));
	b = token->get_element(token, IDtoken_orgid);
	memcpy(ipc->assertion_id, b->get(b), b->size(b));

	b = token->get_element(token, IDtoken_id);
	memcpy(ipc->idhash, b->get(b), b->size(b));

	b = token->get_element(token, IDtoken_key);
	memcpy(ipc->idkey, b->get(b), b->size(b));

	ipc->valid = true;
	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
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
 * \param token		The IDtoken object which will be loaded with
 *			the identity obtained from the broker.
 *
 * \return		A true value is returned if the query for the
 *			identity was successful.  A false value indicated
 *			the request failed.
 */

static _Bool get_idtoken(CO(IDmgr, this), CO(IDtoken, token))

{
	STATE(S);

	_Bool retn = false;

	struct IDmgr_ipc *ipc;

	Buffer b = NULL;


	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;


	INIT(HurdLib, Buffer, b, goto done);

	ipc = S->ipc->get(S->ipc);
	if ( !S->ipc->lock(S->ipc) )
		goto done;

	ipc->valid = false;
	kill(ipc->pid, SIGUSR1);
	while ( !ipc->valid )
		continue;

	b->add(b, ipc->assertion_key, sizeof(ipc->assertion_key));
	if ( !token->set_element(token, IDtoken_orgkey, b) )
		goto done;
	b->reset(b);
	b->add(b, ipc->assertion_id, sizeof(ipc->assertion_id));
	if ( !token->set_element(token, IDtoken_orgid, b) )
		goto done;

	b->reset(b);
	b->add(b, ipc->idhash, sizeof(ipc->idhash));
	if ( !token->set_element(token, IDtoken_id, b) )
		goto done;

	b->reset(b);
	b->add(b, ipc->idkey, sizeof(ipc->idkey));
	if ( !token->set_element(token, IDtoken_key, b) )
		goto done;

	if ( !S->ipc->unlock(S->ipc) )
		goto done;
	retn = true;
	

 done:
	WHACK(b);
	memset(ipc->assertion_key, '\0', sizeof(ipc->assertion_key));	
	memset(ipc->assertion_id, '\0', sizeof(ipc->assertion_id));	
	memset(ipc->idhash, '\0', sizeof(ipc->idhash));	
	memset(ipc->idkey, '\0', sizeof(ipc->idkey));	

	if ( !retn )
		S->poisoned = true;
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

static _Bool get_id_key(CO(IDmgr, this), CO(Buffer, idhash), CO(Buffer, idkey))

{
	STATE(S);

	_Bool retn = false;

	struct IDmgr_ipc *ipc;


	if ( S->poisoned )
		goto done;
	if ( (idhash == NULL) || idhash->poisoned(idhash) )
		goto done;
	if ( (idkey == NULL) || idkey->poisoned(idkey) )
		goto done;


	ipc = S->ipc->get(S->ipc);
	if ( !S->ipc->lock(S->ipc) )
		goto done;

	ipc->valid = false;
	kill(ipc->pid, SIGUSR1);
	while ( !ipc->valid )
		continue;

	if ( !idhash->add(idhash, ipc->idhash, sizeof(ipc->idhash)) )
		goto done;
	if ( !idkey->add(idkey, ipc->idkey, sizeof(ipc->idkey)) )
		goto done;

	if ( !S->ipc->unlock(S->ipc) )
		goto done;
	retn = true;
	

 done:
	memset(ipc, '\0', sizeof(struct IDmgr_ipc));	

	if ( !retn )
		S->poisoned = true;
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
 * \param idhash	The Buffer object which contains the hash of
 *			the identity implementation.
 *
 * \param idkey		The Buffer object which contains the identity
 *			authenticator.
 *
 * \return		A true value is returned if the identity
 *			elements were successfuly conveyed to the
 *			consumer.
 */

static _Bool set_id_key(CO(IDmgr, this), CO(Buffer, idhash), CO(Buffer, idkey))

{
	STATE(S);

	_Bool retn = false;

	struct IDmgr_ipc *ipc;


	if ( S->poisoned )
		goto done;
	if ( (idhash == NULL) || idhash->poisoned(idhash) )
		goto done;
	if ( (idkey == NULL) || idkey->poisoned(idkey) )
		goto done;

	ipc = S->ipc->get(S->ipc);
	memcpy(ipc->idhash, idhash->get(idhash), idhash->size(idhash));
	memcpy(ipc->idkey, idkey->get(idkey), idkey->size(idkey));

	ipc->valid = true;
	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
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


	if ( S->ipc != NULL )
		WHACK(S->ipc);

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

	this->set_idtoken = set_idtoken;
	this->get_idtoken = get_idtoken;

	this->get_id_key = get_id_key;
	this->set_id_key = set_id_key;

	this->whack = whack;

	return this;
}
