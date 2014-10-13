/** \file
 * This file implements the methods for implementing transactions
 * against the identity generation daemon.  Communications is carried
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
#include <String.h>

#include "NAAAIM.h"
#include "IPC.h"
#include "IDengine.h"


/* State definition macro. */
#define STATE(var) CO(IDengine_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDengine_OBJID)
#error Object identifier not defined.
#endif


/** IDengine private state information. */
struct NAAAIM_IDengine_State
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
struct IDengine_ipc
{
	pid_t pid;

	_Bool valid;

	IDengine_identity idtype;

	char identifier[80];

	unsigned char identity[NAAAIM_IDSIZE];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDengine_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(IDengine_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDengine_OBJID;

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

static _Bool setup(CO(IDengine, this))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *idipc;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->create(S->ipc, "IDengine", sizeof(struct IDengine_ipc)) )
		goto done;

	idipc = S->ipc->get(S->ipc);
	memset(idipc, '\0', sizeof(struct IDengine_ipc));

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

static _Bool attach(CO(IDengine, this))

{
	STATE(S);

	_Bool retn = false;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->attach(S->ipc, "IDengine") )
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
 * This method implements an accessor method for obtaining an identity
 * from the identity generator.
 *
 * \param this		A pointer to the identity generation object which
 *			is requesting the identity.
 *
 * \param id		A Buffer object which will be loaded with the
 *			identity which has been retrieved from the IPC
 *			object.
 *
 * \return		A true value is returned if the query for the
 *			identity was successful.  A false value indicated
 *			the request failed.
 */

static _Bool get_identity(CO(IDengine, this), CO(Buffer, id))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc;

	Buffer b = NULL;


	if ( S->poisoned )
		goto done;

	/* Lock the IPC area and get the shared structure. */
	if ( !S->ipc->lock(S->ipc) )
		goto done;
	ipc = S->ipc->get(S->ipc);

	/* Set the identity request parameters. */
	ipc->idtype = IDengine_device;
	memset(ipc->identifier, '\0', sizeof(ipc->identifier));
	memset(ipc->identity,   '\0', sizeof(ipc->identity));

	/* Request processing of the structure. */
	ipc->valid = false;
	kill(ipc->pid, SIGUSR1);
	while ( !ipc->valid )
		continue;

	/* Unlock the processing area. */
	if ( !S->ipc->unlock(S->ipc) )
		goto done;

	/* Return the identity. */
	if ( !id->add(id, ipc->identity, sizeof(ipc->identity)) )
		goto done;
	retn = true;
	

 done:
	memset(ipc->identifier, '\0', sizeof(ipc->identifier));
	memset(ipc->identity,   '\0', sizeof(ipc->identity));

	WHACK(b);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements setting the the shared memory area with the
 * value of the generated identity.
 *
 * \param this		A pointer to the identity generation object which
 *			is setting the identity
 *
 * \param id		The Buffer object which contains the generated
 *			identity to be returned to the caller.
 *
 * \return		A true value is returned if the identity was
 *			successfully set.  A false value indicates that
 *			setting the identity failed.
 */

static _Bool set_identity(CO(IDengine, this), CO(Buffer, id))

{

	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc;


	if ( S->poisoned )
		goto done;

	ipc = S->ipc->get(S->ipc);

	memcpy(ipc->identity, id->get(id), sizeof(ipc->identity));
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
 * This method implements obtaining the parameters for the identity
 * which will be generated.
 *
 * \param this		A pointer to the identity generation object which
 *			is setting the identity
 *
 * \return		A true value is returned if the identity was
 *			successfully set.  A false value indicates that
 *			setting the identity failed.
 */

static _Bool get_id_info(CO(IDengine, this), IDengine_identity *type, \
			 CO(String, identifier))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc = S->ipc->get(S->ipc);


	*type = ipc->idtype;
	if ( !identifier->add(identifier, ipc->identifier) )
		goto done;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDengine object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(IDengine, this))

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
 * This function implements a constructor call for a IDengine object.
 *
 * \return	A pointer to the initialized IDengine.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDengine NAAAIM_IDengine_Init(void)

{
	auto Origin root;

	auto IDengine this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDengine);
	retn.state_size   = sizeof(struct NAAAIM_IDengine_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDengine_OBJID, &retn) )
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

	this->get_id_info = get_id_info;

	this->get_identity = get_identity;
	this->set_identity = set_identity;

	this->whack = whack;

	return this;
}
