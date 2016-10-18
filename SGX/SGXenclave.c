/** \file
 * This file contains the implementation of an object which is used to
 * manage a Software Guard Extension (SGX) enclave.  This object is
 * responsible for intereacting with the operating system provided
 * driver which provides access to the ENCLS privileged instructions
 * which are used to manipulate an enclave at the hardware level.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXmetadata.h"
#include "SGXloader.h"
#include "SGXenclave.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXenclave_OBJID)
#error Object identifier not defined.
#endif


/** SGXenclave private state information. */
struct NAAAIM_SGXenclave_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Enclave file descriptor. */
	int fd;

	/* The enclave loader object. */
	SGXloader loader;

	/* The SGX Enclave Control Structure. */
	struct SGX_secs secs;

	/* The enclave start address. */
	unsigned long int enclave_address;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXenclave_OBJID;


	S->poisoned = false;

	S->fd = -1;
	S->loader = NULL;

	memset(&S->secs, '\0', sizeof(struct SGX_secs));

	S->enclave_address = 0;

	return;
}


/**
 * External public method.
 *
 * This method opens the SGX interface device and loads the SGX
 * metadata and program segment data.
 *
 * \param this		A pointer to the object which is to hold the
 *			metadata.
 *
 * \param device	A pointer to a null-terminated buffer which
 *			contains the path specification for the SGX
 *			device node.
 *
 * \param enclave	A pointer to a null-terminated buffer which
 *			contains the path specification to the shared
 *			object implementation of the enclave.

 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave is ready for creation.
 */

static _Bool open_enclave(CO(SGXenclave, this), CO(char *, device), \
			  CO(char *, enclave))

{
	STATE(S);

	_Bool retn = false;


	/* Open the SGX device node. */
	if ( (S->fd = open(device, O_RDWR)) < 0 )
		ERR(goto done);

	/* Load the SGX metadata and shared object file. */
	INIT(NAAAIM, SGXloader, S->loader, ERR(goto done));
	if ( !S->loader->load_secs(S->loader, enclave, &S->secs) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method creates the SGX enclave based on information in the
 * SGX Enclave Control Structure (SECS).
 *
 * \param this		A pointer to the object representing the
 *			enclave to be created.
 *
 * \return	If an error is encountered while creating the enclave
 *		a false value is returned.   A true value indicates the
 *		enclave was successfully created.
 */

static _Bool create_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;

	struct SGX_create_param create_param;


	/* Verify object status and ability to create enclave. */
	if ( S->poisoned )
		ERR(goto done);


	/* Create the enclave based on the SECS parameters. */
	create_param.secs = &S->secs;
	create_param.addr = 0;

	fprintf(stdout, "Size: 0x%lx\n", S->secs.size);
	fprintf(stdout, "Using secs xfrm: 0x%lx\n", S->secs.xfrm);
	if ( ioctl(S->fd, SGX_IOCTL_ENCLAVE_CREATE, &create_param) < 0 )
		ERR(goto done);
	fprintf(stdout, "OK, start adress=0x%0lx\n", create_param.addr);
	S->enclave_address = create_param.addr;

	retn = true;


 done:

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for an SGXenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXenclave, this))

{
	STATE(S);

	struct SGX_destroy_param destroy_param;


	if ( S->enclave_address != 0 ) {
		destroy_param.addr = S->enclave_address;
		ioctl(S->fd, SGX_IOCTL_ENCLAVE_DESTROY, &destroy_param);
	}

	if ( S->fd != -1 )
		close(S->fd);

	WHACK(S->loader);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXenclave object.
 *
 * \return	A pointer to the initialized SGXenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXenclave NAAAIM_SGXenclave_Init(void)

{
	auto Origin root;

	auto SGXenclave this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXenclave);
	retn.state_size   = sizeof(struct NAAAIM_SGXenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXenclave_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->open_enclave   = open_enclave;
	this->create_enclave = create_enclave;

	this->whack = whack;

	return this;
}
