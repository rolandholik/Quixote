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
#include "SGXenclave.h"
#include "SGXloader.h"
#include "SGXsigstruct.h"


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

	/* Enclave page count .*/
	uint64_t page_cnt;
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
	S->page_cnt	   = 0;

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
 * \param debug		A boolean flag used to indicate whether or not
 *			the enclave is to be initialized in debug mode.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave is ready for creation.
 */

static _Bool open_enclave(CO(SGXenclave, this), CO(char *, device), \
			  CO(char *, enclave), _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Open the SGX device node. */
	if ( (S->fd = open(device, O_RDWR)) < 0 )
		ERR(goto done);

	/* Load the SGX metadata and shared object file. */
	INIT(NAAAIM, SGXloader, S->loader, ERR(goto done));
	if ( !S->loader->load_secs(S->loader, enclave, &S->secs, debug) )
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
 * This method loads a previously created enclave using the contents
 * of the shared enclave image.
 *
 * \param this		A pointer to the object representing the enclave
 *			which is being loaded.
 *
 * \return	If an error is encountered while loading the enclave
 *		a false value is returned.   A true value indicates the
 *		enclave was successfully loaded.
 */

static _Bool load_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Load the TEXT portion of the enclave. */
	if ( !S->loader->load_segments(S->loader, this) )
		ERR(goto done);

	/* Load the layout portion of the enclave. */
	if ( !S->loader->load_layouts(S->loader, this) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method initializes an enclave which has previously been
 * loaded.  This initialization step is the final step in preparing an
 * enclave for execution.  For a non-launch enclave an initialization
 * token generated by the launch token is needed for the
 * initialization process.
 *
 * \param this		A pointer to the object representing the enclave
 *			which will be initialized.
 *
 * \return		If an error is encountered while initializing
 *			the enclave a false value is returned.  A true
 *			value indicates the enclave was successfully
 *			loaded.
 */

static _Bool init_enclave(CO(SGXenclave, this))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct SGX_sigstruct sigstruct;

	struct SGX_einittoken einittoken;

	struct SGX_init_param init_param;

	SGXsigstruct LEsigstruct = NULL;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Get the signature structure from the enclave metadata and
	 * initialize the EINIT token.
	 */
	if ( !S->loader->get_sigstruct(S->loader, &sigstruct) )
		ERR(goto done);

	memset(&einittoken, '\0', sizeof(struct SGX_einittoken));


	/* Populate the initialization control structure. */
	memset(&init_param, '\0', sizeof(struct SGX_init_param));
	init_param.addr	      = S->enclave_address;
	init_param.einittoken = &einittoken;

	INIT(NAAAIM, SGXsigstruct, LEsigstruct, ERR(goto done));
	if ( !LEsigstruct->get_LE(LEsigstruct, &sigstruct) )
		ERR(goto done);
	init_param.sigstruct  = &sigstruct;

	if ( (rc = ioctl(S->fd, SGX_IOCTL_ENCLAVE_INIT, &init_param)) != 0 )
		ERR(goto done);

	retn = true;


 done:
	WHACK(LEsigstruct);

	return retn;
}


/**
 * External public method.
 *
 * This method adds a page to the enclave.  The final arguement to the
 * method call specifies whether or not the enclave measurement is
 * extended with the contents of the page.
 *
 * The nature of the flags which define whether or not the contents of
 * the page should be extended into the enclave measurement is
 * confusing.  The Intel SDK assigns meaning to two bit positions in
 * the flags arguement.  One bit indicates the page is to be added and
 * the second indicates whether the contents of the page should be
 * extended into the enclave measurement.
 *
 * In contrast the kernel driver only acts on the page addition flag
 * and treats this as an indication the contents of the page is NOT to
 * be extended into the enclave measurement.
 *
 * \param this		A pointer to the object representing the enclave
 *			which is having a page added to it.
 *
 * \param page		A pointer to a memory buffer containing the
 *			page which is to be added.
 *
 * \param secinfo	A pointer to the data structure which defines
 *			the security characteristics of the page which
 *			is to be added.
 *
 * \param flags		A bit encoding of the flags which define the type
 *			of page insertion which will be carried out.
 *
 * \return	If an error is encountered while adding the page a false
 *		value is returned.   A true value indicates the
 *		enclave was successfully loaded.
 */

static _Bool add_page(CO(SGXenclave, this), CO(uint8_t *, page), \
		      struct SGX_secinfo *secinfo, const uint8_t flags)

{
	STATE(S);

	_Bool retn = false;

	struct SGX_add_param add_param;


	/* Verify object. */
	if ( S->poisoned )
		ERR(goto done);


	/* Initialize the page addition parameters and add page. */
	memset(&add_param, '\0', sizeof(add_param));
	add_param.addr	    = S->enclave_address + (4096 * S->page_cnt);
	add_param.user_addr = (unsigned long) page;
	add_param.secinfo   = secinfo;
	if ( !(flags & SGX_PAGE_EXTEND) )
		add_param.flags |= SGX_PAGE_ADD;

	if ( ioctl(S->fd, SGX_IOCTL_ENCLAVE_ADD_PAGE, &add_param) < 0 ) {
		perror("page add error");
		ERR(goto done);
	}
	S->page_cnt += 1;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method adds a 'hole' in the enclave.  Its implementation was
 * inspired by the fact that the Intel SDK uses a sparse virtual
 * memory map to implement 'guard' pages between the memory arenas.
 *
 * A 'hole' is a page in the enclave which does not have its virtual
 * address mapped to a page in the Enclave Page Cache.  References to
 * any addresses in this page range generate the equivalent of a page
 * fault which generates an asynchronous enclave exit event.
 *
 * \param this	The object representing the enclave which is to have
 *		a hole punched into it.

 * \return	If an error is encountered while adding the hole a false
 *		value is returned.   A true value indicates the
 *		hole was successfully punched.
 */

static _Bool add_hole(CO(SGXenclave, this))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		ERR(return false);

	++S->page_cnt;

	return true;
}


/**
 * External public method.
 *
 * This method returns the current relative virtual address of the
 * enclave represented by this object.  The relative virtual address
 * is the byte displacement from the start of the enclave to the
 * next page which will be added to enclave.
 *
 * \param this	The object representing the enclave whose
 *		a hole punched into it.

 * \return	The functions returns the current size of the enclave
 *		which is the allocated page count of the enclave
 *		multipled by the page size of the enclave.
 */

static unsigned long int get_address(CO(SGXenclave, this))

{
	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		ERR(return false);

	return S->page_cnt * 4096;
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
	this->load_enclave   = load_enclave;
	this->init_enclave   = init_enclave;

	this->add_page	  = add_page;
	this->add_hole	  = add_hole;
	this->get_address = get_address;

	this->whack = whack;

	return this;
}
