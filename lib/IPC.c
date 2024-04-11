/** \file
 * This file contains the implementation methods for an object which
 * allows POSIX style shared memory regions to be created and
 * manipulated.  The object also provides access to a POSIX shared
 * memory semaphore for locking the shared region.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <Origin.h>
#include <HurdLib.h>
#include <String.h>

#include "NAAAIM.h"
#include "IPC.h"

/* State extraction macro. */
#define STATE(var) CO(IPC_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IPC_OBJID)
#error Object identifier not defined.
#endif


/** IPC private state information. */
struct NAAAIM_IPC_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Shared memory file descriptor. */
	int fd;

	/* Size of shared memory area. */
	off_t size;

	/* Pointer to shared memory area. */
	void *ptr;

	/* Pointer to the shared memory semaphore. */
	sem_t *sem;

	/* String object with the shared memory region name. */
	String name;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IPC_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(IPC_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IPC_OBJID;

	S->poisoned = false;

	S->fd   = 0;
	S->size	= 0;
	S->ptr	= MAP_FAILED;
	S->sem	= SEM_FAILED;
	S->name = NULL;
	

	return;
}


/**
 * External public method.
 *
 * This method implements creating a shared memory object.
 *
 * \param this	A pointer to the shared memory object which is to
 *		be created.
 *
 * \param path  A pointer to a null-terminated buffer containing
 *		the name of the object to be created.
 *
 * \param size	The size of the shared memory region to be created.
 *
 * \return	If an error is encountered during creation of the
 *		shared memory object a false value is returned.  A
 *		true value indicates the region was created and
 *		is available for use.
 */

static _Bool create(CO(IPC, this), CO(char *, path), off_t size)

{
	STATE(S);

	_Bool retn = false;

	int mode = O_RDWR | O_CREAT | O_EXCL,
	    perm = S_IRUSR | S_IWUSR;


	INIT(HurdLib, String, S->name, goto done);

	S->name->add(S->name, "/");
	if ( !S->name->add(S->name, path) )
		goto done;

	if ( (S->fd = shm_open(S->name->get(S->name), mode, perm)) == -1 )
		goto done;

	if ( ftruncate(S->fd, size) == -1 )
		goto done;
	if ( (S->ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, \
			    MAP_SHARED, S->fd, 0)) == MAP_FAILED )
		goto done;

	S->name->add(S->name, ".sem");
	S->sem = sem_open(S->name->get(S->name), mode, perm, 1);
	S->name->reset(S->name);

	S->name->add(S->name, "/");
	S->name->add(S->name, path);
	if ( S->sem == SEM_FAILED )
		goto done;

	S->size = size;
	retn	= true;

	
 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements attaching to shared memory object which has
 * been created by another process
 *
 * \param this	A pointer to the shared memory object which is to
 *		be opened.
 *
 * \param path  A pointer to a null-terminated buffer containing
 *		the name of the object to be created.
 *
 * \return	If an error is encountered during creation of the
 *		shared memory object a false value is returned.  A
 *		true value indicates the region was created and
 *		is available for use.
 */

static _Bool attach(CO(IPC, this), CO(char *, path))

{
	STATE(S);

	_Bool retn = false;

	int mode = O_RDWR;

	struct stat statbuff;

	String name = NULL;


	INIT(HurdLib, String, name, goto done);

	name->add(name, "/");
	if ( !name->add(name, path) )
		goto done;

	if ( (S->fd = shm_open(name->get(name), mode, 0)) == -1 )
		goto done;
	if ( fstat(S->fd, &statbuff) == -1 )
		goto done;
	S->size = statbuff.st_size;

	if ( (S->ptr = mmap(NULL, S->size, PROT_READ | PROT_WRITE, \
			    MAP_SHARED, S->fd, 0)) == MAP_FAILED )
		goto done;

	name->add(name, ".sem");
	S->sem = sem_open(name->get(name), mode);
	if ( S->sem == SEM_FAILED )
		goto done;

	retn = true;

	
 done:
	WHACK(name);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements writing the specified number of bytes to
 * the shared memory segment.
 *
 * \param this		A pointer to the object whose memory segment
 *			is to be written to.
 *
 * \param ptr		A pointer to the memory which is to be written
 *			to the shared memory segment.
 *
 * \param size		The number of bytes to be written to the segment.
 *
 * \param offset	The offset into the segment which is to
 *			be written.
 *
 * \return		If the memory is successfully writen a true
 *			value is returned.  A false value is used to
 *			that an error occurred when writing to the
 *			segment.
 */

static _Bool copy(CO(IPC, this), CO(unsigned char *, ptr), \
		  const off_t size, const off_t offset)

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( size > (S->size - offset) )
		goto done;

	memcpy(S->ptr, ptr, size);
	retn = true;


 done:
	if ( !retn ) 
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for obtaining the pointer
 * to the shared memory region.
 *
 * \param this		A pointer to the object whose memory segment
 *			is to be written to.
 *
 * \param ptr		A pointer to the memory which is to be written
 *			to the shared memory segment.
 *
 * \param size		The number of bytes to be written to the segment.
 *
 * \param offset	The offset into the segment which is to
 *			be written.
 *
 * \return		If the memory is successfully writen a true
 *			value is returned.  A false value is used to
 *			that an error occurred when writing to the
 *			segment.
 */

static void * get(CO(IPC, this))

{
	STATE(S);

	return S->ptr;
}


/**
 * External public method.
 *
 * This method implements a  method for requesting a lock on the
 * shared memory region.
 *
 * \param this		A pointer to the object whose memory segment
 *			is to be locked.
 *
 * \return		If the lock was successfully obtained a true
 *			value is returned.  If an error was
 *			encountered a false value is returned.
 */

static _Bool lock(CO(IPC, this))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( sem_wait(S->sem) == -1 ) {
		if ( errno == EINTR )
			retn = true;
	}
	else
		retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements a  method for unlocking a shared memory
 * region.
 *
 * \param this		A pointer to the object whose memory segment
 *			is to be unlock.
 *
 * \return		If the unlock was successfully obtained a true
 *			value is returned.  If an error was
 *			encountered a false value is returned.
 */

static _Bool unlock(CO(IPC, this))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( sem_post(S->sem) == 0 )
		retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}

	
/**
 * External public method.
 *
 * This method implements a destructor for a IPC object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(IPC, this))

{
	STATE(S);

	if ( S->ptr != MAP_FAILED )
		munmap(S->ptr, S->size);
	if ( S->sem != SEM_FAILED )
		sem_close(S->sem);

	if ( S->name != NULL ) {
		shm_unlink(S->name->get(S->name));

		S->name->add(S->name, ".sem");
		sem_unlink(S->name->get(S->name));

		WHACK(S->name);
	}

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a IPC object.
 *
 * \return	A pointer to the initialized IPC.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IPC NAAAIM_IPC_Init(void)

{
	auto Origin root;

	auto IPC this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IPC);
	retn.state_size   = sizeof(struct NAAAIM_IPC_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IPC_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->create = create;
	this->attach = attach;

	this->copy = copy;
	this->get  = get;

	this->lock   = lock;
	this->unlock = unlock;

	this->whack = whack;

	return this;
}
