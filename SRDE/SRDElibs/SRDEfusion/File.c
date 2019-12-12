/** \file
 * This file contains the implementation of an object that exposes
 * operations supplied by the HurdLib/File object in standard userspace
 * to enclave context.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
/* Size of I/O buffer. */
#define FILE_BUFSIZE 4069

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include "HurdLib.h"
#include "Origin.h"
#include "Buffer.h"
#include "String.h"
#include "File.h"

#include <SRDE.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>
#include <SRDEfile_mgr.h>


/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_File_OBJID)
#error Object identifier not defined.
#endif

/* State initialization macro. */
#define STATE(var) CO(File_State, var) = this->state


/** HurdLib_File private state information. */
struct HurdLib_File_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Untrusted instance. */
	unsigned int instance;

	/* Error code. */
	int error;
};


/*
 * The Intel SDK version of this function is being used until the
 * loader initialization issue is addressed.
 */
static _Bool SRDEfusion_untrusted_region(void *ptr, size_t size)

{
	_Bool retn = false;

	if ( ptr == NULL )
		goto done;
	if ( sgx_is_within_enclave(ptr, size) )
		goto done;
	retn = true;
 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int File_ocall(struct File_ocall *ocall)

{
	_Bool file_open,
	      retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct File_ocall);

	struct File_ocall *ocp = NULL;


	/* Set size of arena for file open operations. */
	file_open = ((ocall->ocall == File_open_ro) || \
		(ocall->ocall == File_open_rw)	    || \
		(ocall->ocall == File_open_wo));
	if ( file_open ) {
		if ( SRDEfusion_untrusted_region(ocall->filename, \
						 ocall->filename_size) )
			goto done;
		arena_size += ocall->filename_size;
	}


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == File_write_Buffer ) {
		if ( SRDEfusion_untrusted_region(ocall->bufr, \
						 ocall->bufr_size) )
			goto done;
		arena_size += ocall->bufr_size;
	}

	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena for for file open. */
	if ( file_open ) {
		memcpy(ocp->arena, ocp->filename, ocall->filename_size);
		ocp->filename = (char *) ocp->arena;
	}


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == File_write_Buffer ) {
		memcpy(ocp->arena, ocall->bufr, ocall->bufr_size);
		ocp->bufr = ocp->arena;
	}


	/* Call the SRDEfile manager. */
	if ( (status = sgx_ocall(SRDEFUSION_OCALL2, ocp)) == 0 ) {
		retn = true;

		if ( ocall->ocall == File_slurp ) {
			ocall->bufr	 = ocp->bufr;
			ocall->bufr_size = ocp->bufr_size;
		}
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the HurdLib_File_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const File_State const S) {

	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_File_OBJID;

	S->poisoned = false;
	S->instance = -1;
	S->error    = 0;

	return;
}


/**
 * External public method.
 *
 * This method implements opening a file in read-only mode.
 *
 * \param this	A pointer to the object representing the file
 *		to be opened.
 *
 * \param fname	The pathname of the file to be opened.
 *
 * \return	A boolean value is returned to indicate the status of
 *		the file open.  A boolean indicates an error
 *		condition.
 */

static _Bool open_ro(CO(File, this), CO(char *, fname))

{
	STATE(S);

	_Bool retn = false;

	struct File_ocall ocall;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct File_ocall));

	ocall.ocall    = File_open_ro;
	ocall.instance = S->instance;

	ocall.filename	    = (char *) fname;
	ocall.filename_size = strlen(fname) + 1;

	if ( File_ocall(&ocall) != 0 )
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
 * This method implements opening a file in read/write mode.
 *
 * \param this	A pointer to the object representing the file
 *		to be opened.
 *
 * \param fname	The pathname of the file to be opened.
 *
 * \return	A boolean value is returned to indicate the status of
 *		the file open.  A boolean indicates an error
 *		condition.
 */

static _Bool open_rw(CO(File, this), CO(char *, fname))

{
	STATE(S);

	_Bool retn = false;

	struct File_ocall ocall;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct File_ocall));

	ocall.ocall    = File_open_rw;
	ocall.instance = S->instance;

	ocall.filename	    = (char *) fname;
	ocall.filename_size = strlen(fname) + 1;

	if ( File_ocall(&ocall) != 0 )
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
 * This method implements opening a file in write-only mode.
 *
 * \param this	A pointer to the object representing the file
 *		to be opened.
 *
 * \param fname	The pathname of the file to be opened.
 *
 * \return	A boolean value is returned to indicate the status of
 *		the file open.  A boolean indicates an error
 *		condition.
 */

static _Bool open_wo(const File const this, const char * const fname)

{
	return false;
}


/**
 * External public method.
 *
 * This method implements reading the contents of a file from the
 * current file pointer.   The amount read is designated by the count
 * arguement.  If the count arguement is zero the file is read until an
 * end-of-file indication is given.  Otherwise the number of bytes
 * bytes is read.
 *
 * \param this	A pointer to the object which the file is to be
 *		read into.
 *
 * \param bufr	The buffer object which is to receive the contents of
 *		the file.
 *
 * \param cnt	The number of bytes read interpreted as noted in the
 *		function description.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the read was successful.
 */

static _Bool read_Buffer(const File const this, const Buffer const bufr, \
			 size_t cnt)

{
	return false;
}


/**
 * External public method.
 *
 * This method implements reading the entire contents of a file into a
 * a Buffer object.
 *
 * \param this	A pointer to the object which the file is to be
 *		read into.
 *
 * \param bufr	The object that the file contents is to be read into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the read was successful.  A false value indicates the
 *		read failed and the object is poisoned.  A true value
 *		indicates the file contents was read and the Buffer
 *		object was populated with the contents.
 */

static _Bool slurp(CO(File, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	struct File_ocall ocall;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct File_ocall));

	ocall.ocall    = File_slurp;
	ocall.instance = S->instance;

	if ( File_ocall(&ocall) != 0 )
		ERR(goto done);

	if ( !bufr->add(bufr, ocall.bufr, ocall.bufr_size) )
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
 * This method implements reading a String object from a file.  The
 * delimiter of a string object is up to and including a newline
 * character.  The newline is replaced with a null character.
 *
 * \param this	A pointer to the object representing the file from which
 *		the String is to be read.
 *
 * \param str	The String object which is to be populated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the read was successful.
 */

static _Bool read_String(CO(File, this), CO(String, str))

{
	return false;
}


/**
 * External public method.
 *
 * This method implements writing the contents of a buffer to the
 * opened file.
 *
 * \param this	A pointer to the object being written to.
 *
 * \return	A boolean value is returned to indicate the status
 *		of the write.  A false value indicates an error
 *		was experienced.
 */

static _Bool write_Buffer(CO(File, this), CO(Buffer, buffer))

{
	STATE(S);

	_Bool retn = false;

	struct File_ocall ocall;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct File_ocall));

	ocall.ocall    = File_write_Buffer;
	ocall.instance = S->instance;

	ocall.bufr	= buffer->get(buffer);
	ocall.bufr_size = buffer->size(buffer);

	if ( File_ocall(&ocall) != 0 )
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
 * This method implements seeking to specific locations in a file.
 *
 * \param this	A pointer to the object whose file position is being
 *		changed.
 *
 * \param locn	The position in the file to be seeked to.  Seeking
 *		to the end of the file is requested by specifying a
 *		value of -1.
 *
 * \return	The location in the file after the seek operation has
 *		completed.  If an error was encountered the value of -1
 *		is returned.
 */

static off_t seek(const File const this, off_t locn)

{
	return false;
}


/**
 * External public method.
 *
 * This method implements the reset of a file object.  The filehandle
 * is closed which prepares the object for re-use.  This function also
 * resets the error status on the object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void reset(CO(File, this))

{
	return;
}


/**
 * External public method.
 *
 * This method returns the status of the object.
 *
 * \param this	The object whose status is being requested.
 */
static _Bool poisoned(CO(File, this))

{
	STATE(S);

	return S->poisoned;
}


/**
 * External public method.
 *
 * This method implements a destructor for a HurdLib_File object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(File, this))

{
	STATE(S);

	struct File_ocall ocall;


	/* Setup and call OCALL for whack method.. */
	memset(&ocall, '\0', sizeof(struct File_ocall));

	ocall.ocall    = File_whack;
	ocall.instance = S->instance;
	File_ocall(&ocall);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a HurdLib_File object.
 *
 * \return	A pointer to the initialized HurdLib_File.  A null value
 *		indicates an error was encountered in object generation.
 */

extern File HurdLib_File_Init(void)

{
	Origin root;

	File this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct File_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct HurdLib_File);
	retn.state_size   = sizeof(struct HurdLib_File_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_File_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct File_ocall));
	ocall.ocall = File_init;
	if ( File_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->open_ro	= open_ro;
	this->open_rw	= open_rw;
	this->open_wo	= open_wo;

	this->read_Buffer	= read_Buffer;
	this->slurp		= slurp;
	this->read_String	= read_String;
	this->write_Buffer	= write_Buffer;

	this->seek	= seek;

	this->reset	= reset;
	this->poisoned	= poisoned;
	this->whack	= whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
