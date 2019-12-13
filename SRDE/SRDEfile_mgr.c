/** \file
 * This file implements an File manager that manages implementation
 * objects on behalf of each File object that is instantiated in
 * enclave context.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEfile_mgr.h"


/** Pipe objects and buffers under external management. */
static _Bool SRDE_file_initialized = false;

static File SRDE_files[16];
static Buffer SRDE_buffers[16];


/**
 * Internal private function.
 *
 * This function manages the initialization of a File object to
 * implement functionality for an enclave based File object.  The
 * object instance slot is returned and stored in the enclave based object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_init(struct File_ocall *ocp)

{
	_Bool retn = false;

	unsigned int instance;

	Buffer bufr = NULL;

	File file = NULL;


	for (instance= 0; instance < sizeof(SRDE_files)/sizeof(File); \
		     ++instance) {
		if ( SRDE_files[instance] == NULL )
			break;
	}
	if ( instance == sizeof(SRDE_files)/sizeof(File) )
		ERR(goto done);


	INIT(HurdLib, File, file, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	ocp->instance	       = instance;
	SRDE_files[instance]   = file;
	SRDE_buffers[instance] = bufr;

	retn = true;


 done:
	if ( !retn ) {
		if ( (file = SRDE_files[instance]) != NULL ) {
			WHACK(file);
			SRDE_files[instance] = NULL;
		}
		if ( (bufr = SRDE_buffers[instance]) != NULL ) {
			WHACK(bufr);
			SRDE_buffers[instance] = NULL;
		}
	}
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements invocation of the ->open_ro method of the
 * File object on behalf of the same method of a File object running
 * in enclave context.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_open_ro(struct File_ocall *ocp)

{
	_Bool retn = false;

	File file = SRDE_files[ocp->instance];


	if ( !file->open_ro(file, ocp->filename) )
		ERR(goto done);

	retn = true;


 done:
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements invocation of the ->open_rw method of the
 * File object on behalf of the same method of a File object running
 * in enclave context.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_open_rw(struct File_ocall *ocp)

{
	_Bool retn = false;

	File file = SRDE_files[ocp->instance];


	if ( !file->open_rw(file, ocp->filename) )
		ERR(goto done);

	retn = true;


 done:
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements invocation of the ->slurp method of
 * the File object on behalf of the same method call from a File
 * object running in enclave context.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_slurp(struct File_ocall *ocp)

{
	_Bool retn = false;

	Buffer bufr = SRDE_buffers[ocp->instance];

	File file = SRDE_files[ocp->instance];


	bufr->reset(bufr);
	if ( !file->slurp(file, bufr) )
		ERR(goto done);

	ocp->bufr      = bufr->get(bufr);
	ocp->bufr_size = bufr->size(bufr);

	retn = true;


 done:
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements invocation of the ->slurp method of
 * the File object on behalf of the same method call from a File
 * object running in enclave context.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_write_Buffer(struct File_ocall *ocp)

{
	_Bool retn = false;

	Buffer bufr = SRDE_buffers[ocp->instance];

	File file = SRDE_files[ocp->instance];


	if ( !bufr->add(bufr, ocp->bufr, ocp->bufr_size) )
		ERR(goto done);

	if ( !file->write_Buffer(file, bufr) )
		ERR(goto done);

	retn = true;


 done:
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function manages the destruction of an SRDEquote object which
 * has been previously initialized.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdefile_whack(struct File_ocall *ocp)

{
	Buffer bufr = SRDE_buffers[ocp->instance];

	File file = SRDE_files[ocp->instance];

	bufr->whack(bufr);
	file->whack(file);

	SRDE_files[ocp->instance]   = NULL;
	SRDE_buffers[ocp->instance] = NULL;

	return;
}


/**
 * External function.
 *
 * This function is the external entry point for the enclave File OCALL
 * handler.
 *
 * \param ocp	A pointer to the structure which is used to marshall
 *		the data being submitted to and returned from the
 *		enclave OCALL handler.
 *
 * \return	If an error is encountered a non-zero value is
 *		returned to the caller.  Successful processing of
 *		the command returns a value of zero.
 */

int SRDEfile_mgr(struct File_ocall *ocp)

{
	int rc = -1;


	/* Verify on first call that object array is initialized. */
	if ( !SRDE_file_initialized ) {
		memset(SRDE_files, '\0', sizeof(SRDE_files));
		SRDE_file_initialized = true;
	}


	/* Verify ocall method type and instance specification. */
	if ( (ocp->ocall < 0) || (ocp->ocall >= File_END) )
		ERR(goto done);
	if ( ocp->instance >= sizeof(SRDE_files)/sizeof(File) )
		ERR(goto done);


	/* Vector execution to the appropriate method handler. */
	switch ( ocp->ocall ) {
		case File_init:
			srdefile_init(ocp);
			break;

		case File_open_ro:
			srdefile_open_ro(ocp);
			break;
		case File_open_rw:
			srdefile_open_rw(ocp);
			break;
		case File_open_wo:
			break;

		case File_read_Buffer:
			break;
		case File_slurp:
			srdefile_slurp(ocp);
			break;
		case File_read_String:
			break;
		case File_write_Buffer:
			srdefile_write_Buffer(ocp);
			break;

		case File_seek:
			break;
		case File_poisoned:
			break;
		case File_whack:
			srdefile_whack(ocp);
			break;

		case File_END:
			break;
	}
	rc = 0;


 done:
	return rc;
}
