/** \file
 * This file implements an object which allows retrieval of the status
 * of the installed software.
 *
 * This object currently obtains the software measurement from the
 * binary runtime file which is in the following pre-ng format with
 * byte counts in parenthesis:
 *
 *	PCR(4)
 *	TEMPLATE(20)
 *	TEMPLATE_NAME_SIZE(4)
 *	TEMPLATE_NAME(TEMPLATE_NAME_SIZE)
 *	FILE_HASH(20)
 *	TEMPLATE_FILE_SIZE(4)
 *	TEMPLATE_FILE(TEMPLATE_FILE_SIZE)
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local dfines. */
/* The pseudo-file containing the measurement count. */
#if 0
#define LOCATION "."
#else
#define LOCATION "/sys/kernel/security/ima"
#endif
#define MEASUREMENTS	   LOCATION"/binary_runtime_measurements"
#define MEASUREMENTS_COUNT LOCATION"/runtime_measurements_count"

#define IMA_HASH_SIZE 20


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "SoftwareStatus.h"

#define STATE(var) CO(SoftwareStatus_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SoftwareStatus_OBJID)
#error Object identifier not defined.
#endif


/** SoftwareStatus private state information. */
struct NAAAIM_SoftwareStatus_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Count of measurements. */
	uint32_t count;

	/* File object used to read the measurement file. */
	File file;

	/* Hash of template hashes. */
	Sha256 template_hash;

	/* Hash of file hashes. */
	Sha256 file_hash;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SoftwareStatus_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const SoftwareStatus_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SoftwareStatus_OBJID;

	S->poisoned = false;
	S->count    = 0;
	S->file	    = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements opening of the pseudo-file which contains the
 * binary version of the runtime measurements.
 *
 * \param this	The object being used to calculate the system measurement
 *		state.
 *
 * \return	If an error is encountered opening either the measurement
 *		count file or the binary measurement file itself a false
 *		value is returned.  A true value indicates the object
 *		was loaded with the measurement count and a valid
 *		file connection.
 */

static bool open(CO(SoftwareStatus, this))

{
	STATE(S);

	_Bool retn = false;

	long int count;

	String incnt = NULL;


	if ( S->poisoned )
		goto done;

	INIT(HurdLib, String, incnt, goto done);
	INIT(HurdLib, File, S->file, goto done);

	/* Get the number of runtime measurements. */
	if ( !S->file->open_ro(S->file, MEASUREMENTS_COUNT) )
		goto done;
	if ( !S->file->read_String(S->file, incnt) )
		goto done;
	S->file->reset(S->file);

	count = strtol(incnt->get(incnt), NULL, 10);
	if ( errno == ERANGE )
		goto done;
	if ( count < 0 )
		goto done;
	S->count = count;


	/* Open the measurement file. */
	if ( !S->file->open_ro(S->file, MEASUREMENTS) )
		goto done;

	retn = true;


 done:
	WHACK(incnt);
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private function.
 *
 * This method is responsible for reading a single record from the
 * binary measurement file.
 *
 * \param this			A pointer to the measurement object being
 *				read.
 *
 * \param tmp			A buffer object which will be used to
 *				sequence past unused elements of the
 *				measurement record.
 *
 * \param template_hash		A Buffer object which will be loaded with
 *				the binary value of the template hash.
 *
 * \param file_hash		A buffer object which will be loaded with
 *				the binary value of the file contents hash.
 *
 * \return			If an error is encountered while reading
 *				the record a false value is returned.  If
 *				the read of the measurement record
 *				succeeds a true value is returned.
 */

static bool _read_measurement(CO(File, file), CO(Buffer, tmp), \
			      CO(Buffer, template_hash), CO(Buffer, file_hash))

{
	uint32_t length;
	

	/* Read past the PCR value. */
	file->read_Buffer(file, tmp, sizeof(uint32_t));
	tmp->reset(tmp);

	/* Read the template hash. */
	file->read_Buffer(file, template_hash, IMA_HASH_SIZE);

	/* Read the template description. */
	file->read_Buffer(file, tmp, sizeof(uint32_t));
	length = *((uint32_t *) tmp->get(tmp));
	file->read_Buffer(file, tmp, length);
	tmp->reset(tmp);

	/* Read the file contents hash. */
	file->read_Buffer(file, file_hash, IMA_HASH_SIZE);

	/* Read the template. */
	file->read_Buffer(file, tmp, sizeof(uint32_t));
	length = *((uint32_t *) tmp->get(tmp));
	file->read_Buffer(file, tmp, length);
	tmp->reset(tmp);


	if ( file->poisoned(file) ||			\
	     template_hash->poisoned(template_hash) ||	\
	     file_hash->poisoned(file_hash) )
		return false;

	return true;
}


/**
 * External public method.
 *
 * This method implements a request to take the current measurement of
 * the software status of the system.
 *
 * \param this	The object being used to request the measurement.
 *
 * \return	If an error is encountered reading the measurement file
 *		a false value is returned.  A true value indicates the
 *		measurement was successfully made.
 */

static bool measure(CO(SoftwareStatus, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t cnt = S->count;

	Buffer tmp	     = NULL,
	       template_hash = NULL,
	       file_hash     = NULL;


	INIT(HurdLib, Buffer, tmp, goto done);
	INIT(HurdLib, Buffer, template_hash, goto done);
	INIT(HurdLib, Buffer, file_hash, goto done);

	/* Read past the boot aggregate measurement. */
	if ( !_read_measurement(S->file, tmp, template_hash, file_hash) )
		goto done;
	template_hash->reset(template_hash);
	file_hash->reset(file_hash);
	--cnt;

	/* Read and accumulate the subsequent measurements. */
	while ( cnt > 0 ) {
		if ( !_read_measurement(S->file, tmp, template_hash,\
					file_hash) )
			goto done;

		if ( !S->template_hash->add(S->template_hash, template_hash) )
			goto done;
		if ( !S->file_hash->add(S->file_hash, file_hash) )
			goto done;

		template_hash->reset(template_hash);
		file_hash->reset(file_hash);
		--cnt;
	}

	if ( !S->file_hash->compute(S->file_hash) )
		goto done;
	if ( !S->template_hash->compute(S->template_hash) )
		goto done;

	S->file->reset(S->file);
	retn = true;


 done:
	WHACK(tmp);
	WHACK(template_hash);
	WHACK(file_hash);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a request to generate a derived software
 * status measurement.  This is currently used by the SGX version
 * of the object to generate a nonce derived measurement of the
 * enclave.
 *
 * \param this	The object being used to request the measurement.
 *
 * \param nonce	The object containing the nonce used to derive the
 *		software measurement.
 *
 * \return	If an error is encountered reading the measurement file
 *		a false value is returned.  A true value indicates the
 *		measurement was successfully made.
 */

static _Bool measure_derived(CO(SoftwareStatus, this), CO(uint8_t *, nonce))

{
	return true;
}


/**
 * External public method.
 *
 * This method implements an accessor for returning a Buffer object which
 * holds the value of the template hash.
 *
 * \param this	A pointer to the object whose template hash is to be
 *		returned.
 *
 * \return	The Buffer object holding the template hash.
 */

static Buffer get_template_hash(CO(SoftwareStatus, this))

{
	STATE(S);

	return S->template_hash->get_Buffer(S->template_hash);
}


/**
 * External public method.
 *
 * This method implements an accessor for returning a Buffer object which
 * holds the value of the file contents hash.
 *
 * \param this	A pointer to the object whose file contents hash is to be
 *		returned.
 *
 * \return	The Buffer object holding the file contents hash.
 */

static Buffer get_file_hash(CO(SoftwareStatus, this))

{
	STATE(S);

	return S->file_hash->get_Buffer(S->file_hash);
}
		
		
/**
 * External public method.
 *
 * This method implements a destructor for a SoftwareStatus object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const SoftwareStatus const this)

{
	STATE(S);

	WHACK(S->file);
	WHACK(S->template_hash);
	WHACK(S->file_hash);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a SoftwareStatus object.
 *
 * \return	A pointer to the initialized SoftwareStatus.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SoftwareStatus NAAAIM_SoftwareStatus_Init(void)

{
	auto Origin root;

	auto SoftwareStatus this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SoftwareStatus);
	retn.state_size   = sizeof(struct NAAAIM_SoftwareStatus_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SoftwareStatus_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
        if ( (this->state->template_hash = NAAAIM_Sha256_Init()) == NULL ) {
                root->whack(root, this, this->state);
                return NULL;
        }
	if ( (this->state->file_hash = NAAAIM_Sha256_Init()) == NULL ) {
		WHACK(this->state->template_hash);
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->open    = open;

	this->measure	      = measure;
	this->measure_derived = measure_derived;

	this->get_template_hash = get_template_hash;
	this->get_file_hash	= get_file_hash;

	this->whack = whack;

	return this;
}
