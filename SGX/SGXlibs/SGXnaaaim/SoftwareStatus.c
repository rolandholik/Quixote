/** \file
 * This file implements an object which is meant to provide equivalent
 * functionality to the untrusted code.  Ultimately in a fully
 * measured environment this will be a bridge function which accesses
 * un untrusted implementation to return the desired data.
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
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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

#define TEMPLATE_HASH "da9502abf3222a8241657f6ef4535ac75906195b969a0f5f53fa6c02e3966e1a"
#define FILE_HASH "770e23e6f6be5129fa1b765001d50cf8f960d5c31557131bb96306e64f600e9b"


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

#include <SGX.h>
#include <SGXfusion.h>

#include "NAAAIM.h"
#include "SoftwareStatus.h"
#include "SHA256.h"


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

	/* Hash of template hashes. */
	Buffer template_hash;

	/* Hash of file hashes. */
	Buffer file_hash;
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
	_Bool retn = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a request to take the current measurement of
 * an enclave's software status.  It implements this by requesting a
 * NULL hardware report.
 *
 * \param this	The object being used to request the measurement.
 *
 * \return	If an error is encountered while measuring the enclave
 *		a false value is returned.  A true value indcates
 *		the measurement was successfully taken.
 */

static _Bool measure(CO(SoftwareStatus, this))

{
	STATE(S);

	int rc;

	_Bool retn = false;

	char report_data[64] __attribute__((aligned(128)));

	uint8_t keydata[16] __attribute__((aligned(128)));

	struct SGX_targetinfo target;

	struct SGX_report __attribute__((aligned(512))) report;

	struct SGX_keyrequest keyrequest;

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;


	/* Request a report on the current enclave. */
	memset(&target, '\0', sizeof(struct SGX_targetinfo));
	memset(&report, '\0', sizeof(struct SGX_report));
	memset(report_data, '\0', sizeof(report_data));
	enclu_ereport(&target, &report, report_data);


	/* Request the key. */
	memset(keydata, '\0', sizeof(keydata));
	memset(&keyrequest, '\0', sizeof(struct SGX_keyrequest));

	keyrequest.keyname   = SGX_KEYSELECT_SEAL;
	keyrequest.keypolicy = SGX_KEYPOLICY_SIGNER;
	memcpy(keyrequest.keyid, report.body.mr_enclave.m, \
	       sizeof(keyrequest.keyid));

	if ( (rc = enclu_egetkey(&keyrequest, keydata)) != 0 ) {
		fprintf(stdout, "EGETKEY return: %d\n", rc);
		goto done;
	}


	/* Derive and save the key. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, keydata, sizeof(keydata)) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	if ( !S->template_hash->add_Buffer(S->template_hash, b) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sha256);

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
	STATE(S);

	int rc;

	_Bool retn = false;

	char report_data[64] __attribute__((aligned(128)));

	uint8_t keydata[16] __attribute__((aligned(128)));

	struct SGX_targetinfo target;

	struct SGX_report __attribute__((aligned(512))) report;

	struct SGX_keyrequest keyrequest;

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;


	/* Request a report on the current enclave. */
	memset(&target, '\0', sizeof(struct SGX_targetinfo));
	memset(&report, '\0', sizeof(struct SGX_report));
	memset(report_data, '\0', sizeof(report_data));
	enclu_ereport(&target, &report, report_data);


	/* Request the key. */
	memset(keydata, '\0', sizeof(keydata));
	memset(&keyrequest, '\0', sizeof(struct SGX_keyrequest));

	keyrequest.keyname    = SGX_KEYSELECT_SEAL;
	keyrequest.keypolicy  = SGX_KEYPOLICY_ENCLAVE;
	keyrequest.miscselect = report.body.miscselect;
	keyrequest.attributes = report.body.attributes;
	memcpy(keyrequest.keyid, nonce, sizeof(keyrequest.keyid));

	if ( (rc = enclu_egetkey(&keyrequest, keydata)) != 0 ) {
		fprintf(stdout, "EGETKEY return: %d\n", rc);
		goto done;
	}


	/* Derive and save the key. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, keydata, sizeof(keydata)) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	if ( !S->template_hash->add_Buffer(S->template_hash, b) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(bufr);
	WHACK(sha256);

	return retn;
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

	return S->template_hash;
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

	return S->file_hash;
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
        if ( (this->state->template_hash = HurdLib_Buffer_Init()) == NULL ) {
                root->whack(root, this, this->state);
                return NULL;
        }
	if ( (this->state->file_hash = HurdLib_Buffer_Init()) == NULL ) {
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
