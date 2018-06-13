/** \file
 * This file contains the implementation of an ECALL which provides a
 * remote management interface for an ISOidentity modeling enclave.  The
 * management ECALL initiates a PossumPipe connection listening on
 * a specified port.  Commands received on this port are executed against
 * the model running in the enclave with results returned to the caller.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <NAAAIM.h>
#include <PossumPipe.h>
#include <IDtoken.h>
#include <Ivy.h>

#include <SGX.h>
#include <SGXfusion.h>

#include "ISOidentity-interface.h"


/**
 * The device identity to be used.
 */
size_t Identity_size	= 0;
unsigned char *Identity = NULL;


/**
 * The device verified for the communication counter-party.
 */
size_t Verifier_size	= 0;
unsigned char *Verifier = NULL;


/**
 * The seed time for the time() function.
 */
static time_t Current_Time;


/**
 * Global function.
 *
 * The following function implements a function for returning something
 * that approximates monotonic time for the enclave.  The expection
 * is for an ECALL to set the Current_Time variable to some initial
 * value, typically when the ECAL was made.  Each time this function
 * is called the value is incremented so a value which roughly
 * approximately monotonic time is available.
 *
 * For the purposes of a PossumPiple this is sufficient since the
 * replay defense is based on the notion that an endpoint will never
 * see an OTEDKS key repeated.
 *
 * \param timeptr	If this value is non-NULL the current time
 *			value is copied into the location specified by
 *			this pointer.
 *
 * \return		The current value of the enclave time variable
 *			is returned to the caller.
 */

time_t time(time_t *timeptr)

{
	if ( timeptr != NULL )
		*timeptr = Current_Time;

	return Current_Time++;
}


/**
 * ECALL 10
 *
 * This function implements the ECALL entry point for the ISOidentity
 * management interface.
 *
 * \param debug		A flag which specifies whether or not the
 *			PossumPipe object is to be run in debug mode.
 *
 * \param port		The port number the management enclave is to
 *			listen on.
 *
 * \param current_time	The time to be used as the seed for intra-enclave
 *			time.
 *
 * \param spid_key	A pointer to the Service Provider ID (SPID)
 *			encoded in ASCII hexadecimal form.
 *
 * \param id_size	The size of the buffer containing the
 *			identity token.
 *
 * \param identity	A pointer to a buffer containing the identity
 *			token which will identify the enclave.
 *
 * \param vfy_size	The size of the buffer containing the identity
 *			verifier that will be used.
 *
 * \param verifier	A pointer to a buffer containing the identity
 *			verifier that will be used.
 *
 * \return	A boolean value is used to indicate the status of
 *		the management interface.  A false value indicates an
 *		error was encountered while setting up or operating
 *		the interface.  A true value indicates the management
 *		interface had executed successfully.
 */

_Bool manager(_Bool debug, int port, time_t current_time, char *spid_key, \
	      size_t id_size, unsigned char *identity, size_t vfy_size,   \
	      unsigned char *verifier)

{
	_Bool retn = false;

	PossumPipe pipe = NULL;

	Buffer spid = NULL,
	       bufr = NULL;


	/* Initialize the time. */
	Current_Time = current_time;

	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) )
		ERR(goto done);


	/* Stash the identity token and verifier buffer descriptions. */
	Identity      = identity;
	Identity_size = id_size;

	Verifier      = verifier;
	Verifier_size = vfy_size;


	/* Start the management interface. */
	fprintf(stdout, "ISOidentity manager: port=%d\n", port);

	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( debug )
		pipe->debug(pipe, debug);

	if ( !pipe->init_server(pipe, NULL, port, false) )
		ERR(goto done);

	if ( !pipe->accept_connection(pipe) ) {
		fputs("Error accepting connection.\n", stderr);
		ERR(goto done);
	}

	if ( !pipe->start_host_mode(pipe, spid) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}


 done:
	WHACK(pipe);
	WHACK(spid);
	WHACK(bufr);

	return retn;
}


/**
 * ECALL 11
 *
 * This function implements the ecall entry point for a function which
 * generates the platform specific device identity.
 *
 * \param id	A pointer containing the buffer which will be loaded
 *		with the 32 byte platform specific enclave identity.
 *
 * \return	A boolean value is used to indicate the status of the
 *		identity generation.  A false value indicates an error
 *		was encountered while a true value indicates the
 *		identity was successfully generated.
 */

_Bool generate_identity(uint8_t *id)

{
	_Bool retn = false;

	int rc;

	uint8_t keydata[16] __attribute__((aligned(128)));

	char report_data[64] __attribute__((aligned(128)));

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;

	struct SGX_report __attribute__((aligned(512))) report;

	struct SGX_targetinfo target;

	struct SGX_keyrequest keyrequest;


	/* Request a self report to get the measurement. */
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


	/* Generate the derived key and return it to the caller. */
	if ( (rc = enclu_egetkey(&keyrequest, keydata)) != 0 ) {
		fprintf(stdout, "EGETKEY return: %d\n", rc);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, keydata, sizeof(keydata)) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	memcpy(id, b->get(b), 32);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sha256);

	return retn;
}
