#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <NAAAIM.h>
#include <IDtoken.h>
#include <Ivy.h>
#include <PossumPipe.h>

#include <SGX.h>
#include <SGXfusion.h>

#include "ISOmanager-interface.h"


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
 * ECALL 0
 *
 * This function implements the ecall entry point for a function which
 * implements the client side of the Duct test.
 *
 * \param debug		A flag which specifies whether or not the
 *			PossumPipe object is to be placed in debug
 *			mode.
 *
 * \param hostname	A pointer to a null-terminated character buffer
 *			containing the hostname which the client is to
 *			connect to.
 *
 * \param current_time	The time to be used as the seed for intra-enclave
 *			time.
 *
 * \param port		The port number to connect to on the remote
 *			server.
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
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool connect(_Bool debug, char *hostname, int port, time_t current_time, \
	      char *spid_key, size_t id_size, unsigned char *identity,    \
	      size_t vfy_size, unsigned char *verifier)

{
	_Bool retn = false;

	PossumPipe pipe = NULL;

	Buffer bufr = NULL,
	       spid = NULL;

	Ivy ivy = NULL;

	IDtoken idt = NULL;


	fprintf(stderr, "%s: Called.\n", __func__);
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


	/* Start client mode. */
	fprintf(stdout, "Client mode: connecting to %s:%d\n", hostname, port);
	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( debug )
		pipe->debug(pipe, debug);

	if ( !pipe->init_client(pipe, hostname, port) ) {
		fputs("Cannot initialize client pipe.\n", stderr);
		goto done;
	}
	if ( !pipe->start_client_mode(pipe, spid)) {
		fputs("Error starting client mode.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	WHACK(pipe);
	WHACK(bufr);
	WHACK(spid);
	WHACK(ivy);
	WHACK(idt);

	return retn ? 0 : 1;
}


/**
 * ECALL 1
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
