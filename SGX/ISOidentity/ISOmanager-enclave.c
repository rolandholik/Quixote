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

#include <cboot.h>

#include "ISOmanager-interface.h"


/**
 * The device identity to be used.
 */
size_t Identity_size	= 0;
unsigned char *Identity = NULL;


/**
 * The valid identity verifiers of the communication counter-parties
 */
Buffer Verifiers = NULL;


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
 * Private function.
 *
 * This function implements the receipt of a trajectory list from
 * the canister management daemon.  The protocol used is for the
 * management daemon to send the number of points in the trajectory
 * followed by each point in ASCII form.
 *
 * \param mgmt		The object used to communicate with the
 *			canister management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the trajectory
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_trajectory(CO(PossumPipe, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_packet(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Trajectory size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_packet(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a forensics list from
 * the canister management daemon.  The protocol used is for the
 * management daemon to send the number of events in the forensics
 * patch followed by each event in ASCII form.
 *
 * \param mgmt		The object used to communicate with the
 *			canister management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the forensics
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_forensics(CO(PossumPipe, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_packet(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Forensics size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_packet(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a behavior contour map from
 * the canister management enclave.  The protocol used is for the
 * enclave to send the number of events in the map followed by each
 * contour point in ASCII form.
 *
 * \param mgmt		The object used to communicate with the
 *			canister management enclave.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the contour map.
 *			A false value indicates an error occurred while
 *			a true value indicates the response was properly
 *			processed.
 */

static _Bool receive_contours(CO(PossumPipe, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_packet(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Contour size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_packet(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements receipt and processing of the command
 * which was executed on the canister management daemon.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
 *
 * \param cmdbufr	The object used to hold the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate an
 *			error was encountered while processing receipt
 *			of the command.  A false value indicates an
 *			error occurred while a true value indicates the
 *			response was properly processed.
 */

static _Bool receive_command(CO(PossumPipe, mgmt), CO(Buffer, cmdbufr), \
			     int cmdnum)

{
	_Bool retn = false;


	switch ( cmdnum ) {
		case show_measurement:
			if ( !mgmt->receive_packet(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->print(cmdbufr);
			cmdbufr->reset(cmdbufr);
			retn = true;
			break;

		case show_trajectory:
			retn = receive_trajectory(mgmt, cmdbufr);
			break;

		case show_forensics:
			retn = receive_forensics(mgmt, cmdbufr);
			break;

		case show_contours:
			retn = receive_contours(mgmt, cmdbufr);
			break;
	}

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the parsing of the supplied command and
 * the translation of this command to a binary expression of the
 * command.  The binary command is sent over the PossumpPipe connection
 * with subsequent reads from the pipe for the command response.
 *
 * \param mgmt		The object used to communicate with the canister
 *			management instance.
 *
 * \param cmd		A character point to the null-terminated buffer
 *			containing the ASCII version of the command.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of commands should continue.  A
 *			false value indicates the processing of commands
 *			should be terminated while a true value indicates
 *			an additional command cycle should be processed.
 */

static _Bool process_command(CO(PossumPipe, mgmt), CO(char *, cmd))

{
	_Bool retn = false;

	int lp,
	    cmdnum = 0;

	struct cboot_cmd_definition *cp = cboot_cmd_list;

	Buffer cmdbufr = NULL;


	/* Process local commands. */
	if ( strcmp("show connection", cmd) == 0 ) {
		mgmt->display_connection(mgmt);
		retn = true;
		goto done;
	}


	/* Locate the command. */
	for (lp= 0; cp[lp].syntax != NULL; ++lp) {
		if ( strcmp(cp[lp].syntax, cmd) == 0 )
			cmdnum = cp[lp].command;
	}
	if ( cmdnum == 0 ) {
		fprintf(stdout, "Unknown command: %s\n", cmd);
		retn = true;
		goto done;
	}

	/* Send the command over the management socket. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	cmdbufr->add(cmdbufr, (unsigned char *) &cmdnum, sizeof(cmdnum));
	if ( !mgmt->send_packet(mgmt, PossumPipe_data, cmdbufr) )
		ERR(goto done);

	cmdbufr->reset(cmdbufr);
	if ( !receive_command(mgmt, cmdbufr, cmdnum) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(cmdbufr);
	return retn;
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
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool connect(_Bool debug, char *hostname, int port, time_t current_time, \
	      char *spid_key, size_t id_size, unsigned char *identity)

{
	_Bool retn = false;

	char *p,
	     inbufr[80];

	PossumPipe pipe = NULL;

	Buffer bufr = NULL,
	       spid = NULL;

	Ivy ivy = NULL;

	IDtoken idt = NULL;


	/* Initialize the time. */
	Current_Time = current_time;


	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) )
		ERR(goto done);


	/* Stash the identity token and verifier buffer descriptions. */
	Identity      = identity;
	Identity_size = id_size;


	/* Start client mode. */
	fprintf(stdout, "SGX cboot manager: connecting to %s:%d\n", hostname, \
		port);
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


	/* Start command loop. */
	while ( 1 ) {
		memset(inbufr, '\0', sizeof(inbufr));

		fprintf(stdout, "%s:cboot>", hostname);
		if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL )
			goto done;
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';

		if ( inbufr[0] == '\0' )
			continue;
		if ( strcmp(inbufr, "quit") == 0 ) {
			retn = true;
			goto done;
		}

		if ( !process_command(pipe, inbufr) )
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


/**
 * ECALL 2
 *
 * This function implements the ecall entry point for a function which
 * adds an identity verifier to the list of valid POSSUM communication
 * parties.
 *
 * \param ecall13	A pointer to the input structure to the ECALL.
 *
 * \return	A boolean value is used to indicate the status of the
 *		registration of the identity verifier.  A false value
 *		indicates an error was encountered while registering
 *		the verifier while a true value indicates the verifier
 *		was successfully registered.
 */

_Bool add_verifier(struct ISOmanager_ecall2 *ecall2)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	Ivy ivy = NULL;


	/* Decode the raw Ivy buffer. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Ivy, ivy, ERR(goto done));

	if ( !bufr->add(bufr, ecall2->verifier, ecall2->verifier_size) )
		ERR(goto done);
	if ( !ivy->decode(ivy, bufr) )
		ERR(goto done);


	/* Add the Ivy object to the verifier list. */
	if ( Verifiers == NULL )
		INIT(HurdLib, Buffer, Verifiers, ERR(goto done));

	if ( !Verifiers->add(Verifiers, (unsigned char *) &ivy, sizeof(Ivy)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		WHACK(ivy);
	WHACK(bufr);

	return retn;
}
