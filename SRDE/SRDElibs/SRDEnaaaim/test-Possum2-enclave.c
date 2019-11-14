/** \file
 * This file contains an implementation of a test harness for testing
 * the enclave version of the Duct object.  This object is used for
 * implementing network based communications from one enclave to
 * another.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions of messages to be sent. */
#define KEY1 "0000000000000000000000000000000000000000000000000000000000000000"
#define KEY2 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define CR "\n"
#define OK "OK\n"


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <RandomBuffer.h>
#include <RSAkey.h>
#include <SHA256.h>

#include <SRDE.h>
#include <SRDEfusion.h>

#include "PossumPipe.h"

#include "test-Possum2-interface.h"


/* Macro to clear an array object. */
#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


/** Provide a local definition for the socket address structure. */
struct in_addr {
	uint32_t s_addr;
};


/**
 * Enumerated type to specify what mode the enclave is running in.
 */
enum test_mode {
	none,
	client,
	server
} Mode = none;


/**
 * The device identity to be used.  This is unused for mode 2
 * authentication but needed in order to satisfy the link dependency
 * from the PossumPipe object.
 */
size_t Identity_size	= 0;
unsigned char *Identity = NULL;

/**
 * The list of verifiers for communication counter-parties.
 */
Buffer Verifiers = NULL;


/**
 * The seed time for the time() function.
 */
static time_t Current_Time;


/**
 * Static private function.
 *
 * The following function is used to add a verifier key to the current
 * list current verifies that are permitted to connect to the enclave.
 *
 * \param verifier	A character pointer to the buffer containing
 *			the raw key blob that will be added to the
 *			verifier list.
 *
 * \param size		The number of bytes in the verifier buffer.
 *
 * \return		A boolean value is returned to indicate
 *			whether or not addition of the identity
 *			verifier succeed.  A true value indicates the
 *			addition was successful while a false value
 *			indicates the identity was not registered.
 */

static _Bool _add_verifier(uint8_t *verifier, size_t size)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	RSAkey key = NULL;


	/* Decode the raw RSAkey buffer. */
	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !bufr->add(bufr, verifier, size) )
		ERR(goto done);
	if ( !key->load_public(key, bufr) )
		ERR(goto done);


	/* Add the RSAkey object to the verifier list. */
	if ( Verifiers == NULL )
		INIT(HurdLib, Buffer, Verifiers, ERR(goto done));

	if ( !Verifiers->add(Verifiers, (unsigned char *) &key, \
			     sizeof(RSAkey)) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


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


static _Bool ping(CO(PossumPipe, pipe))

{
	_Bool retn = false;

	Buffer b,
	       bufr = NULL;

	RandomBuffer rnd = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);

	if ( Mode == server ) {
		fputs("\nWaiting for ping packet.\n", stderr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}
		fputs("Received packet:\n", stdout);
		bufr->print(bufr);

		fputs("\nReturning packet.\n", stdout);
		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending packet.\n", stderr);
			goto done;
		}

		fputs("\nServer mode done.\n", stdout);
		retn = true;
	}

	if ( Mode == client ) {
		fputs("\nSending ping packet:\n", stderr);

		INIT(NAAAIM, RandomBuffer, rnd, ERR(goto done));
		if ( !rnd->generate(rnd, 32) )
			ERR(goto done);
		b = rnd->get_Buffer(rnd);

		bufr->add_Buffer(bufr, b);
		bufr->print(bufr);

		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending data packet.\n", stderr);
			goto done;
		}

		fputs("\nWaiting for response:\n", stdout);
		bufr->reset(bufr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}

		if ( bufr->equal(bufr, b) )
			fputs("\nPacket is verified.\n", stdout);
		else {
			fputs("\nPacket failed verification.\n", stdout);
			fputs("\nSent:\n", stdout);
			b->print(b);
			fputs("Received:\n", stdout);
			bufr->print(bufr);
		}

		retn = true;
	}

 done:
	WHACK(bufr);
	WHACK(rnd);

	return retn;
}


/**
 * ECALL 0
 *
 * This function implements the ecall entry point for the function that
 * implements the server side of the PossumpPipe mode 2 protocol test.
 *
 * \param ifp		A pointer to the structure containing the
 *			server mode arguements.
 *
 * \return	A boolean value is used to indicate the status of the
 *		server mode test.  A false value indicates an error was
 *		encountered while a true value indicates the test was
 *		successfully conducted.
 */

_Bool test_server(struct Possum2_ecall0 *ifp)

{
	_Bool retn = false;

	uint16_t vendor,
		 svn;

	uint64_t attributes;

	PossumPipe pipe = NULL;

	Buffer spid	   = NULL,
	       bufr	   = NULL,
	       signer	   = NULL,
	       measurement = NULL;


	/* Initialize the time. */
	Current_Time = ifp->current_time;

	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, ifp->spid) )
		ERR(goto done);


	/* Start the server listening. */
	fprintf(stdout, "Server mode: port=%d\n", ifp->port);

	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( ifp->debug_mode )
		pipe->debug(pipe, ifp->debug_mode);

	if ( !pipe->init_server(pipe, NULL, ifp->port, false) )
		ERR(goto done);

	if ( !pipe->accept_connection(pipe) ) {
		fputs("Error accepting connection.\n", stderr);
		ERR(goto done);
	}

	if ( !pipe->start_host_mode2(pipe, spid) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}

	/* Display remote connection parameters. */
	INIT(HurdLib, Buffer, signer, ERR(goto done));
	INIT(HurdLib, Buffer, measurement, ERR(goto done));

	if ( !pipe->get_connection(pipe, &attributes, signer, measurement, \
				   &vendor, &svn) )
		ERR(goto done);

	fputs("\nHave connection.\n", stdout);
	fputs("Signer:\n\t", stdout);
	signer->print(signer);
	fputs("Measurement:\n\t", stdout);
	measurement->print(measurement);
	fprintf(stdout, "Attributes:\n\t%lu\n", attributes);
	fprintf(stdout, "Software:\n\t%u/%u\n", vendor, svn);


	/* Run server mode test. */
	Mode = server;
	ping(pipe);


 done:
	GWHACK(RSAkey, Verifiers);
	WHACK(Verifiers);

	WHACK(pipe);
	WHACK(spid);
	WHACK(bufr);
	WHACK(signer);
	WHACK(measurement);

	return retn;
}


/**
 * ECALL 1
 *
 * This function implements the ecall entry point for a function which
 * implements the client side of the PossumPipe authentication mode2
 * test.
 *
 * \param ifp		A pointer to the structure that contains the
 *			client arguements.
 *
 * \return	A boolean value is used to indicate the status of client
 *		mode.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool test_client(struct Possum2_ecall1 *ifp)

{
	_Bool retn = false;

	uint16_t vendor,
		 svn;

	uint64_t attributes;

	PossumPipe pipe = NULL;

	Buffer signer	   = NULL,
	       measurement = NULL;

	RSAkey key = NULL;


	/* Initialize the time. */
	Current_Time = ifp->current_time;


	/* Load the identifier key. */
	INIT(HurdLib, Buffer, signer, ERR(goto done));
	if ( !signer->add(signer, ifp->key, ifp->key_size) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_private(key, signer) )
		ERR(goto done);


	/* Start client mode. */
	fprintf(stdout, "Client mode: connecting to %s:%d\n", \
		ifp->hostname, ifp->port);
	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( ifp->debug_mode )
		pipe->debug(pipe, ifp->debug_mode);

	if ( !pipe->init_client(pipe, ifp->hostname, ifp->port) ) {
		fputs("Cannot initialize client pipe.\n", stderr);
		goto done;
	}
	if ( !pipe->start_client_mode2(pipe, key)) {
		fputs("Error starting client mode.\n", stderr);
		goto done;
	}


	/* Display remote connection parameters. */
	INIT(HurdLib, Buffer, measurement, ERR(goto done));

	signer->reset(signer);
	if ( !pipe->get_connection(pipe, &attributes, signer, measurement, \
				   &vendor, &svn) )
		ERR(goto done);

	fputs("\nHave connection.\n", stdout);
	fputs("Signer:\n\t", stdout);
	signer->print(signer);
	fputs("Measurement:\n\t", stdout);
	measurement->print(measurement);
	fprintf(stdout, "Attributes:\n\t%lu\n", attributes);
	fprintf(stdout, "Software:\n\t%u/%u\n", vendor, svn);


	/* Run client mode test. */
	Mode = client;
	ping(pipe);

	retn = true;


 done:
	WHACK(pipe);
	WHACK(signer);
	WHACK(measurement);
	WHACK(key);

	return retn ? 0 : 1;
}


/**
 * ECALL 2
 *
 * This function implements the ecall entry point for a function which
 * adds an identity verifier to the list of valid POSSUM communication
 * parties.  It wraps the _add_verifier() private function which
 * implements the addition of the identity verifier.
 *
 * \param ecall3	A pointer to the input structure to the ECALL.
 *
 * \return	A boolean value is used to indicate the status of the
 *		registration of the identity verifier.  A false value
 *		indicates an error was encountered while registering
 *		the verifier while a true value indicates the verifier
 *		was successfully registered.
 */

_Bool add_verifier(struct Possum2_ecall2 *ecall2)

{
	_Bool retn = false;


	/* Verify arguements. */
	if ( ecall2->key_size == 0 )
		ERR(goto done);

	retn = _add_verifier(ecall2->key, ecall2->key_size);


 done:
	return retn;
}
