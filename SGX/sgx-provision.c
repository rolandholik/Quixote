/** \file
 * This file contains a utility which provisions an platform specific
 * EPID token to the platform.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Definitions local to this file. */
#define PGM "sgx-provision"


#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>

#include "SGXmessage.h"
#include "PVEenclave.h"
#include "intel-messages.h"


/**
 * Object to hold validated server name.
 */
static String Server = NULL;

/**
 * Variable to hold the message TTL.
 */
static uint16_t Ttl = 0;


/**
 * Internal public function.
 *
 * This method implements outputting of an error message and status
 * information on how to run the utility.
 *
 * \param err	A pointer to a null-terminated buffer holding the
 *		error message to be output.
 *
 * \return	No return value is defined.
 */

static void usage(char *err)

{
	fprintf(stdout, "%s: SGX provisioning tool.\n", PGM);
	fprintf(stdout, "%s: (C)IDfusion, LLC\n", PGM);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("Usage:\n", stdout);
	fputs("\t-t:\tThe file containing the initialization token\n\n", \
	      stdout);

	return;
}


/**
 * Internal private function.
 *
 * This function implements the process of validating an endpoint
 * verification message from the Intel servers.  This message provides
 * a validated URL to be used for further message processing.
 *
 * \param msg		A pointer to the object which is managing
 *			the message.
 *
 * \param response	An object containing the string encoded message
 *			returned from the Intel server.
 *
 * \return		A boolean value is used to indicated the status
 *			of the message processing.  A false value
 *			indicates that message processing failed while
 *			a true value indicates the message was
 *			processed and verified.
 */

static _Bool process_message1(CO(SGXmessage, msg), CO(String, response))

{
	_Bool retn = false;

	Buffer bufr = NULL;


	/* Decode and verify the message count. */
	if ( !msg->decode(msg, response) )
		ERR(goto done);
	if ( msg->message_count(msg) != 3 )
		ERR(goto done);
	msg->dump(msg);


	/* Extract the server TTL and URL. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !msg->get_message(msg, TLV_ES_INFORMATION, 1, bufr) )
		ERR(goto done);

	Ttl = *(uint16_t *) bufr->get(bufr);
	Ttl = ntohs(Ttl);

	if ( !bufr->add(bufr, (unsigned char *) "\0", 1) )
		ERR(goto done);

	INIT(HurdLib, String, Server, ERR(goto done));
	if ( !Server->add(Server, (char *) (bufr->get(bufr) + sizeof(Ttl))) )
		ERR(goto done);

	fputs("\nSERVER:\n\t", stdout);
	Server->print(Server);
	fprintf(stdout, "\tTTL: %u\n", Ttl);


	/* Process the signature message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_SIGNATURE, 1, bufr) )
		ERR(goto done);

	fputs("\nSIGNATURE:\n", stdout);
	bufr->hprint(bufr);

	retn = true;


	/* Process the PEK message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_PEK, 1, bufr) )
		ERR(goto done);
	fputs("\nPEK:\n", stdout);
	bufr->hprint(bufr);


 done:
	WHACK(bufr);

	return retn;
}


/* Main program starts here. */

extern int main(int argc, char *argv[])

{
	char *msg1_response = NULL,
	     *token = NULL;

	int opt,
	    retn;

	String response = NULL;

	PVEenclave pve = NULL;

	SGXmessage msg = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "1:t:")) != EOF )
		switch ( opt ) {
			case '1':
				msg1_response = optarg;
				break;

			case 't':
				token = optarg;
				break;
		}

	if ( token == NULL ) {
		usage("No initialization token specified.\n");
		return 1;
	}

	INIT(NAAAIM, SGXmessage, msg, ERR(goto done));


	/* Decode a message 1 response. */
	if ( msg1_response != NULL ) {
		INIT(HurdLib, String, response, ERR(goto done));
		if ( !response->add(response, msg1_response) )
			ERR(goto done);

		if ( !process_message1(msg, response) )
			ERR(goto done);
		retn = 0;
		goto done;
	}


	/* Load the provisioning enclave. */
	INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
	if ( !pve->open(pve, token) )
		ERR(goto done);


	/* Get the endpoint. */
	if ( !pve->get_endpoint(pve) )
		ERR(goto done);


	/* Encode the message. */
	if ( !pve->generate_message1(pve, msg) )
		ERR(goto done);

	msg->dump(msg);
	retn = 0;


 done:
	WHACK(pve);
	WHACK(msg);
	WHACK(response);

	WHACK(Server);

	return retn;
}
