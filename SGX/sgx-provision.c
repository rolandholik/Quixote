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

#include <HurdLib.h>
#include <String.h>

#include <NAAAIM.h>

#include "SGXmessage.h"
#include "PVEenclave.h"


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
		msg->decode(msg, response);
		msg->dump(msg);
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

	return retn;
}
