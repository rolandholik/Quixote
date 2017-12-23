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

#include <NAAAIM.h>

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
	char *token = NULL;

	int opt,
	    retn;

	PVEenclave pve = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "t:")) != EOF )
		switch ( opt ) {
			case 't':
				token = optarg;
				break;
		}

	if ( token == NULL ) {
		usage("No initialization token specified.\n");
		return 1;
	}


	/* Load the provisioning enclave. */
	INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
	if ( !pve->open(pve, token) )
		ERR(goto done);
	fputs("Provisioning enclave initialized.\n", stdout);


	/* Get the endpoint. */
	if ( !pve->get_endpoint(pve) )
		ERR(goto done);
	fputs("Have endpoint.\n", stdout);

	retn = 0;


 done:
	WHACK(pve);

	return retn;
}
