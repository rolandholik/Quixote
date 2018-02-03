/** \file
 * This file contains a test harness for exercising the generation of
 * a remotely verifiable attestation of an enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>

#include "SGX.h"
#include "SGXenclave.h"
#include "QEenclave.h"
#include "SGXepid.h"

#include "LocalSource-interface.h"
#include "LocalTarget-interface.h"


/** OCALL interface definition. */
struct SGXfusion_ocall0_interface {
	char* str;
} SGXfusion_ocall0;

int ocall0_handler(struct SGXfusion_ocall0_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

static const struct OCALL_api ocall_table = {
	1, {ocall0_handler}
};


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	char *epid_blob	  = NULL,
	     *quote_token = "qe.token";

	int opt,
	    retn = 1;

	QEenclave qe = NULL;

	Buffer bufr = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "e:q:")) != EOF )
		switch ( opt ) {
			case 'e':
				epid_blob = optarg;
				break;
			case 'q':
				quote_token = optarg;
				break;
		}


	/* Verify arguements. */
	if ( epid_blob == NULL ) {
		fputs("No EPID blob specified.\n", stderr);
		goto done;
	}


	/* Load and initialize the source and target enclaves. */
	fputs("Opening quoting enclave.\n", stderr);
	INIT(NAAAIM, QEenclave, qe, ERR(goto done));
	if ( !qe->open(qe, quote_token) )
		ERR(goto done);


	/* Verify the EPID blob. */
	if ( !qe->load_epid(qe, epid_blob) )
		ERR(goto done);
	fputs("Verified EPID.\n", stdout);

	retn = 0;


 done:
	fputs("Done.\n", stdout);

	WHACK(bufr);
	WHACK(qe);


	return retn;

}
