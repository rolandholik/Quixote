/** \file
 * This file contains a test harness for exercising the functionality
 * of the SGXfusion library.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Number of tests. */
#define NUMBER_OF_TESTS 3

/* Name of program and associated enclave. */
#define PGM "test-fusion"
#define ENCLAVE PGM".signed.so"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <String.h>
#include <Buffer.h>
#include <File.h>

#include <NAAAIM.h>
#include <SGX.h>
#include <SGXenclave.h>


/* Define the OCALL interface for the 'print string' call. */
struct ocall1_interface {
	char* str;
} ocall1_string;

int ocall1_handler(struct ocall1_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}


/* Interface and handler for fgets function simulation. */
struct SGXfusion_fgets_interface {
	_Bool retn;

	int stream;
	char bufr_size;
	char bufr[];
};

int fgets_handler(struct SGXfusion_fgets_interface *oc)

{
	FILE *instream = NULL;


	if ( oc->stream == 3 )
		instream = stdin;
	else {
		fprintf(stderr, "%s: Bad stream number: %d", __func__, \
			oc->stream);
		return 1;
	}

	if ( fgets(oc->bufr, oc->bufr_size, instream) != NULL )
		oc->retn = true;
	return 0;
}


static const struct OCALL_api ocall_table = {
	2,
	{
		ocall1_handler,
		fgets_handler
	}
};


/* Interfaces for the trusted ECALL's. */
static struct ecall0_table {
	int test;
} ecall0_table;


/**
 * Program entry point.
 *
 * The following arguements are processed:
 *
 *	-d:	By default the debug attribute is set for the enclave.
 *		This option toggles that option.
 *
 *	-e:	The enclave which is to be executed.
 *
 *	-n:	The SGX device node to be used.  By default /dev/isgx.
 *
 *	-t:	The file containing the EINITTOKEN for this processor.
 */

extern int main(int argc, char *argv[])

{
	_Bool debug	    = false,
	      debug_enclave = true;

	char *token	   = NULL,
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = ENCLAVE_NAME;

	int opt,
	    rc,
	    test,
	    retn = 1;

	struct SGX_einittoken *einit = NULL;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Output header. */
	fprintf(stdout, "%s: IDfusion SGXfusion library test utility.\n", \
		"fusion-test");
	fprintf(stdout, "%s: (C)Copyright 2017, IDfusion, LLC. All rights "
		"reserved.\n\n", "fusion-test");


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "dpn:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'n':
				sgx_device = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}



	/* Load a launch token if one is specified. */
	if ( (token != NULL) && (token[0] != '\0') ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		INIT(HurdLib, File, token_file, ERR(goto done));

		token_file->open_ro(token_file, token);
		if ( !token_file->slurp(token_file, bufr) )
			ERR(goto done);
		einit = (void *) bufr->get(bufr);
	}


	/* Load an initialize the enclave. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));
	if ( debug )
		enclave->debug(enclave, true);

	if ( !enclave->open_enclave(enclave, sgx_device, enclave_name, \
				    debug_enclave) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);


	for (test= 1; test <= NUMBER_OF_TESTS; ++test) {
		ecall0_table.test = test;
		if ( !enclave->boot_slot(enclave, 0, &ocall_table, \
					 &ecall0_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
		fputc('\n', stdout);
	}

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(token_file);
	WHACK(enclave);

	return retn;

}
