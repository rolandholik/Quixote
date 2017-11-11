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

static const struct OCALL_api ocall_table = {
	1, {ocall1_handler}
};


/* Interfaces for the trusted ECALL's. */
static struct ecall0_table {
	char *update;
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
	_Bool debug = true;

	char *token	   = NULL,
	     *trajectory   = NULL,
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = "ISOidentity.signed.so";

	int opt,
	    rc,
	    retn = 1;

	struct SGX_einittoken *einit;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	String input = NULL;

	File infile = NULL;


	/* Output header. */
	fprintf(stdout, "%s: IDfusion ISOidentity model test harness.\n", \
		"test-ISOidentity");
	fprintf(stdout, "%s: (C)Copyright 2017, IDfusion, LLC. All rights "
		"reserved.\n\n", "test-ISOidentity");


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "dni:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = debug ? false : true;
			case 'n':
				sgx_device = optarg;
				break;

			case 'i':
				trajectory = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}


	/* Load the launch token. */
	if ( token == NULL ) {
		fputs("No EINIT token specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, infile, ERR(goto done));

	infile->open_ro(infile, token);
	if ( !infile->slurp(infile, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);

	infile->reset(infile);


	/* Open the trajectory file. */
	if ( trajectory == NULL ) {
		fputs("No trajectory file specified.\n", stderr);
		goto done;
	}
	if ( !infile->open_ro(infile, trajectory) )
		ERR(goto done);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, sgx_device, enclave_name, debug) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);


	/* Process the trajectory file. */
	INIT(HurdLib, String, input, ERR(goto done));

	while ( infile->read_String(infile, input) ) {
		ecall0_table.update = input->get(input);
		if ( !enclave->boot_slot(enclave, 0, &ocall_table, \
					 &ecall0_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}

		input->reset(input);
	}

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(enclave);

	return retn;

}
