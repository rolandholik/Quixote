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

#include "ISOidentity-interface.h"


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

	static char *violation = "event{sh:/bin/dotest.sh} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} subject{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}";

	int opt,
	    rc,
	    retn = 1;

	struct ISOidentity_ecall0_interface ecall0_table;

	struct ISOidentity_ecall1_interface ecall1_table;

	struct ISOidentity_ecall4_interface ecall4_table;

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
	fflush(stdout);


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


	/* Initialize the model. */
	if ( !enclave->boot_slot(enclave, 0, &ocall_table, &ecall0_table, \
				 &rc) )
	{
		fprintf(stderr, "Enclave internal error: %d\n", rc);
		goto done;
	}
	if ( !ecall0_table.retn ) {
		fputs("Enclave model initialization failed.\n", stderr);
		goto done;
	}


	/* Process the trajectory file. */
	INIT(HurdLib, String, input, ERR(goto done));

	while ( infile->read_String(infile, input) ) {
		ecall1_table.update = input->get(input);
		if ( !enclave->boot_slot(enclave, 1, &ocall_table, \
					 &ecall1_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
		if ( !ecall1_table.retn ) {
			fputs("Enclave model update failed.\n", stderr);
			goto done;
		}
		input->reset(input);
	}


	/* Seal and violate the model to obtain forensic information. */
	if ( !enclave->boot_slot(enclave, 2, &ocall_table, NULL, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	input->reset(input);
	if ( !input->add(input, violation) )
		ERR(goto done);

	ecall1_table.update = input->get(input);
	if ( !enclave->boot_slot(enclave, 1, &ocall_table, \
				 &ecall1_table, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( !ecall1_table.retn ) {
		fputs("Enclave model update failed.\n", stderr);
		goto done;
	}


	/* Dump the model status. */
	if ( !enclave->boot_slot(enclave, 3, &ocall_table, NULL, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}


	/* Test the return of model sizes. */
	fputs("Sizes:\n", stdout);
	ecall4_table.type = ISO_IDENTITY_EVENT;
	if ( !enclave->boot_slot(enclave, 4, &ocall_table, &ecall4_table, \
				 &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	fprintf(stdout, "\tModel:     %zu\n", ecall4_table.size);

	ecall4_table.type = ISO_IDENTITY_FORENSICS;
	if ( !enclave->boot_slot(enclave, 4, &ocall_table, &ecall4_table, \
				 &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	fprintf(stdout, "\tForensics: %zu\n", ecall4_table.size);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(enclave);

	return retn;

}
