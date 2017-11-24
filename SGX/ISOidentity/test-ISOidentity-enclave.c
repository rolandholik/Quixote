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

/* Default aggregate value. */
#define DEFAULT_AGGREGATE \
	"0000000000000000000000000000000000000000000000000000000000000000"


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


/**
 * Private function.
 *
 * This function is used to replay either the model or forensic events.
 *
 * \param enclave	The object representing the enclave which is
 *			to be interrogated for the events.
 *
 * \param type		The type of event to be replayed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		an error was encountered while the event list was
 *		being replayed.
 */

static _Bool display_events(SGXenclave enclave, int type)

{
	_Bool retn = false;

	int rc;

	size_t lp;

	struct ISOidentity_ecall4_interface ecall4;

	struct ISOidentity_ecall8_interface ecall8;

	struct ISOidentity_ecall9_interface ecall9;


	/* Get the model component size. */
	ecall4.type = type;
	ecall4.size = 0;
	if ( !enclave->boot_slot(enclave, 4, &ocall_table, &ecall4, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( ecall4.size == 0 ) {
		fputs("Event type has zero size.\n", stdout);
		retn = true;
		goto done;
	}


	/* Rewind the event type. */
	ecall8.type = type;
	if ( !enclave->boot_slot(enclave, 8, &ocall_table, &ecall8, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}


	/* Loop through the events. */
	ecall9.type = type;
	fprintf(stdout, "Event count: %zu\n", ecall4.size);
	for (lp= 0; lp < ecall4.size; ++lp) {
		if ( !enclave->boot_slot(enclave, 9, &ocall_table, &ecall9, \
					 &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
		if ( strlen(ecall9.event) != 0 )
			fprintf(stdout, "%s\n", ecall9.event);
	}

	retn = true;


 done:
	return retn;
}


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

	static char *violation = "pid{9999} event{sh:/bin/dotest.sh} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} subject{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}";

	int opt,
	    rc,
	    retn = 1;

	struct ISOidentity_ecall0_interface ecall0_table;

	struct ISOidentity_ecall1_interface ecall1_table;

	struct ISOidentity_ecall4_interface ecall4_table;

	struct ISOidentity_ecall5_interface ecall5_table;

	struct ISOidentity_ecall6_interface ecall6_table;

	struct ISOidentity_ecall7_interface ecall7_table;

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

	bufr->reset(bufr);
	if ( !bufr->add_hexstring(bufr, DEFAULT_AGGREGATE) )
		ERR(goto done);

	ecall5_table.aggregate = bufr->get(bufr);
	ecall5_table.aggregate_length = bufr->size(bufr);

	if ( !enclave->boot_slot(enclave, 5, &ocall_table, \
				 &ecall5_table, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( !ecall5_table.retn ) {
		fputs("Enclave set aggregate failed.\n", stderr);
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

	ecall1_table.update	= input->get(input);
	ecall1_table.discipline = false;
	if ( !enclave->boot_slot(enclave, 1, &ocall_table, \
				 &ecall1_table, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( !ecall1_table.retn ) {
		fputs("Enclave model update failed.\n", stderr);
		goto done;
	}

	memset(&ecall7_table, '\0', sizeof(ecall7_table));
	if ( ecall1_table.discipline ) {
		if ( !enclave->boot_slot(enclave, 7, &ocall_table, \
					 &ecall7_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
		if ( !ecall7_table.retn ) {
			fputs("Enclave pid retrieval failed.\n", stderr);
			goto done;
		}
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

	fprintf(stdout, "\nPID of violator: %d\n", ecall7_table.pid);


	/* Test retrieval of the model measurement. */
	memset(ecall6_table.measurement, '\0', \
	       sizeof(ecall6_table.measurement));
	if ( !enclave->boot_slot(enclave, 6, &ocall_table, \
				 &ecall6_table, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}
	if ( !ecall6_table.retn ) {
		fputs("Enclave get measurement failed.\n", stderr);
		goto done;
	}

	bufr->reset(bufr);
	if ( !bufr->add(bufr, ecall6_table.measurement, \
			sizeof(ecall6_table.measurement)) )
		ERR(goto done);

	fputs("\n\nMeasurement:\n", stdout);
	bufr->print(bufr);


	/* Replay model and forensic events. */
	fputs("\n\nModel events:\n", stdout);
	if ( !display_events(enclave, ISO_IDENTITY_EVENT) )
		ERR(goto done);

	fputs("\n\nForensic events:\n", stdout);
	if ( !display_events(enclave, ISO_IDENTITY_FORENSICS) )
		ERR(goto done);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(enclave);

	return retn;

}
