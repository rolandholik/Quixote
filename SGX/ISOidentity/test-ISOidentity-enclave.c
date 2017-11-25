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

#define VIOLATION "pid{9999} event{sh:/bin/dotest.sh} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} subject{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}"


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
#include <ExchangeEvent.h>

#include "ISOidentity-interface.h"
#include "ISOenclave.h"


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
	_Bool discipline,
	      debug = true;

	char *token	   = NULL,
	     *trajectory   = NULL,
	     *enclave_name = "ISOidentity.signed.so";

	static char *violation = VIOLATION;

	int opt,
	    retn = 1;

	pid_t pid;

	ISOenclave isoenclave = NULL;

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
	while ( (opt = getopt(argc, argv, "di:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = debug ? false : true;

			case 'i':
				trajectory = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}


	/* Open the trajectory file. */
	if ( trajectory == NULL ) {
		fputs("No trajectory file specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, trajectory) )
		ERR(goto done);


	/* Load enclave and initialize model. */
	INIT(NAAAIM, ISOenclave, isoenclave, ERR(goto done));
	if ( !isoenclave->load_enclave(isoenclave, enclave_name, token) )
		ERR(goto done);


	/* Set the model aggregate value. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add_hexstring(bufr, DEFAULT_AGGREGATE) )
		ERR(goto done);

	if ( !isoenclave->set_aggregate(isoenclave, bufr) )
		ERR(goto done);


	/* Process the trajectory file. */
	INIT(HurdLib, String, input, ERR(goto done));

	while ( infile->read_String(infile, input) ) {
		if ( !isoenclave->update(isoenclave, input, &discipline) )
			ERR(goto done);
		if ( discipline ) {
			fputs("Model needs disciplining.\n", stdout);
			goto done;
		}
		input->reset(input);
	}


	/* Dump the events. */
	fputs("Events:\n", stdout);
	isoenclave->dump_events(isoenclave);


	/* Seal and violate the model to obtain forensic information. */
	if ( !isoenclave->seal(isoenclave) )
		ERR(goto done);

	input->reset(input);
	if ( !input->add(input, violation) )
		ERR(goto done);

	if ( !isoenclave->update(isoenclave, input, &discipline) )
		ERR(goto done);

	fputs("\nForensics:\n", stdout);
	if ( discipline ) {
		isoenclave->discipline_pid(isoenclave, &pid);
		fprintf(stdout, "Forensic event generated for pid=%d.\n\n", \
			pid);
	}
	else {
		fputs("Failed to detect forensic event.\n", stdout);
		ERR(goto done);
	}

	isoenclave->dump_forensics(isoenclave);


	/* Test retrieval of the model measurement. */
	bufr->reset(bufr);
	if ( !isoenclave->get_measurement(isoenclave, bufr) )
		ERR(goto done);

	fputs("\nMeasurement:\n", stdout);
	bufr->print(bufr);


 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(isoenclave);

	return retn;

}
