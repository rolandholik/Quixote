/** \file
 * This file contains a test harness for exercising the functionality
 * of the SRDEfusion library.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Default aggregate value. */
#define PGM		"test-ISOidentity"
#define COPYRIGHT	"%s: Copyright (c) %s, %s. All rights reserved.\n"
#define DATE		"2020"
#define COMPANY		"Enjellic Systems Development, LLC"

#define DEFAULT_AGGREGATE \
	"0000000000000000000000000000000000000000000000000000000000000000"

#define VIOLATION "pid{9999} event{sh:/bin/dotest.sh} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} subject{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
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
#include <IDtoken.h>
#include <SRDE.h>
#include <SRDEenclave.h>
#include <ExchangeEvent.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "SanchoSGX-interface.h"
#include "SanchoSGX.h"


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

	char *spid	   = NULL,
	     *trajectory   = NULL,
	     *id_token	   = NULL,
	     *verifier	   = NULL,
	     *token	   = "SanchoSGX.token",
	     *enclave_name = "SanchoSGX.signed.so";

	static char *violation = VIOLATION;

	int opt,
	    retn = 1;

	pid_t pid;

	FILE *idfile = NULL;

	enum {test, measure} mode = test;

	SanchoSGX sancho = NULL;

	Buffer ivy     = NULL,
	       bufr    = NULL,
	       id_bufr = NULL;

	String input = NULL;

	File infile = NULL;

	IDtoken idt = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "Mdf:i:s:t:v:")) != EOF )
		switch ( opt ) {
			case 'M':
				mode = measure;
				break;

			case 'd':
				debug = debug ? false : true;
				break;
			case 'f':
				trajectory = optarg;
				break;
			case 'i':
				id_token = optarg;
				break;
			case 's':
				spid = optarg;
				break;
			case 't':
				token = optarg;
				break;
			case 'v':
				verifier = optarg;
				break;
		}


	/* Setup the exception handler. */
	if ( !srde_configure_exception() )
		ERR(goto done);


	/* Run measurement mode. */
	if ( mode == measure ) {
		INIT(NAAAIM, SanchoSGX, sancho, ERR(goto done));
		if ( !sancho->load_enclave(sancho, enclave_name, token) )
			ERR(goto done);

		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		if ( !sancho->generate_identity(sancho, bufr) )
			ERR(goto done);
		bufr->print(bufr);

		goto done;
	}


	/* Output header. */
	fprintf(stdout, "%s: Turing event test harness.\n", PGM);
	fprintf(stdout, COPYRIGHT, PGM, DATE, COMPANY);
	fflush(stdout);


	/* Verify arguements. */
	if ( spid == NULL ) {
		fputs("No SPID specified.\n", stderr);
		goto done;
	}

	if ( verifier == NULL ) {
		fputs("No identifier verified specifed.\n", stderr);
		goto done;
	}

	if ( id_token == NULL ) {
		fputs("No device identity specifed.\n", stderr);
		goto done;
	}


	/* Load the identity token. */
	INIT(NAAAIM, IDtoken, idt, goto done);
	if ( (idfile = fopen(id_token, "r")) == NULL ) {
		fputs("Cannot open identity token file.\n", stderr);
		goto done;
	}
	if ( !idt->parse(idt, idfile) ) {
		fputs("Enable to parse identity token.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, id_bufr, ERR(goto done));
	if ( !idt->encode(idt, id_bufr) ) {
		fputs("Error encoding identity token.\n", stderr);
		goto done;
	}


	/* Load the identifier verifier. */
	INIT(HurdLib, Buffer, ivy, ERR(goto done));
	INIT(HurdLib, File, infile, ERR(goto done));

	infile->open_ro(infile, verifier);
	if ( !infile->slurp(infile, ivy) ) {
		fputs("Cannot read identity verifier.\n", stderr);
		goto done;
	}


	/* Open the trajectory file. */
	if ( trajectory == NULL ) {
		fputs("No trajectory file specified.\n", stderr);
		goto done;
	}

	infile->reset(infile);
	if ( !infile->open_ro(infile, trajectory) )
		ERR(goto done);


	/* Load enclave and initialize model. */
	INIT(NAAAIM, SanchoSGX, sancho, ERR(goto done));
	if ( !sancho->load_enclave(sancho, enclave_name, token) )
		ERR(goto done);


	/* Set the model aggregate value. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add_hexstring(bufr, DEFAULT_AGGREGATE) )
		ERR(goto done);

	if ( !sancho->set_aggregate(sancho, bufr) )
		ERR(goto done);


	/* Process the trajectory file. */
	INIT(HurdLib, String, input, ERR(goto done));

	while ( infile->read_String(infile, input) ) {
		if ( !sancho->update(sancho, input, &discipline) )
			ERR(goto done);
		if ( discipline ) {
			fputs("Model needs disciplining.\n", stdout);
			goto done;
		}
		input->reset(input);
	}


	/* Dump the events. */
	fputs("Events:\n", stdout);
	sancho->dump_events(sancho);


	/* Seal and violate the model to obtain forensic information. */
	if ( !sancho->seal(sancho) )
		ERR(goto done);

	input->reset(input);
	if ( !input->add(input, violation) )
		ERR(goto done);

	if ( !sancho->update(sancho, input, &discipline) )
		ERR(goto done);

	fputs("\nForensics:\n", stdout);
	if ( discipline ) {
		sancho->discipline_pid(sancho, &pid);
		fprintf(stdout, "Forensic event generated for pid=%d.\n\n", \
			pid);
	}
	else {
		fputs("Failed to detect forensic event.\n", stdout);
		ERR(goto done);
	}

	sancho->dump_forensics(sancho);


	/* Test retrieval of the model measurement. */
	bufr->reset(bufr);
	if ( !sancho->get_measurement(sancho, bufr) )
		ERR(goto done);

	fputs("\nMeasurement:\n", stdout);
	bufr->print(bufr);


	/* Start management interface test. */
	if ( !sancho->manager(sancho, id_bufr, 11990, spid) )
		ERR(goto done);

	retn = true;


 done:
	if ( idfile != NULL )
		fclose(idfile);

	WHACK(sancho);
	WHACK(ivy);
	WHACK(bufr);
	WHACK(id_bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(idt);

	return retn;

}
