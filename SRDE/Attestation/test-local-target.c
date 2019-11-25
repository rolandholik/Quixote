/** \file
 * This file contains a test harness for exercising the functionality
 * of the code for obtaining a report from a local enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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

#include <SRDE.h>
#include <SRDEenclave.h>
#include <SRDEocall.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "LocalSource-interface.h"
#include "LocalTarget-interface.h"


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *source_token   = NULL,
	     *target_token   = NULL,
	     *source_enclave = "LocalSource.signed.so",
	     *target_enclave = "LocalTarget.signed.so";

	int opt,
	    rc,
	    retn = 1;

	struct OCALL_api *table;

	struct SGX_targetinfo targetinfo;

	struct SGX_reportbody body;

	struct SGX_report __attribute__((aligned(512))) report;

	struct LocalSource_ecall0_interface source_ecall0;

	struct LocalTarget_ecall0_interface target_ecall0;

	SRDEenclave source = NULL,
		    target = NULL;

	SRDEocall ocall = NULL;

	Buffer bufr = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "dn:s:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 's':
				source_token = optarg;
				break;
			case 't':
				target_token = optarg;
				break;
		}


	/* Load the target enclave. */
	if ( source_token == NULL ) {
		fputs("No source enclave token specified.\n", stderr);
		goto done;
	}
	if ( target_token == NULL ) {
		fputs("No target enclave token specified.\n", stderr);
		goto done;
	}


	/* Load and initialize the source and target enclaves. */
	INIT(NAAAIM, SRDEenclave, source, ERR(goto done));
	if ( !source->setup(source, source_enclave, source_token, debug) )
		ERR(goto done);

	INIT(NAAAIM, SRDEenclave, target, ERR(goto done));
	if ( !target->setup(target, target_enclave, target_token, debug) )
		ERR(goto done);


	/* Setup the exception handler. */
	if ( !srde_configure_exception() )
		ERR(goto done);


	/* Setup OCALL table. */
	INIT(NAAAIM, SRDEocall, ocall, ERR(goto done));

	ocall->add_table(ocall, SRDEfusion_ocall_table);
	ocall->add_table(ocall, SRDEnaaaim_ocall_table);

	if ( !ocall->get_table(ocall, &table) )
		ERR(goto done);


	/* Get target information from source enclave. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	source_ecall0.mode   = 1;
	source_ecall0.target = &targetinfo;
	source_ecall0.report = &report;
	if ( !source->boot_slot(source, 0, table, &source_ecall0, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn )
		ERR(goto done);


	/* Request report from target enclave. */
	target_ecall0.mode   = 1;
	target_ecall0.target = &targetinfo;
	target_ecall0.report = &report;
	if ( !target->boot_slot(target, 0, table, &target_ecall0, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !target_ecall0.retn )
		ERR(goto done);

	body = report.body;
	fputs("Report:\n", stdout);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, body.cpusvn, sizeof(body.cpusvn)) )
		ERR(goto done);
	fputs("cpusvn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\nmiscselect: %u\n", body.miscselect);

	fputs("\nattributes:\n", stdout);
	fprintf(stdout, "\tflags: 0x%0lx\n", body.attributes.flags);
	fprintf(stdout, "\txfrm:  0x%0lx\n", body.attributes.xfrm);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, body.mr_enclave.m, sizeof(body.mr_enclave.m)) )
		ERR(goto done);
	fputs("\nmeasurement: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, body.mrsigner, sizeof(body.mrsigner)) )
		ERR(goto done);
	fputs("signer:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\nisvprodid: 0x%0x\n", body.isvprodid);
	fprintf(stdout, "isvsvn:    0x%0x\n", body.isvsvn);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, body.reportdata, sizeof(body.reportdata)) )
		ERR(goto done);
	fputs("\ndata:\n", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.keyid, sizeof(report.keyid)) )
		ERR(goto done);
	fputs("\nkeyid: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.mac, sizeof(report.mac)) )
		ERR(goto done);
	fputs("MAC:   ", stdout);
	bufr->print(bufr);
	fputc('\n', stdout);


	/* Verify the report and generate counter report. */
	source_ecall0.mode   = 2;
	source_ecall0.target = &targetinfo;
	source_ecall0.report = &report;
	if ( !source->boot_slot(source, 0, table, &source_ecall0, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn ) {
		fputs("Failed report verification.\n", stdout);
		goto done;
	}


	/* Transmit report to target to complete key creation. */
	target_ecall0.mode   = 2;
	target_ecall0.target = &targetinfo;
	target_ecall0.report = &report;
	if ( !target->boot_slot(target, 0, table, &target_ecall0, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !target_ecall0.retn )
		ERR(goto done);

	retn = 0;


 done:
	WHACK(source);
	WHACK(target);
	WHACK(ocall);
	WHACK(bufr);

	return retn;

}
