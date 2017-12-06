/** \file
 * This file contains a test harness for exercising the functionality
 * of the code for obtaining a report from a local enclave.
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
	_Bool debug = true;

	char *token	   = NULL,
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = NULL;

	int opt,
	    rc,
	    retn = 1;

	struct SGX_einittoken *einit;

	struct SGX_targetinfo target;

	struct SGX_report report;

	struct LocalTarget_ecall0_interface ecall0;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "de:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'e':
				enclave_name = optarg;
				break;
			case 'n':
				sgx_device = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}

	if ( enclave_name == NULL ) {
		fputs("No enclave name specifed.\n", stderr);
		goto done;
	}


	/* Load the launch token. */
	if ( token == NULL ) {
		fputs("No token specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


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


	/* Request report from enclave. */
	if ( !enclave->get_targetinfo(enclave, &target) )
		ERR(goto done);

	ecall0.target = &target;
	ecall0.report = &report;
	if ( !enclave->boot_slot(enclave, 0, &ocall_table, &ecall0, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}

	fputs("Report:\n", stdout);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.cpusvn, sizeof(report.cpusvn)) )
		ERR(goto done);
	fputs("cpusvn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\nmiscselect: %u\n", report.miscselect);

	fputs("\nattributes:\n", stdout);
	fprintf(stdout, "\tflags: 0x%0lx\n", report.attributes.flags);
	fprintf(stdout, "\txfrm:  0x%0lx\n", report.attributes.xfrm);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.mr_enclave.m, \
			sizeof(report.mr_enclave.m)) )
		ERR(goto done);
	fputs("\nmeasurement: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.mrsigner, \
			sizeof(report.mrsigner)) )
		ERR(goto done);
	fputs("signer:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\nisvprodid: 0x%0x\n", report.isvprodid);
	fprintf(stdout, "isvsvn:    0x%0x\n", report.isvsvn);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, report.reportdata, sizeof(report.reportdata)) )
		ERR(goto done);
	fputs("\nReport data:\n", stdout);
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


 done:
	WHACK(bufr);
	WHACK(token_file);
	WHACK(enclave);

	return retn;

}
