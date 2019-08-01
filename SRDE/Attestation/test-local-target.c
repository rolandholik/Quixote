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

#include "SGX.h"
#include "SGXenclave.h"

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


/**
 * Static public function.
 *
 * This function opens and initializes an enclave whose name and
 * token are specified.
 *
 * \param enclave	The object which will be used to manage the
 *			enclave.
 *
 * \param device	A pointer to a null-terminated character buffer
 *			containing the name of the SGX device used to
 *			issue the control commands to the kernel
 *			driver.
 *
 * \param name		A pointer to a null-terminated character buffer
 *			containing the name of the shared object
 *			file containing the enclave image.
 *
 * \param token		A pointer to a null-terminated character buffer
 *			containing the name of the file containing
 *			the initialization token.
 *
 * \param debug		A boolean value used to indicate whether or
 *			not the debug attribute is to be set on
 *			the enclave.
 *
 * \return	If an error is encountered while initializing the
 *		enclave a false value is returned.  A true value indicates
 *		the enclave has been loaded and initialized.
 */

static _Bool open_enclave(CO(SGXenclave, enclave), CO(char *, device), \
			  CO(char *, name), CO(char *, token), 	       \
			  const _Bool debug)

{
	_Bool retn = false;

	struct SGX_einittoken *einit;

	Buffer bufr = NULL;

	File token_file = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	if ( !enclave->open_enclave(enclave, device, name, debug) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *source_token   = NULL,
	     *target_token   = NULL,
	     *sgx_device     = "/dev/isgx",
	     *source_enclave = "LocalSource.signed.so",
	     *target_enclave = "LocalTarget.signed.so";

	int opt,
	    rc,
	    retn = 1;

	struct SGX_targetinfo targetinfo;

	struct SGX_reportbody body;

	struct SGX_report __attribute__((aligned(512))) report;

	struct LocalSource_ecall0_interface source_ecall0;

	struct LocalTarget_ecall0_interface target_ecall0;

	SGXenclave source = NULL,
		   target = NULL;

	Buffer bufr = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "dn:s:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'n':
				sgx_device = optarg;
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
	INIT(NAAAIM, SGXenclave, source, ERR(goto done));
	if ( !open_enclave(source, sgx_device, source_enclave, source_token, \
			   debug) )
		ERR(goto done);

	INIT(NAAAIM, SGXenclave, target, ERR(goto done));
	if ( !open_enclave(target, sgx_device, target_enclave, target_token, \
			   debug) )
		ERR(goto done);


	/* Get target information from source enclave. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	source_ecall0.mode   = 1;
	source_ecall0.target = &targetinfo;
	source_ecall0.report = &report;
	if ( !source->boot_slot(source, 0, &ocall_table, &source_ecall0, \
				&rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn )
		ERR(goto done);


	/* Request report from target enclave. */
	target_ecall0.mode   = 1;
	target_ecall0.target = &targetinfo;
	target_ecall0.report = &report;
	if ( !target->boot_slot(target, 0, &ocall_table, &target_ecall0, \
				&rc) ) {
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
	if ( !source->boot_slot(source, 0, &ocall_table, &source_ecall0, \
				&rc) ) {
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
	if ( !target->boot_slot(target, 0, &ocall_table, &target_ecall0, \
				&rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !target_ecall0.retn )
		ERR(goto done);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(source);
	WHACK(target);

	return retn;

}
