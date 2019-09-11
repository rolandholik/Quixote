/** \file
 * This file contains a test harness for exercising the generation of
 * a remotely verifiable attestation of an enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
#define PGM	"test-remote-target"
#define ENCLAVE "LocalTarget.signed.so"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>
#include <Base64.h>
#include <HTTP.h>

#include "SRDE.h"
#include "SRDEenclave.h"
#include "SRDEquote.h"
#include "SRDEepid.h"
#include "SRDEocall.h"
#include "SRDEfusion-ocall.h"
#include "SRDEnaaaim-ocall.h"

#include "LocalTarget-interface.h"


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *epid_blob	     = "/var/lib/IDfusion/data/EPID.bin",
	     *quote_token    = SGX_TOKEN_DIRECTORY"/libsgx_qe.token",
	     *pce_token	     = SGX_TOKEN_DIRECTORY"/libsgx_pce.token",
	     *spid_fname     = SPID_FILENAME,
	     *source_token   = SGX_TOKEN_DIRECTORY"/LocalTarget.token",
	     *source_enclave = ENCLAVE_NAME;

	int rc,
	    opt,
	    retn = 1;

	enum {
		untrusted,
		trusted
	} mode = untrusted;

	struct SGX_report __attribute__((aligned(512))) enclave_report;

	struct LocalTarget_ecall0_interface source_ecall0;

	struct LocalTarget_ecall1 source_ecall1;

	struct OCALL_api *ocall_table;

	Buffer spid	= NULL,
	       quote	= NULL,
	       http_in	= NULL,
	       http_out = NULL;

	String output	= NULL,
	       spid_key = NULL;

	File spid_file = NULL;

	RandomBuffer nonce = NULL;

	Base64 base64 = NULL;

	SRDEquote quoter = NULL;

	SRDEenclave source = NULL;

	SRDEocall ocall = NULL;

	HTTP http = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "Te:p:q:s:t:")) != EOF )
		switch ( opt ) {
			case 'T':
				mode = trusted;
				break;
			case 'e':
				epid_blob = optarg;
				break;
			case 'p':
				pce_token = optarg;
				break;
			case 'q':
				quote_token = optarg;
				break;
			case 's':
				spid_fname = optarg;
				break;
			case 't':
				source_token = optarg;
				break;
		}


	/* Print banner. */
	fprintf(stdout, "%s: Remote test utility.\n", PGM);
	fprintf(stdout, "%s: (C)2018 IDfusion, LLC\n", PGM);


	/* Setup SPID key. */
	INIT(HurdLib, String, spid_key, ERR(goto done));

	INIT(HurdLib, File, spid_file, ERR(goto done));
	if ( !spid_file->open_ro(spid_file, spid_fname) )
		ERR(goto done);
	if ( !spid_file->read_String(spid_file, spid_key) )
		ERR(goto done);

	if ( spid_key->size(spid_key) != 32 ) {
		fputs("Invalid SPID size: ", stdout);
		spid_key->print(spid_key);
		goto done;
	}


	/* Setup the OCALL dispatch table. */
	INIT(NAAAIM, SRDEocall, ocall, ERR(goto done));

	ocall->add_table(ocall, SRDEfusion_ocall_table);
	ocall->add_table(ocall, SRDEnaaaim_ocall_table);
	if ( !ocall->get_table(ocall, &ocall_table) )
		ERR(goto done);


	/* Test trusted mode. */
	if ( mode == trusted ) {
		fputs("\nTesting enclave mode attestation.\n", stdout);

		INIT(NAAAIM, SRDEenclave, source, ERR(goto done));
		if ( !source->setup(source, source_enclave, source_token, \
				    debug) )
			ERR(goto done);

		source_ecall1.qe_token	    = quote_token;
		if ( quote_token != NULL )
			source_ecall1.qe_token_size = strlen(quote_token) + 1;

		source_ecall1.pce_token	     = pce_token;
		if ( pce_token != NULL )
			source_ecall1.pce_token_size = strlen(pce_token) + 1;

		source_ecall1.epid_blob	     = epid_blob;
		if ( epid_blob != NULL )
			source_ecall1.epid_blob_size = strlen(epid_blob) + 1;

		source_ecall1.spid 	= spid_key->get(spid_key);
		source_ecall1.spid_size = spid_key->size(spid_key) + 1;

		if ( !source->boot_slot(source, 1, ocall_table, \
					&source_ecall1, &rc) ) {
			fprintf(stderr, "Enclave return error: %d\n", rc);
			ERR(goto done);
		}

		if ( !source_ecall1.retn )
			fputs("Trusted remote attestation test failed.\n", \
			      stderr);
		goto done;
	}


	/* Load and initialize the quoting object. */
	fputs("\nTesting non-enclave attestation.\n", stdout);

	fputs("\nInitializing quote.\n", stdout);
	INIT(NAAAIM, SRDEquote, quoter, ERR(goto done));
	if ( !quoter->init(quoter, quote_token, pce_token, epid_blob) )
		ERR(goto done);


	/*
	 * Load the source enclave which the quote will be generated
	 * for.  The report will be directed to the quoting enclave.
	 */
	INIT(NAAAIM, SRDEenclave, source, ERR(goto done));
	if ( !source->setup(source, source_enclave, source_token, debug) )
		ERR(goto done);

	source_ecall0.mode   = 1;
	source_ecall0.target = quoter->get_qe_targetinfo(quoter);
	source_ecall0.report = &enclave_report;
	if ( !source->boot_slot(source, 0, ocall_table, &source_ecall0, \
				&rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn )
		ERR(goto done);
	fputs("\nGenerated attesting enclave report.\n", stdout);


	/*
	 * Convert the SPID into a binary buffer and generate the
	 * nonce to be used.
	 */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key->get(spid_key)) ) {
		fputs("Invalid SPID format.\n", stderr);
		goto done;
	}

	fputs("\nGenerating quote with:\n", stdout);
	fputs("\tSPID:  ", stdout);
	spid_key->print(spid_key);


	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( !nonce->generate(nonce, 16) ) {
		fputs("Unable to generate nonce.\n", stderr);
		goto done;
	}
	fputs("\tNONCE: ", stdout);
	nonce->get_Buffer(nonce)->print(nonce->get_Buffer(nonce));


	/* Request the quote. */
	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quoter->generate_quote(quoter, &enclave_report, spid, \
				     nonce->get_Buffer(nonce), quote) )
		ERR(goto done);

	fputs("\nBinary quote:\n", stdout);
	quote->hprint(quote);
	fputs("\n", stdout);


	/* Request a report on the quote. */
	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output) )
		ERR(goto done);

	fputs("Attestation report:\n", stdout);
	output->print(output);


	/* Decode response values. */
	fputc('\n', stdout);
	if ( !quoter->decode_report(quoter, output) )
		ERR(goto done);
	quoter->dump_report(quoter);

	retn = 0;


 done:
	WHACK(spid);
	WHACK(quote);
	WHACK(nonce);
	WHACK(source);
	WHACK(ocall);
	WHACK(output);
	WHACK(spid_key);
	WHACK(spid_file);
	WHACK(base64);
	WHACK(quoter);
	WHACK(http_in);
	WHACK(http_out);
	WHACK(http);

	return retn;

}
