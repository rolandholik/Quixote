/** \file
 * This file contains a test harness for exercising the functionality
 * of the Duct object.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Definition of program and primary enclave. */
#define PGM "test-Duct"
#define ENCLAVE PGM".signed.so"


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
#include <Duct.h>
#include <SRDE.h>
#include <SRDEenclave.h>

#include "test-Duct-interface.h"


/* Define the OCALL interface for the 'print string' call. */
struct ocall1_interface {
	char* str;
} ocall1_string;

int ocall1_handler(struct ocall1_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

struct ocall2_interface {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
};

static void cpuid(int *eax, int *ebx, int *ecx, int *edx)\

{
	__asm("cpuid\n\t"
	      /* Output. */
	      : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
	      /* Input. */
	      : "0" (*eax), "2" (*ecx));

	return;
}


int ocall2_handler(struct ocall2_interface *pms)

{
	struct ocall2_interface *ms = (struct ocall2_interface *) pms;


	ms->ms_cpuinfo[0] = ms->ms_leaf;
	ms->ms_cpuinfo[2] = ms->ms_subleaf;

	cpuid(&ms->ms_cpuinfo[0], &ms->ms_cpuinfo[1], &ms->ms_cpuinfo[2], \
	      &ms->ms_cpuinfo[3]);

	return 0;
}

static const struct OCALL_api ocall_table = {
	4,
	{
		ocall1_handler,
		NULL,
		ocall2_handler,
		Duct_sgxmgr
	}
};


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

	char *token	   = SGX_TOKEN_DIRECTORY"/test-Duct.token",
	     *hostname	   = "localhost",
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = ENCLAVE_NAME;

	int opt,
	    rc,
	    retn = 1;

	enum {none, client, server} Mode = none;

	struct SGX_einittoken *einit = NULL;

	SRDEenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;

	struct Duct_ecall0 ecall0;

	struct Duct_ecall1 ecall1;


	/* Output header. */
	fprintf(stdout, "%s: IDfusion Duct test utility.\n", PGM);
	fprintf(stdout, "%s: (C)Copyright 2017, IDfusion, LLC. All rights "
		"reserved.\n\n", PGM);


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "CSdph:e:n:t:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = client;
				break;
			case 'S':
				Mode = server;
				break;

			case 'd':
				debug = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'h':
				hostname = optarg;
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


	/* Validate the type of run. */
	if ( Mode == none ) {
		fputs("No mode specified.\n", stderr);
		goto done;
	}

	/* Load a launch token if specified.. */
	if ( (token != NULL) && (token[0] != '\0') ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		INIT(HurdLib, File, token_file, ERR(goto done));

		token_file->open_ro(token_file, token);
		if ( !token_file->slurp(token_file, bufr) )
			ERR(goto done);
		einit = (void *) bufr->get(bufr);
	}


	/* Setup the exception handler. */
	if ( !srde_configure_exception() )
		ERR(goto done);


	/* Load an initialize the enclave. */
	INIT(NAAAIM, SRDEenclave, enclave, ERR(goto done));
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


	/* Test server mode. */
	if ( Mode == server ) {
		ecall0.port = 11990;
		if ( !enclave->boot_slot(enclave, 0, &ocall_table, \
					 &ecall0, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
	}


	/* Test client mode. */
	if ( Mode == client ) {
		ecall1.port	     = 11990;
		ecall1.hostname	     = hostname;
		ecall1.hostname_size = strlen(hostname) + 1;

		if ( !enclave->boot_slot(enclave, 1, &ocall_table, \
					 &ecall1, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
	}

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(token_file);
	WHACK(enclave);

	return retn;

}
