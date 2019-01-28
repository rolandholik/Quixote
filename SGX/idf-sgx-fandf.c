/** \file
 * This file contains an implemenation of the IDfusion 'oneshot' SGX
 * invocation technology.  All of the infrastructure needed to implement
 * the test-ecall enclave is implemented in a single binary.
 *
 * The functionality of the enclave which implements printing an
 * arbitrary string from inside the enclave is invariant from the
 * test-ecall utility.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Definitions specific to this file. */
#define PGM "idf-sgx-fandf"


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

#include "NAAAIM.h"
#include "SHA256.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXmetadata.h"


/**
 * The following include file loads an encoded version of the Launch
 * Enclave whitelist that contains the list of the key signatures that
 * the Intel launch enclave will verify.
 */
#include "LE_whitelist.h"


/* Include the launch image. */
#include "launch-enclave.c"


/**
 * The following defines an empty OCALL table since the Launch Enclave
 * does not support any outgoing calls.
 */
static const struct {
	size_t nr_ocall;
	void *table[1];
} LE_ocall_table = { 0, {NULL}};


/**
 * The following structure defines the API for the ECALL which carries
 * out the generation of an EINITTOKEN.
 */
static struct LE_ecall0_table {
	int ms_retval;
	sgx_measurement_t *ms_mrenclave;
	sgx_measurement_t *ms_mrsigner;
	sgx_attributes_t *ms_se_attributes;
	struct SGX_einittoken *ms_lictoken;
} LE_ecall0_table;


/**
 * The following structure defines the API definition for the ECALL
 * which implements loading of the certificate white list.
 */
static struct LE_ecall1_table {
	uint32_t ms_retval;
	uint8_t *ms_wl_cert_chain;
	uint32_t ms_wl_cert_chain_size;
} LE_ecall1_table;


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

static struct ecall0_table {
	uint8_t *buffer;
	size_t len;
} ecall0_table;


static _Bool LE_init_ecall0(char *enclave,
			    struct LE_ecall0_table *ecall,	\
			    sgx_attributes_t *attributes,	\
			    sgx_measurement_t *mrenclave,	\
			    sgx_measurement_t *mrsigner,	\
			    struct SGX_einittoken *token)

{
	_Bool retn = false;

	struct SGX_sigstruct sigstruct;

	SGXmetadata init_enclave = NULL;

	Buffer bufr = NULL;

	Sha256 sha256 = NULL;


	/* Buffer object for utility support. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));


	/* Get the attributes for an enclave to be signed. */
	INIT(NAAAIM, SGXmetadata, init_enclave, ERR(goto done));
	if ( !init_enclave->load(init_enclave, enclave) )
		ERR(goto done);
	if ( !init_enclave->compute_attributes(init_enclave, true) )
		ERR(goto done);
	if ( !init_enclave->get_attributes(init_enclave, attributes) )
		ERR(goto done);

	if ( !init_enclave->get_sigstruct(init_enclave, &sigstruct) )
		ERR(goto done);
	memcpy(mrenclave, sigstruct.enclave_hash, SGX_HASH_SIZE);


	/* Compute the hash of the signature modulus. */
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	if ( !bufr->add(bufr, (unsigned char *) sigstruct.modulus, \
			sizeof(sigstruct.modulus)) )
		ERR(goto done);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	memcpy(mrsigner, sha256->get(sha256), SGX_HASH_SIZE);

	memset(token, '\0', sizeof(struct SGX_einittoken));

	ecall->ms_retval	  = 0;
	ecall->ms_mrenclave	  = mrenclave;
	ecall->ms_mrsigner	  = mrsigner;
	ecall->ms_se_attributes	  = attributes;
	ecall->ms_lictoken	  = token;

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sha256);
	WHACK(init_enclave);

	return retn;
}


static _Bool load_white_list(SGXenclave enclave)

{
	_Bool retn = false;

	int rc;


	/* Call the enclave white list loader. */
	memset(&LE_ecall1_table, '\0', sizeof(LE_ecall1_table));
	LE_ecall1_table.ms_wl_cert_chain	   = LE_whitelist;
	LE_ecall1_table.ms_wl_cert_chain_size = sizeof(LE_whitelist);

	if ( !enclave->boot_slot(enclave, 1, &LE_ocall_table, \
				 &LE_ecall1_table, &rc) )
		ERR(goto done);
	if ( LE_ecall1_table.ms_retval != 0 )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


static _Bool generate_token(SGXenclave enclave, char *init_enclave, \
			    struct SGX_einittoken *token)

{
	_Bool retn = false;

	int rc;

	sgx_attributes_t attributes;

	sgx_measurement_t mrenclave,
			  mrsigner;


	if ( !LE_init_ecall0(init_enclave, &LE_ecall0_table, &attributes, \
			     &mrenclave, &mrsigner, token) )
		ERR(goto done);

	if ( !enclave->boot_slot(enclave, 0, &LE_ocall_table, \
				 &LE_ecall0_table, &rc) )
		ERR(goto done);

	if ( LE_ecall0_table.ms_retval != 0 ) {
		fprintf(stderr, "LE returned: %d\n", \
			LE_ecall0_table.ms_retval);
		goto done;
	}

	retn = true;


 done:
	return retn;
}


/**
 * Internal function.
 *
 * This function runs in a continuous loop of accepting user input and
 * echoing it through the enclave.
 *
 * \param enclave	The enclave which is to be used to echo user
 *			input.
 *
 * \return		If an error occurs during an enclave call a
 *			false value is returned.  A true value is
 *			used to indicate the user has requested
 *			termination of the loop.
 */

static _Bool enclave_loop(CO(SGXenclave, enclave))

{
	_Bool retn = false;

	int rc;

	char inbufr[1024];


	ecall0_table.len    = sizeof(inbufr);
	ecall0_table.buffer = (uint8_t *) inbufr;

	while ( true ) {
		fputs("Input>", stdout);
		fflush(stdout);

		memset(inbufr, '\0', sizeof(inbufr));
		if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL ) {
			fputc('\n', stdout);
			retn = true;
			goto done;
		}

		if ( memcmp(inbufr, "quit\n", 5) == 0 ) {
			retn = true;
			goto done;
		}

		if ( !enclave->boot_slot(enclave, 0, &ocall_table, \
					 &ecall0_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			goto done;
		}
	}


 done:
	return retn;
}


/**
 * Program entry point.
 *
 * No arguements are expected.
 */

extern int main(int argc, char *argv[])

{
	char *sgx_device   = "/dev/isgx",
	     *enclave_name = "test-ecall.signed.so";

	int retn = 1;

	struct SGX_einittoken token;

	SGXenclave le	   = NULL,
		   enclave = NULL;


	/* Output logo. */
	fprintf(stdout, "%s: IDfusion SGX 'fire and forget' technology.\n", \
		PGM);
	fprintf(stdout, "%s: (C)Copyright 2017, IDfusion, LLC. All rights "
		"reserved.\n\n", PGM);
	fputs("Typed input will be echoed through the enclave.\n", stdout);
	fputs("Type 'quit' to terminate.\n\n", stdout);


	/* Create the launch token. */
	INIT(NAAAIM, SGXenclave, le, ERR(goto done));

	if ( !le->open_enclave_memory(le, sgx_device, LE_image, \
				      sizeof(LE_image), false) )
		ERR(goto done);
	if ( !le->create_enclave(le) )
		ERR(goto done);
	if ( !le->load_enclave(le) )
		ERR(goto done);
	if ( !le->init_launch_enclave(le) )
		ERR(goto done);
	if ( !load_white_list(le) )
		ERR(goto done);
	if ( !generate_token(le, enclave_name, &token) )
		ERR(goto done);


	/* Load and initialize the execution enclave. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, sgx_device, enclave_name, true) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, &token) )
		ERR(goto done);

	if ( !enclave_loop(enclave) )
		ERR(goto done);

	retn = 0;


 done:
	WHACK(le);
	WHACK(enclave);

	return retn;

}
