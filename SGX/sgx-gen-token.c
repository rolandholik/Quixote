/** \file
 * This file contains the implementation of a utility which generates
 * an initialization token for an SGX enclave.  This token is a
 * required element for the ENCLU[EINIT] instruction which carries out
 * final initialization and sealing of an enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions local to this file. */
#define PGM "sgx-gen-token"


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
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXmetadata.h"


/**
 * The following include file contains an encoding of the Intel
 * whitelist certificate that will be loaded into the Launch Enclave
 * prior to generation of the EINIT token.  This white list specifies
 * the enclave signers that are permitted to create initialization
 * tokens that have the debug attribute bit disabled.
 *
 * This include file is designed to be dynamically built by the
 * build process.
 */
#include "LE_whitelist.h"


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
} ecall0_table;


/**
 * The following structure defines the API definition for the ECALL
 * which implements loading of the certificate white list.
 */
static struct LE_ecall1_table {
	uint32_t ms_retval;
	uint8_t *ms_wl_cert_chain;
	uint32_t ms_wl_cert_chain_size;
} ecall1_table;


static void usage(char *err)

{
	fprintf(stdout, "%s: SGX EINIT token generator.\n", PGM);
	fprintf(stdout, "%s: (C)IDfusion, LLC\n", PGM);

	if ( err != NULL )
		fprintf(stdout, "\n%s\n", err);

	fputc('\n', stdout);
	fputs("Usage:\n", stdout);
	fputs("\t-d:\tEnable enclave debug mode.\n", stdout);
	fputs("\t-p:\tGenerate token for a non-debug enclave.\n\n", stdout);

	fputs("\t-e:\tEnclave to generate token for.\n", stdout);
	fputs("\t-l:\tLocation of launch enclave.\n\t\t\tdefault = "	\
	      "/opt/intel/sgxpsw/aesm/libsgx_le.signed.so\n", stdout);
	fputs("\t-n:\tSGX device node.\n\t\t\tdefault = /dev/isgx\n", stdout);
	fputs("\t-o:\tOutput file.\n\t\t\tdefault = stdout\n", stdout);

	return;
}


static _Bool init_ecall0(char *enclave,
			 struct LE_ecall0_table *ecall,	\
			 sgx_attributes_t *attributes,	\
			 sgx_measurement_t *mrenclave,	\
			 sgx_measurement_t *mrsigner,	\
			 struct SGX_einittoken *token,	\
			 _Bool debug_enclave)

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
	if ( !init_enclave->compute_attributes(init_enclave, debug_enclave) )
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


void thread_manager(void)

{
	fputs("Thread manager.\n", stdout);
	return;
}


static _Bool load_white_list(SGXenclave enclave)

{
	_Bool retn = false;

	int rc;


	/* Call the enclave white list loader. */
	memset(&ecall1_table, '\0', sizeof(ecall1_table));
	ecall1_table.ms_wl_cert_chain	   = LE_whitelist;
	ecall1_table.ms_wl_cert_chain_size = sizeof(LE_whitelist);

	if ( !enclave->boot_slot(enclave, 1, &LE_ocall_table, &ecall1_table, \
				 &rc) )
		ERR(goto done);
	if ( ecall1_table.ms_retval != 0 )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


static _Bool generate_token(SGXenclave enclave, char *init_enclave, \
			    struct SGX_einittoken *token, _Bool debug_enclave)

{
	_Bool retn = false;

	int rc;

	sgx_attributes_t attributes;

	sgx_measurement_t mrenclave,
			  mrsigner;


	if ( !init_ecall0(init_enclave, &ecall0_table, &attributes, \
			  &mrenclave, &mrsigner, token, debug_enclave) )
		ERR(goto done);

	if ( !enclave->boot_slot(enclave, 0, &LE_ocall_table, &ecall0_table, \
				 &rc) )
		ERR(goto done);

	if ( ecall0_table.ms_retval != 0 ) {
		fprintf(stderr, "LE returned: %d\n", ecall0_table.ms_retval);
		goto done;
	}

	retn = true;


 done:
	return retn;
}


static void generate_output(char *output, struct SGX_einittoken *token)

{
	uint8_t token_buffer[sizeof(struct SGX_einittoken)];

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Load the token buffer with the token. */
	memset(token_buffer, '\0', sizeof(token_buffer));
	memcpy(token_buffer, token, sizeof(struct SGX_einittoken));


	/* Send output to the standard output. */
	if ( strcmp(output, "-") == 0 ) {
		fwrite(token_buffer, sizeof(token_buffer), 1, stdout);
		return;
	}


	/* Send output to a user specified file. */
	INIT(HurdLib, File, token_file, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !token_file->open_rw(token_file, output) )
		ERR(goto done);

	bufr->add(bufr, (void *) token_buffer, sizeof(token_buffer));
	if ( !token_file->write_Buffer(token_file, bufr) )
		ERR(goto done);


 done:
	WHACK(bufr);
	WHACK(token_file);

	return;
}


extern int main(int argc, char *argv[])

{
	_Bool debug	    = false,
	      debug_enclave = true;

	char *sgx_device     = "/dev/isgx",
	     *launch_enclave = "/opt/intel/sgxpsw/aesm/libsgx_le.signed.so",
	     *output_file    = "-",
	     *init_enclave   = NULL;

	int opt,
	    retn = 1;

	struct SGX_einittoken token;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "dpe:l:n:o:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'e':
				init_enclave = optarg;
				break;
			case 'l':
				launch_enclave = optarg;
				break;
			case 'n':
				sgx_device = optarg;
				break;
			case 'o':
				output_file = optarg;
				break;
		}


	if ( init_enclave == NULL ) {
		usage("No enclave specified.");
		return 1;
	}

	if ( debug && (strcmp(output_file, "-") == 0) ) {
		usage("Debug mode not compatible with stdout output.");
		return 1;
	}


	/* Setup the Launch Enclave (LE) to generate an EINITTOKEN. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( debug )
		fputs("Setting up launch enclave.\n", stdout);
	if ( !enclave->open_enclave(enclave, sgx_device, launch_enclave, \
				    false) )
		ERR(goto done);
	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);
	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);
	if ( !enclave->init_launch_enclave(enclave) )
		ERR(goto done);


	/* Load the white list. */
	if ( debug )
		fputs("Loading white list.\n", stdout);
	if ( !load_white_list(enclave) )
		ERR(goto done);


	/* Generate the launch token. */
	if ( debug )
		fputs("Generating token.\n", stdout);
	if ( !generate_token(enclave, init_enclave, &token, debug_enclave) )
		ERR(goto done);


	/* Output debug information and token. */
	if ( debug ) {
		fputs("EINITTOKEN generated.\n", stdout);
		fprintf(stdout, "\tstatus: %u\n", token.valid);
		fputs("\tattributes:\n", stdout);
		fprintf(stdout, "\t\tflags: 0x%lx\n", token.attributes.flags);
		fprintf(stdout, "\t\txfrm: 0x%lx\n", token.attributes.xfrm);
		fprintf(stdout, "\tisvsvnle: %u\n", token.isvsvnle);
	}

	generate_output(output_file, &token);

	retn = 0;


 done:
	WHACK(enclave);
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}
