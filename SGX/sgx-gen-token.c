/** \file
 * This file contains the implementation of a utility which generates
 * an initialization token for an SGX enclave.  This token is a
 * required element for the ENCLU[EINIT] instruction which carries out
 * final initialization and sealing of an enclave.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Definitions local to this file. */
#define PGM "sgx-gen-token"


#include <stdio.h>
#include <stdbool.h>
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
 * The following array is an encoding of the Intel certificate white
 * list.  This white list is a requirement for operation of the Launch
 * Enclave.
 */
static uint8_t LE_white_list[] = {
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x65, 0x88, 0x08, 0x83, 0x92, 0xe7, 0x3d, 0x04, \
	0x9d, 0xf6, 0xce, 0xd6, 0xf2, 0xe6, 0x96, 0x31, \
	0x45, 0xe1, 0x89, 0xc0, 0x03, 0xfb, 0x3a, 0x74, \
	0x87, 0x0b, 0x20, 0xd3, 0x2a, 0xa8, 0xa4, 0xa1, \
	0x32, 0xcf, 0x58, 0x63, 0x6a, 0x63, 0xaf, 0xd6, \
	0x4b, 0xf9, 0x5c, 0x60, 0x77, 0x06, 0x9b, 0x62, \
	0x8c, 0x39, 0x75, 0xb6, 0x0d, 0x12, 0xe5, 0x5a, \
	0xd3, 0x3d, 0x9b, 0x99, 0x59, 0x90, 0xca, 0x6d, \
	0xb3, 0x28, 0x22, 0x71, 0xd3, 0x1e, 0xd1, 0x75, \
	0x28, 0xa6, 0xed, 0x89, 0x2f, 0x7a, 0xe7, 0x3a, \
	0x5c, 0xa1, 0xe1, 0xbd, 0xd1, 0xc9, 0xfc, 0xe9, \
	0xa0, 0xd3, 0x9d, 0x59, 0xc7, 0x01, 0x57, 0xe2, \
	0x8c, 0x96, 0x81, 0x98, 0x5e, 0x1e, 0x6d, 0x79, \
	0xeb, 0x00, 0x68, 0x4b, 0x20, 0x6b, 0xeb, 0x8a, \
	0x2f, 0xa2, 0xc4, 0x45, 0x20, 0xd5, 0xa8, 0xdf, \
	0x3e, 0x8e, 0x1f, 0x2e, 0x8f, 0x92, 0x98, 0xb6, \
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, \
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, \
	0xec, 0x15, 0xb1, 0x07, 0x87, 0xd2, 0xf8, 0x46, \
	0x67, 0xce, 0xb0, 0xb5, 0x98, 0xff, 0xc4, 0x4a, \
	0x1f, 0x1c, 0xb8, 0x0f, 0x67, 0x0a, 0xae, 0x5d, \
	0xf9, 0xe8, 0xfa, 0x9f, 0x63, 0x76, 0xe1, 0xf8, \
	0x4b, 0xe2, 0xaf, 0x03, 0x63, 0x66, 0xeb, 0xc4, \
	0x17, 0x6e, 0x70, 0xa5, 0x39, 0xf0, 0x04, 0x45, \
	0xd9, 0x05, 0x7d, 0x96, 0x04, 0xf8, 0xea, 0xd3, \
	0xe3, 0x23, 0xf3, 0x80, 0x4a, 0x11, 0xf9, 0xac, \
	0xf8, 0x7f, 0xd5, 0x6b, 0x93, 0x52, 0x93, 0xa1, \
	0xf4, 0x47, 0xfe, 0x58, 0x3d, 0x7b, 0x59, 0xbc, \
	0x46, 0xfe, 0xc2, 0xfb, 0xc2, 0x16, 0x3c, 0x51, \
	0x8f, 0x84, 0xa2, 0x74, 0x0f, 0x99, 0x3f, 0x52, \
	0xd0, 0xbe, 0x9a, 0x63, 0xbf, 0x39, 0xb3, 0x55, \
	0x81, 0x5d, 0xc2, 0xaa, 0x78, 0xfd, 0x3c, 0x75, \
	0x5b, 0xec, 0x1c, 0x3e, 0xfe, 0x04, 0x5a, 0xab, \
	0xbd, 0x0d, 0x66, 0x36, 0x37, 0x03, 0x45, 0x50  \
};


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

	SHA256 sha256 = NULL;


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
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

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
	ecall1_table.ms_wl_cert_chain	   = LE_white_list;
	ecall1_table.ms_wl_cert_chain_size = sizeof(LE_white_list);

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
	uint8_t token_buffer[1024];

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
