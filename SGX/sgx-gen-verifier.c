/** \file
 * This file contains a utility for converting an identity token into
 * an identity verifier token.  A token implements the information
 * needed to authenticate an identity but does not allow expression of
 * the identity.
 *
 * It does this by converting the identity element into a SHA256
 * compression of the identity.
 *
 * This version is specific to identities that are used to authenticate
 * the endpoints of an SGX PossumPipe connection.  The utility will
 * either use a software status provided on the command-line or will
 * abstract the measurement state if an enclave is specified.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define IVY_EXTENSION ".ivy"


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <IDtoken.h>
#include <RandomBuffer.h>
#include <SHA256.h>
#include <SoftwareStatus.h>
#include <Ivy.h>

#include "SGX.h"
#include "SGXenclave.h"
#include "SGXmetadata.h"


/**
 * Private function.
 *
 * This function is responsible for writing the ASN encoded identity verifier
 * to the file specified by the caller.
 *
 * \param asn		The encoded identity verifier to be written.
 *
 * \param token		The identity token which from which the verifier
 *			was derived.
 *
 * \param label		An optional label which will be appended to the
 *			filename.
 *
 * \return		A true value indicates the verifier was written.
 *			A false value indicates an error was encountered
 *			while writing the verifier.
 */

static _Bool write_identity(CO(Buffer, asn), CO(IDtoken, token), \
			    CO(char *, label))

{
	_Bool retn = false;

	char hex[3];

	unsigned char *p;

	uint8_t lp;

	uint32_t err = 0;

	Buffer b;

	SHA256 sha256;

	String filename = NULL;

	File output = NULL;


	INIT(NAAAIM, SHA256, sha256, goto done);
	INIT(HurdLib, String, filename, goto done);

	if ( (b = token->get_element(token, IDtoken_orgkey)) == NULL )
		ERR(goto done);
	sha256->add(sha256, b);

	if ( (b = token->get_element(token, IDtoken_orgid)) == NULL )
		ERR(goto done);
	sha256->add(sha256, b);

	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	p = b->get(b);

	for (lp= 0; lp < b->size(b); ++lp) {
		if ( snprintf(hex, sizeof(hex), "%02x", *p) >= sizeof(hex) )
			goto done;
		filename->add(filename, hex);
		++p;
	}
	filename->add(filename, IVY_EXTENSION);
	if ( label != NULL ) {
		filename->add(filename, ".");
		filename->add(filename, label);
	}
	if ( filename->poisoned(filename) )
		ERR(goto done);


	/* Output file. */
	INIT(HurdLib, File, output, goto done);

	output->open_rw(output, filename->get(filename));
	if ( !output->write_Buffer(output, asn) )
		ERR(goto done);

	filename->print(filename);
	retn = true;


 done:
	if ( err )
		fprintf(stderr, "Error: %s[%u]\n", __func__, err);
	WHACK(sha256);
	WHACK(filename);
	WHACK(output);

	return retn;
}


/*
 * Program entry point.
 */

extern int main(int argc, char *argv[])

{
	_Bool out_file = false;

	int opt,
	    retn = 1;

	uint32_t err = 0;

	char *measurement  = NULL,
	     *token_file   = NULL,
	     *label_name   = NULL,
	     *enclave_name = NULL;

	struct SGX_sigstruct sigstruct;

	FILE *id_file = NULL;

	Ivy ivy = NULL;

	Buffer bufr = NULL;

	String name = NULL;

	File file = NULL;

	IDtoken token = NULL;

	SoftwareStatus software = NULL;

	RandomBuffer rbufr = NULL;

	SGXmetadata metadata = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (opt = getopt(argc, argv, "fe:l:m:t:")) != EOF )
		switch ( opt ) {
			case 'f':
				out_file = true;
				break;

			case 'e':
				enclave_name = optarg;
				break;
			case 'l':
				label_name = optarg;
				break;
			case 'm':
				measurement = optarg;
				break;
			case 't':
				token_file = optarg;
				break;
		}


	/* Verify arguements. */
	if ( token_file == NULL ) {
		fputs("No identity token specified.\n", stderr);
		goto done;
	}

	if ( (enclave_name == NULL) && (measurement == NULL) ) {
		fputs("No measurement source specified.\n", stderr);
		goto done;
	}


	/* Parse and add the identity. */
	INIT(NAAAIM, Ivy, ivy, ERR(goto done));

	INIT(NAAAIM, IDtoken, token, goto done);
	if ( (id_file = fopen(token_file, "r")) == NULL )
		ERR(goto done);
	if ( !token->parse(token, id_file) )
		ERR(goto done);

	if ( !ivy->set_identity(ivy, token) )
		ERR(goto done);


	/* Add the software measurement. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( enclave_name != NULL ) {
		INIT(NAAAIM, SGXmetadata, metadata, ERR(goto done));
		if ( !metadata->load(metadata, enclave_name) ) {
			fprintf(stderr, "Unable to load %s metadata.\n", \
				enclave_name);
			goto done;
		}

		if ( !metadata->get_sigstruct(metadata, &sigstruct) ) {
			fputs("Unable to load signature information.\n", \
			      stderr);
			goto done;
		}

		if ( !bufr->add(bufr, sigstruct.enclave_hash, \
				sizeof(sigstruct.enclave_hash)) ) {
			fputs("Unable to set enclave measurement.\n", stderr);
			goto done;
		}
	} else {
		if ( strlen(measurement) != NAAAIM_IDSIZE*2 ) {
			fputs("Invalid measurement specified.\n", stderr);
			goto done;
		}
		if ( !bufr->add_hexstring(bufr, measurement ) ) {
			fputs("Unable to set measurement.\n", stderr);
			goto done;
		}
	}

	if ( !ivy->set_element(ivy, Ivy_software, bufr) )
		ERR(goto done);


	/* Encode the identity. */
	bufr->reset(bufr);
	if ( !ivy->encode(ivy, bufr) )
		ERR(goto done);


	/* Output the enclave verifier. */
	ivy->print(ivy);
	fputs("\nASN output:\n", stdout);
	if ( out_file )
		retn = write_identity(bufr, token, label_name);
	else {
		bufr->print(bufr);
		retn = 0;
	}


 done:
	if ( err )
		fprintf(stderr, "Error: %s[%u]\n", __func__, err);
	if ( id_file != NULL )
		fclose(id_file);

	WHACK(ivy);
	WHACK(bufr);

	WHACK(name);
	WHACK(file);
	WHACK(token);
	WHACK(software);
	WHACK(rbufr);
	WHACK(metadata);

	return retn;
}
