/** \file
 * This file contains the implementation of a utility which generates
 * and manipulates SGX enclave metadata.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Definitions local to this file. */
#define PGM "sgx-metadata"
#define COPYRIGHT "2016,2017"


#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <SHA256.h>

#include "SGX.h"
#include "SGXenclave.h"
#include "SGXsigstruct.h"
#include "SGXmetadata.h"


/**
 * Internal public function.
 *
 * This method implements outputting of an error message and status
 * information on how to run the utility.
 *
 * \param err	A pointer to a null-terminated buffer holding the
 *		error message to be output.
 *
 * \return	No return value is defined.
 */

static void usage(char *err)

{
	fprintf(stdout, "%s: SGX enclave metadata utility.\n", PGM);
	fprintf(stdout, "%s: (C)%s IDfusion, LLC\n", PGM, COPYRIGHT);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("Modes:\n", stdout);
	fputs("\t-D:\tDump mode (default).\n", stdout);
	fputs("\t-S:\tSignature structure mode.\n", stdout);

	fputs("\nArguments:\n", stdout);
	fputs("\t-e:\tEnclave name.\n", stdout);
	fputs("\t-o:\tSignature structure output file.\n", stdout);

	return;
}


/**
 * Internal private function
 *
 * This function implements printing out of a character buffer.  It is
 * a utility function to simplify output for printing the fields of
 * the signature structure.
 *
 * \param bufr		A pointer to the buffer to be dumped.
 *
 * \param cnt		The length of the buffer in bytes.
 *
 * \return		No return value is defined.
 */

static void _print_buffer(CO(char *, prefix), CO(uint8_t *, bufr), size_t cnt)

{
	size_t lp;


	fputs(prefix, stdout);
	for (lp= 0; lp < cnt; ++lp) {
		fprintf(stdout, "%02x ", bufr[lp]);
		if ( (lp+1 < cnt) && ((lp+1) % 16) == 0 )
			fputs("\n\t", stdout);
	}
	fputc('\n', stdout);

	return;
}


/**
 * Internal public function.
 *
 * This method implements the signature mode of the utility.  This
 * mode implements printing out the signature structure or dumping
 * the structure in packed binary form.
 *
 * \param metadata	The object which represents the enclave
 *			metadata.
 *
 * \param output	A pointer to a null-terminated character buffer
 *			containing the name of the output file.  If
 *			the pointer is NULL the structure definition
 *			is printed.
 *
 * \return		The value to be returned by the main function
 *			is returned.
 */

static int signature_mode(SGXmetadata metadata, char *output)

{
	int retn = 1;

	struct SGX_sigstruct sigstruct,
			     *sp = &sigstruct;

	Buffer bufr = NULL;

	Sha256 sha256 = NULL;

	File outfile = NULL;


	/* Retrieve the signature structure. */
	if ( !metadata->get_sigstruct(metadata, sp) )
		ERR(goto done);


	/* Dump the structure to a binary file if requested. */
	if ( output != NULL ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		bufr->add(bufr, (void *) sp, sizeof(sigstruct));

		INIT(HurdLib, File, outfile, ERR(goto done));
		if ( !outfile->open_rw(outfile, output) )
			ERR(goto done);
		if ( !outfile->write_Buffer(outfile, bufr) )
			ERR(goto done);

		fprintf(stdout, "Wrote signature structure to %s.\n", output);
		retn = 0;
		goto done;
	}


	/* Print the metadata structure. */
	fputs("\nSIGSTRUCT:\n", stdout);
	fputs("header: ", stdout);
	_print_buffer("", sp->header, sizeof(sp->header));

	fprintf(stdout, "vendor: 0x%x\n", sp->vendor);
	fprintf(stdout, "date: %x\n", sp->date);
	fprintf(stdout, "hw version: 0x%x\n", sp->sw_defined);
	fprintf(stdout, "exponent: 0x%x\n", sp->exponent);

	fputs("modulus:\n", stdout);
	_print_buffer("\t", sp->modulus, sizeof(sp->modulus));

	fputs("signature:\n", stdout);
	_print_buffer("\t", sp->signature, sizeof(sp->signature));

	fprintf(stdout, "misc select: 0x%0x\n", sp->miscselect);
	fprintf(stdout, "misc mask: 0x%0x\n", sp->miscmask);

	fputs("attributes:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attributes.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attributes.xfrm);

	fputs("attribute mask:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", sp->attribute_mask.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", sp->attribute_mask.xfrm);

	fputs("enclave measurement:\n", stdout);
	_print_buffer("\t", sp->enclave_hash, sizeof(sp->enclave_hash));

	fprintf(stdout, "isv prodid: 0x%0x\n", sp->isv_prodid);
	fprintf(stdout, "isv svn: 0x%0x\n", sp->isv_svn);

	fputs("key q1:\n", stdout);
	_print_buffer("\t", sp->q1, sizeof(sp->q1));

	fputs("key q2:\n", stdout);
	_print_buffer("\t", sp->q2, sizeof(sp->q2));

	/* Output the MRSIGNER value. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	if ( !bufr->add(bufr, (unsigned char *) sigstruct.modulus, \
			sizeof(sigstruct.modulus)) )
		ERR(goto done);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	fputs("\nmrsigner:\n", stdout);
	_print_buffer("\t", sha256->get(sha256), 32);


 done:
	WHACK(bufr);
	WHACK(sha256);
	WHACK(outfile);

	return retn;
}


/*
 * Main program.
 */

int main(int argc, char *argv[])

{
	char *enclave_name = NULL,
	     *output_file  = NULL;

	int opt,
	    retn = 1;

	enum {
		dump,
		signature
	} mode = dump;

	SGXmetadata metadata = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "DSe:o:")) != EOF )
		switch ( opt ) {
			case 'D':
				mode = dump;
				break;
			case 'S':
				mode = signature;
				break;

			case 'e':
				enclave_name = optarg;
				break;
			case 'o':
				output_file = optarg;
				break;
		}


	/* Load the metadata .*/
	if ( enclave_name == NULL ) {
		usage("No enclave name specified.\n");
		goto done;
	}

	INIT(NAAAIM, SGXmetadata, metadata, ERR(goto done));
	if ( !metadata->load(metadata, enclave_name) ) {
		fprintf(stderr, "Unable to load metadata for enclave %s.\n", \
			enclave_name);
		goto done;
	}


	/* Metadata dump mode. */
	if ( mode == dump ) {
		fprintf(stdout, "ENCLAVE:\n%s\n\n", enclave_name);
		metadata->dump(metadata);
		retn = 0;
	}


	/* Signature structure mode. */
	if ( mode == signature ) {
		retn = signature_mode(metadata, output_file);
	}


 done:
	WHACK(metadata);

	return retn;
}
