/** \file
 * This file contains a utility for converting an identity token into
 * an identity verifier token.  A token implements the information
 * needed to confirm an identity but does not allow expression of the
 * identity.
 *
 * It does this by converting the identity element into a SHA256
 * compression of the identity.
 *
 * a tunnel mode (ESP) connection to a host device.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
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

#include "IDmgr.h"
#include "Ivy.h"
#include "TPMcmd.h"


/* Macro for setting error location. */
#define ERR(action) {err = __LINE__; action;}


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


extern int main(int argc, char *argv[])

{
	_Bool out_file	= false,
	      use_idmgr = false;

	int opt,
	    retn = 1;

	uint32_t err = 0;

	char *token_file = NULL,
	     *key_file	 = NULL,
	     *uuid_file	 = NULL,
	     *label_name = NULL;

	FILE *id_file = NULL;

	Ivy ivy = NULL;

	Buffer bufr = NULL,
	       uuid = NULL;

	String name = NULL;

	File file = NULL;

	IDtoken token = NULL;

	IDmgr idmgr = NULL;

	SoftwareStatus software = NULL;

	TPMcmd tpmcmd = NULL;

	RandomBuffer rbufr = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (opt = getopt(argc, argv, "fmk:l:t:u:")) != EOF )
		switch ( opt ) {
			case 'f':
				out_file = true;
				break;
			case 'm':
				use_idmgr = true;
				break;

			case 'k':
				key_file = optarg;
				break;
			case 'l':
				label_name = optarg;
				break;
			case 't':
				token_file = optarg;
				break;
			case 'u':
				uuid_file = optarg;
				break;
		}

	if ( !use_idmgr && token_file == NULL ) {
		fputs("No token specified.\n", stderr);
		ERR(goto done);
	}
	if ( uuid_file == NULL ) {
		fputs("No uuid specified.\n", stderr);
		ERR(goto done);
	}


	/* Parse and add the identity. */
	INIT(NAAAIM, Ivy, ivy, goto done);

	INIT(NAAAIM, IDtoken, token, goto done);
	if ( !use_idmgr ) {
		if ( (id_file = fopen(token_file, "r")) == NULL )
			ERR(goto done);
		if ( !token->parse(token, id_file) )
			ERR(goto done);
	} else {
		INIT(NAAAIM, IDmgr, idmgr, goto done);
		if ( (name = HurdLib_String_Init_cstr("device")) == NULL )
			ERR(goto done);

		if ( !idmgr->attach(idmgr) )
			ERR(goto done);
		if ( !idmgr->get_idtoken(idmgr, name, token) )
			ERR(goto done);
	}

	if ( !ivy->set_identity(ivy, token) )
		ERR(goto done);


	/* Get the UUID to use. */
	INIT(HurdLib, File, file, goto done);
	INIT(HurdLib, Buffer, uuid, goto done);

	file->open_ro(file, uuid_file);
	if ( !file->slurp(file, uuid) )
		ERR(goto done);
	file->reset(file);
	

	/* Add the attestation identity key. */
	INIT(NAAAIM, TPMcmd, tpmcmd, goto done);
	INIT(HurdLib, Buffer, bufr, goto done);
	if ( key_file == NULL ) {
		if ( !tpmcmd->get_pubkey(tpmcmd, uuid, bufr) )
			ERR(goto done);
	} else {
		file->open_ro(file, key_file);
		if ( !file->slurp(file, bufr) )
			goto done;
		file->reset(file);
	}

	if ( bufr->size(bufr) == 0 )
		ERR(goto done);
	if ( !ivy->set_element(ivy, Ivy_pubkey, bufr) )
		ERR(goto done);


	/* Add the software measurement. */
	INIT(NAAAIM, SoftwareStatus, software, goto done);
        if ( !software->open(software) )
                ERR(goto done);
        if ( !software->measure(software) )
                ERR(goto done);
	if ( !ivy->set_element(ivy, Ivy_software, \
			       software->get_template_hash(software)) )
		ERR(goto done);


	/* Add the machine quote. */
	INIT(NAAAIM, RandomBuffer, rbufr, goto done);

	bufr->reset(bufr);
	rbufr->generate(rbufr, 20);
	if ( !bufr->add_Buffer(bufr, rbufr->get_Buffer(rbufr)) )
		ERR(goto done);
	if ( !tpmcmd->pcrmask(tpmcmd, 10, 15, 17, 18, -1) )
		ERR(goto done);
	if ( !tpmcmd->generate_quote(tpmcmd, uuid, bufr) )
		ERR(goto done);
	if ( !ivy->set_element(ivy, Ivy_reference, bufr) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !ivy->encode(ivy, bufr) )
		ERR(goto done);

	/* Output the quote. */
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
	WHACK(uuid);
	       
	WHACK(file);
	WHACK(token);
	WHACK(idmgr);
	WHACK(software);
	WHACK(tpmcmd);
	WHACK(rbufr);

	return retn;
}
