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


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <IDtoken.h>
#include <SHA256.h>


extern int main(int argc, char *argv[])

{
	int retn = 1;

	char *token_file;

	FILE *file = NULL;

	Buffer b,
	       orgkey	= NULL,
	       orgid	= NULL,
	       idkey	= NULL;

	IDtoken token = NULL;

	SHA256 mac = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "t:")) != EOF )
		switch ( retn ) {
			case 't':
				token_file = optarg;
				break;
		}

	if ( token_file == NULL ) {
		fputs("No token specified.\n", stdout);
		goto done;
	}


	/* Parse the token file. */
	INIT(NAAAIM, IDtoken, token, goto done);
	if ( (file = fopen(token_file, "r")) == NULL ) {
		fputs("Cannot open token file.\n", stdout);
		goto done;
	}
	if ( !token->parse(token, file) ) {
		fputs("Cannot parse token file.\n", stdout);
		goto done;
	}


	/* Get the token identity and hash it. */
	if ( (b = token->get_element(token, IDtoken_id)) == NULL ) {
		fputs("Cannot get token identity.\n", stderr);
		goto done;
	}

	INIT(NAAAIM, SHA256, mac, goto done);
	mac->add(mac, b);
	if ( !mac->compute(mac) ) {
		fputs("Error computing hash.\n", stdout);
		goto done;
	}

	/* Reset and reload the elements. */
	INIT(HurdLib, Buffer, orgkey, goto done);
	INIT(HurdLib, Buffer, orgid,  goto done);
	INIT(HurdLib, Buffer, idkey,  goto done);
	orgkey->add_Buffer(orgkey, token->get_element(token, IDtoken_orgkey));
	orgid->add_Buffer(orgid, token->get_element(token, IDtoken_orgid));
	idkey->add_Buffer(idkey, token->get_element(token, IDtoken_key));

	token->reset(token);
	token->set_element(token, IDtoken_orgkey, orgkey);
	token->set_element(token, IDtoken_orgid, orgid);
	token->set_element(token, IDtoken_id, mac->get_Buffer(mac));
	if ( !token->set_element(token, IDtoken_key, idkey) ) {
		fputs("Error setting token elements.\n", stderr);
		goto done;
	}

	token->print(token);
	retn = 0;
		
 done:
	if ( file != NULL )
		fclose(file);

	WHACK(orgkey);
	WHACK(orgid);
	WHACK(idkey);
	WHACK(token);
	WHACK(mac);

	return retn;
}
