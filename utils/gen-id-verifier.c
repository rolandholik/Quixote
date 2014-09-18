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


extern int main(int argc, char *argv[])

{
	int retn = 1;

	char *token_file;

	FILE *file = NULL;

	IDtoken token = NULL;


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


	/* Reduce the identity token to its verifier form and print it. */
	if ( !token->to_verifier(token) )
		goto done;

	token->print(token);
	retn = 0;

		
 done:
	if ( file != NULL )
		fclose(file);
	WHACK(token);

	return retn;
}
