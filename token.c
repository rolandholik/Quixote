/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#define ID "8ef2928e3eb9fd0ee1a2b9f1112a48983128d903521034a449c880d1a8e64ac0"

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <Buffer.h>

#include "NAAAIM.h"
#include "IDtoken.h"
#include "Config.h"
#include "OrgID.h"


extern int main(int argc, char *argv[])

{
	auto _Bool parse  = false,
		   verify = false,
		   search = false;

	auto char *credential,
		  *anonymizer,
		  *npifile      = NULL,
		  *config 	= NULL,
		  *organization = NULL,
		  *token_file   = NULL,
		  npi[256];
		

	auto int retn = 1;

	auto FILE *infile  = NULL,
		  *tokenfp = NULL;

	auto Buffer anon = NULL;

	auto IDtoken token = NULL;

	auto Config parser = NULL;

	auto OrgID orgid = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "PSVc:f:o:t:")) != EOF )
		switch ( retn ) {
			case 'P':
				parse = true;
				break;
			case 'S':
				parse  = true;
				search = true;
				break;
			case 'V':
				parse  = true;
				verify = true;
				break;
			case 'c':
				config = optarg;
				break;
			case 'f':
				npifile = optarg;
				break;
			case 'o':
				organization = optarg;
				break;
			case 't':
				token_file = optarg;
				break;
		}

	if ( config == NULL )
		config = "./orgid.txt";


	if ( parse ) {
		if ( (token = NAAAIM_IDtoken_Init()) == NULL ) {
			fputs("Cannot initialize token.\n", stderr);
			goto done;
		}
		if ( token_file != NULL ) {
			if ( (tokenfp = fopen(token_file, "r")) == NULL ) {
				fputs("Cannot open token file.\n", stderr);
				goto done;
			}
		}
		else
			tokenfp = stdin;

		if ( !token->parse(token, tokenfp) ) {
			fputs("Error parsing token.\n", stderr);
			goto done;
		}
		if ( !verify && !search )
			token->print(token);
	}

	if ( verify ) {
		if ( organization == NULL ) {
			fputs("No organization specified.\n", stderr);
			goto done;
		}

		if ( (parser = HurdLib_Config_Init()) == NULL ) {
			fputs("Cannot initialize parser.\n", stderr);
			goto done;
		}

		if ( !parser->parse(parser, config) ) {
			fputs("Failed parsing of identity keys\n", stderr);
			goto done;
		}

		if ( !parser->set_section(parser, organization) ) {
			fputs("Organization section not found.\n", stderr);
			goto done;
		}
		if ( (credential = parser->get(parser, "credential")) == \
		     NULL ) {
			fputs("Cannot obtain credential.\n", stderr);
			goto done;
		}

		if ( (anon = HurdLib_Buffer_Init()) == NULL ) {
			fputs("Cannot create anonymizer buffer.\n", stderr);
			goto done;
		}
		anon->add_hexstring(anon, ID);
		anon->print(anon);

		if ( token->matches(token, anon) )
			fprintf(stdout, "Token matches organization: %s\n", \
				credential);
	}


	/* Match a token against a database of NPI providers. */
	if ( search ) {
		if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
			fputs("Cannot initialize organizational id.\n", \
			      stderr);
			goto done;
		}
		if ( npifile == NULL ) {
			fputs("No NPI reference file specifed.\n", stderr);
			goto done;
		}
		if ( (infile = fopen(npifile, "r")) == NULL ) {
			fputs("Error opening NPI reference file.\n", stderr);
			goto done;
		}

		while ( fgets(npi, sizeof(npi), infile) != NULL ) {
			if ( (anonymizer = strchr(npi, '\n')) != NULL )
				*anonymizer = '\0';
			if ( (anonymizer = strchr(npi, ' ')) == NULL ) {
				fputs("No NPI delimiter found\n", stderr);
				goto done;
			}

			*anonymizer++ = '\0';
			orgid->create(orgid, anonymizer, npi);

			if ( token->matches(token, \
					    orgid->get_Buffer(orgid)) ) {
				fprintf(stdout, "Matched: %s\n", npi);
				retn = 0;
				goto done;
			}
			orgid->reset(orgid);
		}
	}
	retn = 0;
			
		
 done:
	if ( anon != NULL )
		anon->whack(anon);
	if ( token != NULL )
		token->whack(token);
	if ( parser != NULL )
		parser->whack(parser);
	if ( orgid != NULL )
		orgid->whack(orgid);

	return retn;
}
