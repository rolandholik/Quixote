/** \file
 * This file contains an implementation of the identity query client.
 * This application is responsible for initating an identity query
 * onto the identity referral network.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"


/**
 * Private function.
 *
 * This function parses an identity from the specified file.
 *
 * \param token		A token parsing object into which the identity
 *			is to be loaded.
 *
 * \param idfile	A pointer to a null terminated buffer containing
 *			the name of the identity token file to be
 *			parsed.
 *
 * \return		A boolean value is used to return the success or
 *			failure of the token loading.  A true value is
 *			used to indicate success.
 */

static _Bool load_identity(const IDtoken token, const char * const idfile)

{
	auto _Bool retn = false;

	auto FILE *infile = NULL;


	if ( (infile = fopen(idfile, "r")) == NULL )
		goto done;

	if ( !token->parse(token, infile) )
		goto done;

	retn = true;


 done:
	if ( infile != NULL )
		fclose(infile);
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *config;

	auto int retn = 1;

	auto Buffer bufr = NULL;

	auto Config parser = NULL;

	auto Duct duct = NULL;

	auto IDtoken token = NULL;

	auto Authenticator authn = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "c:")) != EOF )
		switch ( retn ) {

			case 'c':
				config = optarg;
				break;
		}
	retn = 1;

	if ( config == NULL )
		config = "./query-client.conf";


	if ( (bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot initialize receive buffer.\n", stderr);
		goto done;
	}

	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !duct->init_client(duct) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !duct->load_certificates(duct, "./org-cert.pem") ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !duct->init_port(duct, "localhost", 11990) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	if ( !duct->init_connection(duct) ) {
		fputs("Cannot initialize connection.\n", stderr);
		goto done;
	}


	/* Obtain connection banner. */
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("Error on receive.\n", stderr);
		goto done;
	}
	bufr->add(bufr, (unsigned char *) "\0", sizeof(1));
	fprintf(stdout, "%s", bufr->get(bufr));


	/* Initialize an authenticator object. */
	if ( (authn = NAAAIM_Authenticator_Init()) == NULL ) {
		fputs("Cannot initialize authenticator.\n", stderr);
		goto done;
	}


	/* Initialize and load device identity. */
	if ( (token = NAAAIM_IDtoken_Init()) == NULL ) {
		fputs("Cannot initialize identity token.\n", stderr);
		goto done;
	}
	if ( !load_identity(token, "./device1.txt") ) {
		fputs("Cannot load device identity.\n", stderr);
		goto done;
	}

	if ( !authn->add_identity(authn, token) ) {
		fputs("Cannot add device identity.\n", stderr);
		goto done;
	}

	token->reset(token);
	if ( !load_identity(token, "./user1.txt") ) {
		fputs("Cannot load user identity.\n", stderr);
		goto done;
	}

	authn->add_element(authn, token->get_element(token, IDtoken_orgkey));
	authn->encrypt(authn, "./org-private.pem");

	fputs("\nSending device authenticator.\n", stdout);
	bufr->reset(bufr);
	if ( !authn->encode(authn, bufr) ) {
		fputs("Error encoding device authenticator.\n", stderr);
		goto done;
	}
	if ( !duct->send_Buffer(duct, bufr) )
		fputs("Error transmitting device authenticator.\n", stderr);


	/* Send the user authenticator. */
	fputs("Sending user authenticator\n", stdout);
	authn->reset(authn);
	authn->add_identity(authn, token);
	authn->add_element(authn, token->get_element(token, IDtoken_orgkey));
	authn->encrypt(authn, "./org-private.pem");
	bufr->reset(bufr);
	if ( !authn->encode(authn, bufr) ) {
		fputs("Error encoding user authenticator.\n", stderr);
		goto done;
	}
	if ( !duct->send_Buffer(duct, bufr) )
		fputs("Error transmitting device authenticator.\n", stderr);


 done:
	if ( !duct->whack_connection(duct) )
		fputs("Error closing connection.\n", stderr);

	if ( parser != NULL )
		parser->whack(parser);
	if ( duct != NULL )
		duct->whack(duct);
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( token != NULL )
		token->whack(token);
	if ( authn != NULL )
		authn->whack(authn);

	return retn;
}
