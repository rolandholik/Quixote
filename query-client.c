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
#include <time.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"


/**
 * Private function.
 *
 * This is a utility function which prints the contents of a text
 * buffer received from a server.
 *
 * \param bufr	The buffer object containing the text to be printed.
 */

static void print_buffer(const Buffer const bufr)

{
	auto char *p,
		  *begin,
		  pbufr[160];


	/* Sanity check. */
	if ( bufr->size(bufr) > 160 ){
		fputs(".reply too long to print", stdout);
		return;
	} 


	/*
	 * Copy the buffer and loop through it prepending a token to
	 * indicate this is an incoming response.
	 */
	memcpy(pbufr, bufr->get(bufr), bufr->size(bufr));

	begin = pbufr;
	do {
		if ( (p = strchr(begin, '\n')) != NULL ) {
			*p = '\0';
			fprintf(stdout, "<%s\n", begin);
			begin = p;
			++begin;
		}
	} while ( p != NULL );

	return;
}


/**
 * Private function.
 *
 * This function encapsulates opening the file containing the identity
 * token and parsin of the file.
 *
 * \param token		The identity token which the file contents is
 *			to be parsed into.
 *
 * \param file		A pointer to a null terminated behavior
 *			containing the name of the file to be parsed.
 *
 * \return		A boolean value is used to indicate whether or
 *			not loading of the file was successful.  A
 *			true value indicates the load was successful.
 */

static _Bool load_identity(const IDtoken const token, \
			   const char * const filename)

{
	auto _Bool retn = false;

	auto FILE *infile = NULL;


	if ( (infile = fopen(filename, "r")) == NULL )
		goto done;

	if ( !token->parse(token, infile) )
		goto done;

	retn = true;


 done:
	if ( infile != NULL )
		fclose(infile);

	return retn;
}


/**
 * Private function.
 *
 * This function parses the three identities which are needed to
 * initiate an identity query.
 *
 * \param devname	A pointer to a null terminated buffer containing
 *			the name of the file holding the device identity
 *			token.
 *
 * \param username	A pointer to a null terminated buffer containing
 *			the name of the file holding the user identity
 *			token.
 *
 * \param patientname	A pointer to a null terminated buffer containing
 *			the name of the file holding the patient identity
 *			token.
 *
 * \param device	The identity token to be loaded with the device
 *			identity.
 *
 * \param user		The identity token to be loaded with the user
 *			identity.
 *
 * \param patient	The identity token to be loaded with the
 *			patient identity.
 *
 * \return		A boolean value is used to return the success or
 *			failure of the token loading.  A true value is
 *			used to indicate success.
 */

static _Bool load_identities(const char * const devname,     \
			     const char * const username,    \
			     const char * const patientname, \
			     const IDtoken const device,     \
			     const IDtoken const user,	     \
			     const IDtoken const patient)

{
	if ( !load_identity(device, devname) )
		return false;
	if ( !load_identity(user, username) )
		return false;
	if ( !load_identity(patient, patientname) )
		return false;

	return true;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *config;

	auto int retn = 1;

	auto time_t start_time;

	auto Buffer bufr = NULL;

	auto Config parser = NULL;

	auto Duct duct = NULL;

	auto IDtoken device  = NULL,
		     user    = NULL,
		     patient = NULL;

	auto Authenticator authn = NULL;


	fputs("NAAAIM query client.\n\n", stdout);

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


	/* Load identities. */
	device	= NAAAIM_IDtoken_Init();
	user	= NAAAIM_IDtoken_Init();
	patient = NAAAIM_IDtoken_Init();
	if ( (device == NULL) || (user == NULL ) || (patient == NULL) ) {
		fputs("Cannot initialize identity tokens\n", stderr);
		goto done;
	}
	if ( !load_identities("./device1.txt", "./user1.txt", \
			      "./patient1.txt", device, user, patient) ) {
		fputs("Error loading identities.\n", stderr);
		goto done;
	}

	start_time = time(NULL);


	/* Initialize SSL connection and attach to root referral server. */
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

	fputs(".Connecting to root referral server.\n", stdout);
	if ( !duct->init_connection(duct) ) {
		fputs("Cannot initialize connection.\n", stderr);
		goto done;
	}


	/* Obtain connection banner. */
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("!Error receiving connection banner.\n", stderr);
		goto done;
	}
	bufr->add(bufr, (unsigned char *) "\0", sizeof(1));
	print_buffer(bufr);


	/* Initialize an authenticator object. */
	if ( (authn = NAAAIM_Authenticator_Init()) == NULL ) {
		fputs("!Cannot initialize authenticator.\n", stderr);
		goto done;
	}


	/* Initialize and load device identity. */
	if ( !authn->add_identity(authn, device) ) {
		fputs("!Cannot add device identity.\n", stderr);
		goto done;
	}

	authn->add_element(authn, patient->get_element(patient, \
						       IDtoken_orgkey));
	authn->encrypt(authn, "./org-private.pem");

	fputs(">Sending device authenticator.\n", stdout);
	bufr->reset(bufr);
	if ( !authn->encode(authn, bufr) ) {
		fputs("!Error encoding device authenticator.\n", stderr);
		goto done;
	}
	if ( !duct->send_Buffer(duct, bufr) )
		fputs("!Error transmitting device authenticator.\n", stderr);


	/* Send the user authenticator. */
	fputs(">Sending user authenticator.\n", stdout);
	authn->reset(authn);
	authn->add_identity(authn, user);
	authn->add_element(authn, patient->get_element(patient, \
						       IDtoken_orgid));
	authn->encrypt(authn, "./org-private.pem");
	bufr->reset(bufr);
	if ( !authn->encode(authn, bufr) ) {
		fputs("!Error encoding user authenticator.\n", stderr);
		goto done;
	}
	if ( !duct->send_Buffer(duct, bufr) )
		fputs("!Error transmitting device authenticator.\n", stderr);

	retn = 0;


 done:
	fprintf(stdout, ".Query complete, time = %ld seconds.\n", \
		time(NULL) - start_time);

	if ( !duct->whack_connection(duct) )
		fputs("!Error closing connection.\n", stderr);

	if ( device != NULL )
		device->whack(device);
	if ( user != NULL )
		user->whack(user);
	if ( patient != NULL )
		patient->whack(patient);

	if ( parser != NULL )
		parser->whack(parser);
	if ( duct != NULL )
		duct->whack(duct);
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( authn != NULL )
		authn->whack(authn);

	return retn;
}
