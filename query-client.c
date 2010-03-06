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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"
#include "IDqueryReply.h"


/* Variables static to this module. */
static unsigned int Ptid_cnt = 1;
static IDtoken *Ptid_list    = NULL;


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
			     const IDtoken const device,     \
			     const IDtoken const user)

{
	if ( !load_identity(device, devname) )
		return false;
	if ( !load_identity(user, username) )
		return false;

	return true;
}


/**
 * Private function.
 *
 * This function loads one or more identities for a filename provided by
 * the caller.  This function populates an array static to this file
 * with the set of identity tokens parsed from the file.
 *
 * \param file		A pointer to a null terminated file containing
 *			the name of the file to parse.
 *
 * \return		A boolean value is used to indicate whether or
 *			not loading of the file was successful.  A
 *			true value indicates the load was successful.
 */

static _Bool load_patient_identity(const char * const filename)

{
	auto _Bool retn = false;

	auto FILE *infile = NULL;

	auto IDtoken token;


	if ( (infile = fopen(filename, "r")) == NULL )
		goto done;

	while ( !feof(infile) ) {
		if ( (token = NAAAIM_IDtoken_Init()) == NULL )
			goto done;
		if ( !token->parse(token, infile) ) {
			token->whack(token);
			if ( feof(infile) )
				break;
			fputs("Error on parse.\n", stderr);
			goto done;
		}

		Ptid_list = realloc(Ptid_list, (Ptid_cnt+1) * sizeof(IDtoken));
		if ( Ptid_list == NULL )
			goto done;
		Ptid_list[Ptid_cnt - 1] = token;
		Ptid_list[Ptid_cnt]     = NULL;
		++Ptid_cnt;
	}

	fprintf(stdout, ".Loaded %d patient identity %s.\n", Ptid_cnt - 1, \
		Ptid_cnt == 2 ? "token" : "tokens");
	retn = true;


 done:
	if ( infile != NULL )
		fclose(infile);

	return retn;
}


/**
 * Private function.
 *
 * This function processes an identity query response.
 *
 * \param reply		The query which is to be processed.
 */

static void process_reply(const IDqueryReply const reply, \
			  const Buffer const host)

{
	auto int port;


	if ( reply->is_type(reply, IDQreply_notfound) ) {
		fputs(".No identity reply information available.\n", stdout);
		return;
	}


	/* Handle an IP address referral. */
	if ( reply->is_type(reply, IDQreply_ipredirect) ) {
		if ( !reply->get_ip_reply(reply, host, &port) )
			goto done;
		fprintf(stdout, ".Referral to %s at port %d.\n", \
			host->get(host), port);
	}


 done:
	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *config;

	auto int retn = 1;

	auto unsigned int lp = 0;

	auto time_t start_time;

	auto Buffer bufr = NULL;

	auto Config parser = NULL;

	auto Duct duct = NULL;

	auto IDtoken patient,
		     device  = NULL,
		     user    = NULL;

	auto Authenticator authn = NULL;

	auto IDqueryReply reply = NULL;


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
	if ( (device == NULL) || (user == NULL ) ) {
		fputs("Cannot initialize identity tokens\n", stderr);
		goto done;
	}
	if ( !load_identities("./device1.txt", "./user1.txt", device, user) ) {
		fputs("Error loading identities.\n", stderr);
		goto done;
	}

	if ( !load_patient_identity("./patient1.txt") ) {
		fputs("Error loading patient identity.\n", stderr);
		goto done;
	}


	/* Initialize SSL connection and attach to root referral server. */
	start_time = time(NULL);

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


	/*
	 * Send the number of identity query slots which we will request
	 * to be filled.
	 */
	fputs(">Sending query slots.\n", stderr);
	bufr->reset(bufr);
	lp = htonl(Ptid_cnt - 1);
	bufr->add(bufr, (unsigned char *) &lp, sizeof(lp));
	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("!Cannot send query slots.\n", stderr);
		goto done;
	}


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

	for (lp= 0; Ptid_list[lp] != NULL; ++lp) {
		patient = Ptid_list[lp];
		authn->add_element(authn, patient->get_element(patient, \
						       IDtoken_orgkey));
	}
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
	for (lp= 0; Ptid_list[lp] != NULL; ++lp) {
		patient = Ptid_list[lp];
		authn->add_element(authn, patient->get_element(patient, \
						       IDtoken_orgid));
	}
	authn->encrypt(authn, "./org-private.pem");
	bufr->reset(bufr);
	if ( !authn->encode(authn, bufr) ) {
		fputs("!Error encoding user authenticator.\n", stderr);
		goto done;
	}
	if ( !duct->send_Buffer(duct, bufr) )
		fputs("!Error transmitting device authenticator.\n", stderr);


	/* Receive the referrals. */
	if ( (reply = NAAAIM_IDqueryReply_Init()) == NULL ) {
		fputs("!Error initializing referral reply object.\n", stderr);
		goto done;
	}

	fputs("<Receiving referrals.\n", stdout);
	for (lp= 0; lp < (Ptid_cnt - 1); ++lp) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) ) {
			fputs("!Error receiving referrals.\n", stderr);
			goto done;
		}

		if ( !reply->decode(reply, bufr) ) {
			fputs("!Error decoding referral.\n", stderr);
			goto done;
		}
		
		fprintf(stdout, ".Processing referral %d.\n", lp);
		process_reply(reply, bufr);
	}

	retn = 0;


 done:
	fprintf(stdout, ".Query complete, time = %ld seconds.\n", \
		time(NULL) - start_time);

	if ( duct != NULL ) {
		if ( !duct->whack_connection(duct) )
			fputs("!Error closing connection.\n", stderr);
		duct->whack(duct);
	}

	if ( device != NULL )
		device->whack(device);
	if ( user != NULL )
		user->whack(user);

	if ( Ptid_list != NULL ) {
		for (lp= 0; Ptid_list[lp] != NULL; ++lp)
			Ptid_list[lp]->whack(Ptid_list[lp]);
		free(Ptid_list);
	}

	if ( parser != NULL )
		parser->whack(parser);
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( authn != NULL )
		authn->whack(authn);
	if ( reply != NULL )
		reply->whack(reply);

	return retn;
}