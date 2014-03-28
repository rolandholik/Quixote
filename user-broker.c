/** \file
 * This file contains an implementation of the user identity broker
 * server.   This server is responsible for arbitrating identity
 * authentication requests for a user.
 *
 * The server accepts an identity broker request which consists of
 * a user authenticator.  The authenticator is decrypted and
 * converted into an identity token.  The identity token is then used
 * to search for a match in the set of organizations managed by this
 * server.
 *
 * If a match is found the identity is decrypted and validated.  If
 * the identity is authentic and authorized the identity elements
 * are decrypted and returned to the caller.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "User Authentication Broker"

#define INSTALL_DIR "/opt/NAAAIM"
#define USER_FILE   INSTALL_DIR "/lib/user/user-search.txt"
#define CONFIG_FILE INSTALL_DIR "/etc/user-broker.conf"


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SSLDuct.h"
#include "IDtoken.h"
#include "Authenticator.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "RSAkey.h"
#include "AuthenReply.h"


/* Variables static to this module. */
static pid_t process_table[100];


/**
 * Private function.
 *
 * This function initializes the process table.
 */

static void init_process_table(void)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		process_table[lp] = 0;
	return;
}


/**
 * Private function.
 *
 * This function adds an entry to the process state table.  It will
 * locate an empy slot in the table and place the PID of the dispatched
 * process in that slot.
 *
 * \param pid	The process ID to be placed in the table.
 */

static void add_process(pid_t pid)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		if ( process_table[lp] == 0 ) {
			process_table[lp] = pid;
			return;
		}
	return;
}


/**
 * Private function.
 *
 * This function reaps any available processes and updates its slot in
 * the process table.
 */

static void update_process_table(void)

{
	auto unsigned int lp;

	auto int pid,
		 status;


	while ( (pid = waitpid(-1, &status, WNOHANG)) > 0 )
		for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
			if ( process_table[lp] == pid ) {
				process_table[lp] = 0;
				fprintf(stdout, "%d terminated", pid);
				if ( !WIFEXITED(status) ) {
					fputs(" abnormally\n", stdout);
					continue;
				}
				fprintf(stdout, ", status = %d\n", \
					WEXITSTATUS(status));
			}
	return;
}




/**
 * Private function.
 *
 * This function is responsible for determining whether or not the
 * user is authorized to request queries.  The contents of the
 * intrinsic identity is extracted and the hash of the ephemeralizer
 * is computed.  The intrinsic identity and the ephemeralizer hash are
 * used to determine the status of the user.
 *
 * \param token		The identity token to be encrypted.
 *
 * \param rsakey	A null-terminated character buffer containing the
 *			name of the RSA public key to be used for
 *			decrypting the intrinsic identity.
 *
 * \return		A boolean return value is used to indicate whether
 *			or not authorization was successful.  A true
 *			value is used to indicate the user is
 *			authorized to conduct queries.
 */

static _Bool authorize_identity(const IDtoken const token, \
				const Buffer const bufr)

{
	auto _Bool retn = false;

	auto Buffer bf;

	auto SHA256 sha256;


	if ( (bf = token->get_element(token, IDtoken_id)) == NULL ) {
		fputs("Cannot access intrinsic identity.\n", stderr);
		goto done;
	}

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Cannot initialize hash object.\n", stderr);
		goto done;
	}
	bufr->reset(bufr);
	bufr->add(bufr, bf->get(bf) + (256 / 8), 512 / 8);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) ) {
		fputs("Error computing ephemeralizer hash.\n", stderr);
		goto done;
	}

	bufr->reset(bufr);
	bufr->add(bufr, bf->get(bf), 256 / 8);

	fputs(".User is authorized.\n", stdout);
	fputs(".ii: ", stdout);
	bufr->print(bufr);
	fputs(".ei: ", stdout);
	sha256->print(sha256);

	retn = true;

 done:
	if ( sha256 != NULL )
		sha256->whack(sha256);

	return retn;
}
	

/**
 * Private function.
 *
 * This function is responsible for extracting and authenticating the
 * intrinsic identity from the identity token.
 *
 * In order to be authentic the RSA decryption of the intrinsic identity
 * and ephemeralizer must be successful.  The first component hash
 * of the ephemeralizer is computed and compared to the orgkey element
 * of the identity token which it must match.
 *
 * \param token		The identity token to be encrypted.
 *
 * \param rsakey	A null-terminated character buffer containing the
 *			name of the RSA public key to be used for
 *			decrypting the intrinsic identity.
 *
 * \param bufr		A Buffer object which is passed to the function
 *			for working purposes in order to avoid an
 *			allocation in this function.
 *
 * \return		A boolean return value is used to indicate whether
 *			or not the decryption was successful.  A true
 *			value indicates the buffer contains a valid
 *			identity.
 */

static _Bool authenticate_identity(const IDtoken const token,  \
				   const char * const rsafile, \
				   const Buffer const bufr)

{
	auto _Bool retn = false;

	auto Buffer bf;

	auto RSAkey rsa = NULL;

	auto SHA256 sha256 = NULL;


	if ( (rsa = NAAAIM_RSAkey_Init()) == NULL )
		goto done;
	if ( !rsa->load_public_key(rsa, rsafile) ) { 
		fputs("Cannot load public key.\n", stderr);
		goto done;
	}

	if ( (bf = token->get_element(token, IDtoken_id)) == NULL ) {
		fputs("Failed extract intrinsic identity.\n", stdout);
		goto done;
	}
	if ( !rsa->decrypt(rsa, bf) ) {
		fputs("Failed phase 1 authentication.\n", stderr);
		goto done;
	}

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("SHA256 object creation failed.\n", stderr);
		goto done;
	}
	bufr->reset(bufr);
	bufr->add(bufr, bf->get(bf) + (256 / 8), 256 / 8);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) ) {
		fputs("Failed hash generation.\n", stderr);
		goto done;
	}

	if ( (bf = token->get_element(token, IDtoken_orgkey)) == NULL ) {
		fputs("Failed to load orgkey\n", stderr);
		goto done;
	}

	if ( memcmp(sha256->get(sha256), bf->get(bf), bf->size(bf)) != 0 ) {
		fputs("Phase two authentication failed.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( rsa != NULL )
		rsa->whack(rsa);
	if ( sha256 != NULL )
		sha256->whack(sha256);

	return retn;
}
	

/**
 * Private function.
 *
 * This function searches for the organizational identity which generated
 * the identity contained in the authenticator.
 *
 * \param token		The identity token whose originating organization
 *			is to be found.
 *
 * \param bufr		A Buffer object which will be loaded with the
 *			intrinsic identity contained in the RSA
 *			encrypted portion of the authenticator.
 *
 * \return		A boolean value is used to indicate whether or not
 *			an orginating organizational identity was
 *			found.  A true value indicates success.
 */

static _Bool search_for_organization(const IDtoken const token, \
				     const Buffer const bufr)

{
	auto _Bool retn = false;

	auto char *rsafile,
		  orgid[256];

	auto FILE *infile = NULL;

	auto Buffer bf = NULL;

	auto SHA256_hmac hmac = NULL;


	bf = token->get_element(token, IDtoken_orgkey);
	if ( (hmac = NAAAIM_SHA256_hmac_Init(bf)) == NULL ) {
		fputs("Cannot initialize hash object.\n", stderr);
		goto done;
	}

	if ( (infile = fopen(USER_FILE, "r")) == NULL ) {
		fputs("Error opening search file.\n", stderr);
		goto done;
	}

	bf = token->get_element(token, IDtoken_orgid);
	while ( fgets(orgid, sizeof(orgid), infile) != NULL ) {
		if ( (rsafile = strchr(orgid, '\n')) != NULL )
			*rsafile = '\0';
		if ( (rsafile = strchr(orgid, ' ')) == NULL ) {
			fputs("No NPI delimiter found\n", stderr);
			goto done;
		}
		*rsafile++ = '\0';

		bufr->add_hexstring(bufr, orgid);
		hmac->add_Buffer(hmac, bufr);
		if ( !hmac->compute(hmac) ) {
			fputs("Error computing organizational identity.\n", \
			      stderr);
			goto done;
		}
		if ( memcmp(bf->get(bf), hmac->get(hmac), bf->size(bf)) \
		     == 0 ) {
			bufr->reset(bufr);
			bufr->add(bufr, (unsigned char *) rsafile, \
				  strlen(rsafile) + 1);
			retn = true;
			goto done;
		}
		bufr->reset(bufr);
		hmac->reset(hmac);
	}


 done:
	if ( infile != NULL )
		fclose(infile);
	if ( hmac != NULL )
		hmac->whack(hmac);

	return retn;
}


/**
 * Private function.
 *
 * This function is called after a fork to handle an accepted connection.
 *
 * \param duct		The SSL connection object describing the accepted
 *			connection.
 *
 * \param config	The object managing configuration for the user
 *			broker.
 *
 * \return	A value of zero is used to indicate the connection has
 *		been handled successfully.  A value of 1 indicates
 *		connection handling has failed.
 */

static int handle_connection(const SSLDuct const duct, \
			     const Config const config)

{
	auto char *key,
		  *site,
		  *location,
		  banner[256];

	auto int retn = 1;

	auto Buffer bufr = NULL;

	auto Authenticator authn = NULL;

	auto IDtoken token = NULL;

	auto AuthenReply reply = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;
	if ( (authn = NAAAIM_Authenticator_Init()) == NULL )
		goto done;
	if ( (token = NAAAIM_IDtoken_Init()) == NULL )
		goto done;
	if ( (reply = NAAAIM_AuthenReply_Init()) == NULL )
		goto done;


	/* Abstract and verify configuration information. */
	if ( (key = config->get(config, "user_public_key")) == NULL ) {
		fputs("!User public key not defined.\n", stderr);
		goto done;
	}

	if ( (site = config->get(config, "site")) == NULL )
		site = "UNKNOWN";
	if ( (location = config->get(config, "location")) == NULL )
		location = "UNKNOWN";
		

	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\nHello\n", SERVER, \
		 site, location);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Read and process user authenticator. */
	fputs("<Receiving user authenticator.\n", stdout);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;

	if ( !authn->decode(authn, bufr) ) {
		fputs("Failed decode.\n", stderr);
		goto done;
	}

	if ( !authn->decrypt(authn, key) ) {
		fputs("Failed decryption of authenticator.\n", stderr);
		goto done;
	}

	authn->get_identity(authn, token);
	if ( !search_for_organization(token, bufr) ) {
		fputs("User organization not found.\n", stderr);
		goto done;
	}
	fputs(".User organization found.\n", stdout);

	memcpy(banner, bufr->get(bufr), bufr->size(bufr));
	if ( !authenticate_identity(token, banner, bufr) )
		goto done;
	fputs(".User is authenticated.\n", stdout);

	if ( !authorize_identity(token, bufr) ) {
		fputs("User is not authorized.\n", stderr);
		goto done;
	}


	/* Return the identity elements. */
	fputs(">Returning identity elements.\n", stdout);
	bufr->reset(bufr);
	if ( !authn->get_element(authn, bufr) ) {
		fputs("Cannot retrieve identity element.\n", stderr);
		goto done;
	}

	reply->add_elements(reply, bufr);
	bufr->reset(bufr);
	if ( !reply->encode(reply, bufr) ) {
		fputs("Error encoding authentication response.\n", stderr);
		goto done;
	}

	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("Error returning user identity element.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( authn != NULL )
		authn->whack(authn);
	if ( token != NULL )
		token->whack(token);
	if ( reply != NULL )
		reply->whack(reply);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *err		   = NULL,
		  *config_file	   = NULL;

	auto int port,
		 retn = 1;

	auto pid_t pid;

	auto Config config = NULL;

	auto SSLDuct duct = NULL;


	fprintf(stdout, "%s started.\n", SERVER);
	fflush(stdout);

	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "c:")) != EOF )
		switch ( retn ) {

			case 'c':
				config_file = optarg;
				break;
		}
	retn = 1;


	/* Load configuration. */
	if ( config_file == NULL )
		config_file = CONFIG_FILE;

	if ( (config = HurdLib_Config_Init()) == NULL ) {
		err = "Error initializing configuration.";
		goto done;
	}

	if ( !config->parse(config, config_file) ) {
		err = "Error parsing configuration file.";
		goto done;
	}


	/* Initialize process table. */
	init_process_table();


	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_SSLDuct_Init()) == NULL ) {
		err = "Error on SSL object creation.";
		goto done;
	}

	if ( !duct->init_server(duct) ) {
		err = "Cannot initialize server mode.";
		goto done;
	}

	if ( !duct->load_credentials(duct, config->get(config, "serverkey"), \
				     config->get(config, "certificate")) ) {
	     err = "Cannot load server credentials.";
	     goto done;
	}

	port = atoi(config->get(config, "port"));
	if ( !duct->init_port(duct, NULL, port) ) {
		err = "Cannot initialize port.";
		goto done;
	}

	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			err = "Error on SSL connection accept.";
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			err = "Connection fork failure.";
			goto done;
		}
		if ( pid == 0 ) {
			if ( handle_connection(duct, config) )
				retn = 0;
			goto done;
		}

		add_process(pid);
		update_process_table();
		duct->reset(duct);
	}


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	if ( duct != NULL ) {
		if ( !duct->whack_connection(duct) )
			fputs("Error closing connection.\n", stderr);
		duct->whack(duct);
	}

	if ( config != NULL )
		config->whack(config);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
