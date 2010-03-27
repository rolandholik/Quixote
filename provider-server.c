/** \file
 * This file contains an implementation of the provider server.  This
 * server is responsible for providing respones to a query client
 * which has received an ip referral in response to an identity query.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "Identity Provider Query Server"

#define INSTALL_DIR "/opt/NAAAIM"
#define CONFIG_FILE INSTALL_DIR "/etc/provider-server.conf"

#define FAILED "Failed.\n"
#define SUCCESS "OK.\n"


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
#include <String.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "DBduct.h"
#include "RSAkey.h"
#include "SHA256.h"
#include "ProviderQuery.h"


/* Variables static to this module. */
static pid_t process_table[100];

static Config Sconfig = NULL;


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
 * This function sends an e-mail to initiate an SMS message to a
 * provider.
 *
 * \param db		The database object which will be used to
 *			obtain patient information for the referral.
 *
 * \param ptid		The database id number assigned to the patient.
 *
 * \param address	The address to which the SMS message is to be
 *			sent.
 *
 * \param verifier	The numeric verifier code to be transmitted
 *			with the SMS message.
 *
 * \return		A boolean value is used to indicate the success
 *			or failure of initiating the message.  A true
 *			value is used to indicate the message was
 *			successfully sent.
 */

static _Bool send_sms_message(const DBduct const db, long int const ptid, \
			      const String const address, int const verifier)

{
	auto char bufr[256];

	auto FILE *mailer = NULL;


	snprintf(bufr, sizeof(bufr), "mail -I /home/greg/.mushrc-provider " \
		 "%s", address->get(address));
	if ( (mailer = popen(bufr, "w")) == NULL )
		return false;

	fputs("Follow up for clinical query from EMT-Intermediate.\n", mailer);
	fprintf(mailer, "Verifier code: %X\n", verifier);

	/* Query for the patient name. */
	fputs("Patient: ", mailer);
	snprintf(bufr, sizeof(bufr), "select * from name where id = %ld", \
		 ptid);
	if ( db->query(db, bufr) == 1 )
		fprintf(mailer, "%s\n", db->get_element(db, 0, 0));
	else
		fputs("not available.\n", mailer);


	if ( pclose(mailer) == -1 )
		return false;

	fprintf(stdout, ".Forwarded SMS message to: %s\n", \
		address->get(address));

	return true;
}


/**
 * Private helper function.
 *
 * This function assists the verify_patient_identity function by
 * determining if the encoded patient identity is authorized.  This
 * is done by computing the hash over the 512 bit none in the
 * encrypted patient idnetity.  The identity authorization database is
 * queried to determine if this hash value exists in the database.
 *
 * \param db		The database connection used to carry out the
 *			authorization.
 *
 * \param bufr		The decrypted patient identity token.
 *
 * \return		A boolen value is used to indicate the success
 *			or failure of identity authorization.  A true
 *			value indicates the verification was successful.
 */

static int _authorize_identity(const DBduct const db, \
			       const Buffer const bufr)

{
	auto char *p,
		  *err = NULL,
		  query[256],
		  tokenkey[NAAAIM_IDSIZE * 2 + 1];

	auto int lp = 0;

	auto Buffer bf = NULL;

	auto SHA256 sha256 = NULL;


	/* Compute the token key. */
	bf     = HurdLib_Buffer_Init();
	sha256 = NAAAIM_SHA256_Init();
	if ( (bf == NULL) || (sha256 == NULL) ) {
		err = "Cannot initialize hashing objects.";
		goto done;
	}

	bf->add(bf, bufr->get(bufr) + 32, 512 / 8);
	sha256->add(sha256, bf);
	if ( !sha256->compute(sha256) ) {
		err = "Cannot compute token key.";
		goto done;
	}
	bf->whack(bf);

	/* Check key authorization. */
	bf = sha256->get_Buffer(sha256);
	p = tokenkey;
	memset(tokenkey, '\0', sizeof(tokenkey));
	while ( lp < bf->size(bf) ) {
		sprintf(p + lp*2, "%02x", *(bf->get(bf)+lp));
		++lp;
	}
	snprintf(query, sizeof(query), "select status from authorized " \
		 "where tokenkey = '%s'", tokenkey);

	if ( (lp = db->query(db, query)) == -1 ) {
		err = "Identity authorization lookup failed.";
		goto done;
	}
	if ( lp == 0 ) {
		err = "Identity token not found.";
		goto done;
	}

	if ( strcmp(db->get_element(db, 0, 0), "0") == 0 ) {
		err = "Identity token no longer valid.";
		goto done;
	}


 done:
	if ( sha256 != NULL )
		sha256->whack(sha256);

	if ( err != NULL ) {
		fprintf(stdout, "!%s\n", err);
		return false;
	}

	return true;
}


/**
 * Private helper function.
 *
 * This function assists the verify_patient_identity function by
 * verifying the patient identity.  This is done by carryint out a lookup
 * of the user's intrinsic identity which is stored in the first
 * NAAAIM_IDSIZE bytes of the incoming buffer.
 *
 * \param db		The database connection used to carry out the
 *			authorization.
 *
 * \param bufr		The decrypted patient identity token.
 *
 * \return		A boolen value is used to indicate the success
 *			or failure of identity authorization.  A true
 *			value indicates the verification was successful.
 *
 *			Upon successful return the incoming bufr is
 *			loaded with the character representation of
 *			the sequence number associated with the patient's
 *			intrinsic identity.
 */

static int _verify_identity(const DBduct const db, \
			    const Buffer const bufr)

{
	auto char *p,
		  *err = NULL,
		  query[256],
		  ptid[NAAAIM_IDSIZE * 2 + 1];

	auto int lp = 0;


	/* Check key authorization. */
	p = ptid;
	memset(ptid, '\0', sizeof(ptid));
	for (lp= 0; lp < NAAAIM_IDSIZE; ++lp)
		sprintf(p + lp*2, "%02x", *(bufr->get(bufr)+lp));
	snprintf(query, sizeof(query), "select id from idmap " \
		 "where ptid = '%s'", ptid);
	fprintf(stderr, ".Looking up: %s\n", ptid);

	if ( (lp = db->query(db, query)) == -1 ) {
		err = "Patient lookup failed.";
		goto done;
	}
	if ( lp == 0 ) {
		err = "Patient not found.";
		goto done;
	}

	p = db->get_element(db, 0, 0);
	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) p, strlen(p) + 1);


 done:
	if ( err != NULL ) {
		fprintf(stdout, "!%s\n", err);
		return false;
	}

	return true;
}


/**
 * Private function.
 *
 * This function is called to verify the patient identiy and to
 * abstract the patient identity from the token.
 *
 * \param db		The database connection used to verify the
 *			token and lookup the patient.
 *
 * \param bufr		The encrypted patient identity.
 *
 * \return		A boolean value is used to indicate the success
 *			or failure of the patient validation.  A true
 *			value indicates the verification was successful.
 */

static _Bool verify_patient_identity(const DBduct const db, \
				     const Buffer const bufr)

{
	auto char *rsa,
		  *err = NULL;

	auto RSAkey key = NULL;


	/* Decrypt the patient identity. */
	if ( (rsa = Sconfig->get(Sconfig, "idkey")) == NULL ) {
		err = "RSA identity key not specified.";
		goto done;
	}

	if ( (key = NAAAIM_RSAkey_Init()) == NULL ) {
		err = "Cannot initialize rsa keyobject.";
		goto done;
	}

	if ( !key->load_public_key(key, rsa) ) {
		err = "Cannot load public key.";
		goto done;
	}

	if ( !key->decrypt(key, bufr) ) {
		err = "Unable to decrypt patient identity.";
		goto done;
	}


	/* Verify this instance of the token is authorized. */
	if ( !_authorize_identity(db, bufr) ) {
		err = "Unable to authorize identity.";
		goto done;
	}
	fputs(".Token is authorized.\n", stdout);


	/* Verify the patient identity. */
	if ( !_verify_identity(db, bufr) ) {
		err = "Unable to locate patient identity.";
		goto done;
	}
	fprintf(stderr, ".Patient is verified, %s\n", bufr->get(bufr));


 done:
	if ( key != NULL )
		key->whack(key);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		return false;
	}

	return true;
}


/**
 * Private function.
 *
 * This function is used to abstract and return information on the
 * subject of the query.
 *
 * \param db		The database connection used to obtain information
 *			on the patient.
 *
 * \param bufr		A buffer containing the ASCII version of the
 *			sequence number assisned to the patient.
 *
 * \return		A boolean value is used to indicate the success
 *			or failure of composing of the reply.  A true
 *			value indicates the incoming bufr has been
 *			updated with information to be returned to
 *			the caller.
 */

static _Bool process_query(const DBduct const db, \
			   const Buffer const bufr)

{
	auto char *err = NULL,
		  query[256];

	auto int row,
		 rows;

	auto String reply = NULL;


	if ( (reply = HurdLib_String_Init()) == NULL ) {
		err = "Error initializing response object.";
		goto done;
	}


	/* Abstract allergy information. */
	snprintf(query, sizeof(query), "select type from allergies where " \
		 "id = %s", bufr->get(bufr));
	if ( (rows = db->query(db, query)) == -1 ) {
		err = "Error on allergy query.";
		goto done;
	}
	reply->add(reply, "Allergies:\n");
	if ( rows == 0 ) 
		reply->add(reply, "\tNKA\n");
	for (row= 0; row < rows; ++row) {
		reply->add(reply, "\t");
		reply->add(reply, db->get_element(db, row, 0));
		reply->add(reply, "\n");
	}
	reply->add(reply, "\n");


	/* Extract chronic conditions. */
	snprintf(query, sizeof(query), "select type from chronic where " \
		 "id = %s", bufr->get(bufr));
	if ( (rows = db->query(db, query)) == -1 ) {
		err = "Error on chronic condition lookup.";
		goto done;
	}
	reply->add(reply, "Chronic conditions:\n");
	if ( rows == 0 ) 
		reply->add(reply, "\tNone.\n");
	for (row= 0; row < rows; ++row) {
		reply->add(reply, "\t");
		reply->add(reply, db->get_element(db, row, 0));
		reply->add(reply, "\n");
	}
	reply->add(reply, "\n");


	/* Extract medication summary. */
	snprintf(query, sizeof(query), "select type from medications where " \
		 "id = %s", bufr->get(bufr));
	if ( (rows = db->query(db, query)) == -1 ) {
		err = "Error on medications lookup.";
		goto done;
	}
	reply->add(reply, "Medication summary:\n");
	if ( rows == 0 ) 
		reply->add(reply, "\tNone.\n");
	for (row= 0; row < rows; ++row) {
		reply->add(reply, "\t");
		reply->add(reply, db->get_element(db, row, 0));
		reply->add(reply, "\n");
	}

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) reply->get(reply), \
		  reply->size(reply));


 done:
	if ( reply != NULL )
		reply->whack(reply);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		return false;
	}

	return true;
}

	
/**
 * Private function.
 *
 * This function is called after a fork to handle an accepted connection.
 *
 * \param duct	The SSL connection object describing the accepted connection.
 *
 * \parm config	The object describing the configuration for the server.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the connection.  A true value indicates the
 *		connection has been successfully processed.
 */

static _Bool handle_connection(const Duct const duct)

{
	auto char *err,
		  *site,
		  *location,
		  *dbparams,
		  banner[256];

	auto int verifier,
		 retn = false;

	auto Buffer bufr = NULL;

	auto String address = NULL;

	auto DBduct db = NULL;

	auto ProviderQuery query = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;


	/* Abstract and verify configuration information. */
	if ( (dbparams = Sconfig->get(Sconfig, "database")) == NULL ) {
		err = "No database parameters defined.";
		goto done;
	}

	if ( (site = Sconfig->get(Sconfig, "site")) == NULL )
		site = "UNKNOWN";
	if ( (location = Sconfig->get(Sconfig, "location")) == NULL )
		location = "UNKNOWN";


	/* Initialize the database connection. */
	if ( (db = NAAAIM_DBduct_Init()) == NULL )
		goto done;
	if ( !db->init_connection(db, dbparams) ) {
		err = "Cannot initialize database connection.";
		goto done;
	}


	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\nHello\n", SERVER, \
		 site, location);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) ) {
		err = "Error sending connection banner.";
		goto done;
	}


	/* Read the patient identity block. */
	fputs("<Receiving patient identity.\n", stdout);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		err = "Error receiving patient identity.";
		goto done;
	}

	fputs(".Decoding query.\n", stdout);
	if ( (query = NAAAIM_ProviderQuery_Init()) == NULL ) {
		err = "Failed to initialize query object.";
		goto done;
	}

	if ( !query->decode(query, bufr) ) {
		err = "Failed to decode query.";
		goto done;
	}


	/* Handle a basic information query. */
	if ( query->type(query) == PQquery_simple ) {
		fputs(".Processing simple query.\n", stdout);

		bufr->reset(bufr);
		if ( !query->get_simple_query(query, bufr) ) {
			err = "Failed to extract patient identity from query.";
			goto done;
		}

		if ( !verify_patient_identity(db, bufr) ) {
			err = "Unable to verify patient identity.";
			goto done;
		}

		if ( !process_query(db, bufr) ) {
			err = "Error processing query.";
			goto done;
		}
	}


	/*
	 * Handle a basic information query with SMS referral of
	 * patient information.
	 */
	if ( query->type(query) == PQquery_simple_sms ) {
		auto long int ptid;

		fputs(".Processing simple query with SMS referral.\n", stdout);

		if ( (address = HurdLib_String_Init()) == NULL ) {
			err = "Error initializing address string.";
			goto done;
		}

		bufr->reset(bufr);
		if ( !query->get_simple_query_sms(query, bufr, address, \
						  &verifier) ) {
			err = "Failed to extract patient identity from query.";
			goto done;
		}

		if ( !verify_patient_identity(db, bufr) ) {
			err = "Unable to verify patient identity.";
			goto done;
		}
		ptid = atol((char *) bufr->get(bufr));
		

		if ( !process_query(db, bufr) ) {
			err = "Error processing query.";
			goto done;
		}

		send_sms_message(db, ptid, address, verifier);
	}


	if ( !duct->send_Buffer(duct, bufr) ) {
		err = "Unable to send query response.";
		goto done;
	}

	retn = true;


 done:
	if ( retn == false ) {
		fprintf(stderr, "!%s\n", err);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) FAILED, strlen(FAILED));
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;
	}

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( db != NULL )
		db->whack(db);
	if ( query != NULL )
		query->whack(query);
	if ( address != NULL )
		address->whack(address);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *err	       = NULL,
		  *config_file = NULL;

	auto int port,
		 retn = 1;

	auto pid_t pid;

	auto Duct duct = NULL;

 
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

	if ( (Sconfig = HurdLib_Config_Init()) == NULL ) {
		err = "Error initializing configuration.";
		goto done;
	}

	if ( !Sconfig->parse(Sconfig, config_file) ) {
		err = "Error parsing configuration file.";
		goto done;
	}


	/* Initialize process table. */
	init_process_table();


	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
		err = "Error on SSL object creation.";
		goto done;
	}

	if ( !duct->init_server(duct) ) {
		err = "Cannot initialize server mode.";
		goto done;
	}

	if ( !duct->load_credentials(duct,				 \
				     Sconfig->get(Sconfig, "serverkey"), \
				     Sconfig->get(Sconfig, "certificate"))) {
		err = "Cannot load server credentials.";
		goto done;
	}

	port = atoi(Sconfig->get(Sconfig, "port"));
	if ( !duct->init_port(duct, NULL, port) ) {
		err = "Cannot initialize port.";
		goto done;
	}

	fputs("\n.Waiting for connections.\n", stdout);
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
			if ( handle_connection(duct) )
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

	if ( Sconfig != NULL )
		Sconfig->whack(Sconfig);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
