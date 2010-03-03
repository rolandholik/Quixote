/** \file
 * This file contains an implementation of the identity broker
 * server.   This server is responsible for determining which organization
 * originate a patient identity.
 *
 * The server accepts an identity query request which consists of
 * two authenticator replies.  The first authenticator reply consists
 * of the set of organizational identity keys assigned to the user.
 * The second reply consists of the organizational identities assigned
 * to the user.
 *
 * The server correlates the two sets of identity elements and for
 * each pair checks to see if any of the organizational identities
 * managed by the broker yields the user organizational identity.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "Identity Brokerage Server"
#define SITE "Clear Lake Cooperative Telephone"
#define LOCATION "Clear Lake, SD"

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

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"
#include "AuthenReply.h"
#include "OrgSearch.h"
#include "IDqueryReply.h"


/* Variables static to this module. */
static pid_t process_table[100];

static OrgSearch IDfinder = NULL;

struct search_entry {
	IDqueryReply reply;
	IDtoken token;
};

static unsigned int Search_cnt;
static struct search_entry *Search_list;


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
 * This function creates an array which will be iterated over for each
 * originating identity managed by this server.  The array will contain
 * a structure which defines each pair of identity elements which are
 * to be searched for.  A boolean value is also contained which allows
 * a given pair of elements to be skipped if they have already been
 * resolved.
 *
 * \param orgkey	The list of organizational identity keys to
 *			be searched for.
 *
 * \param orgid		The list of organization idenities to be
 *			searched for.
 *
 * \param bufr		A Buffer object to be used in setting up the
 *			list.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the search array has been successfully
 *			created.
 */

static _Bool setup_search_array(const AuthenReply const orgkey, \
				const AuthenReply const orgid,  \
				const Buffer const bufr)

{
	auto _Bool retn = false;

	auto unsigned int lp,
			  keysize = NAAAIM_IDSIZE;

	auto Buffer wb	    = NULL,
		    keybufr = NULL,
		    idbufr  = NULL;

	auto IDtoken token;

	auto IDqueryReply reply = NULL;


	/* Load buffers with identity keys and resultant identities. */
	keybufr = HurdLib_Buffer_Init();
	idbufr  = HurdLib_Buffer_Init();
	if ( (keybufr == NULL) || (idbufr == NULL) )
		goto done;

	if ( !orgkey->get_elements(orgkey, keybufr) )
		goto done;
	if ( !orgid->get_elements(orgid, idbufr) )
		goto done;


	/* Allocate the search array. */
	Search_cnt = keybufr->size(bufr) / keysize;
	Search_list = malloc(Search_cnt * sizeof(struct search_entry));
	if ( Search_list == NULL )
		goto done;
	memset(Search_list, '\0', Search_cnt * sizeof(struct search_entry));


	/* Populate the search array. */
	if ( (wb = HurdLib_Buffer_Init()) == NULL )
		goto done;

	for (lp= 0; lp < Search_cnt; ++lp) {
		if ( (reply = NAAAIM_IDqueryReply_Init()) == NULL )
			goto done;
		Search_list[lp].reply = reply;

		if ( (token = NAAAIM_IDtoken_Init()) == NULL )
			goto done;
		Search_list[lp].token = token;

		wb->reset(wb);
		wb->add(wb, keybufr->get(keybufr) + (lp*keysize), keysize);
		if ( !token->set_element(token, IDtoken_orgkey, wb) )
			goto done;

		wb->reset(wb);
		wb->add(wb, idbufr->get(idbufr) + (lp*keysize), keysize);
		if ( !token->set_element(token, IDtoken_orgid, wb) )
			goto done;
	}

	retn = true;


 done:
	if ( wb != NULL )
		wb->whack(wb);
	if ( keybufr != NULL )
		keybufr->whack(keybufr);
	if ( idbufr != NULL )
		idbufr->whack(idbufr);
		
	return retn;
}
			
		
/**
 * Private function.
 *
 * This function is called after a fork to handle an accepted connection.
 *
 * \param duct	The SSL connection object describing the accepted connection.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the connection.  A true value indicates the
 *		connection has been successfully processed.
 */

static _Bool handle_connection(const Duct const duct)

{
	auto char *err,
		  banner[256];

	auto int retn = false;

	auto unsigned int lp;

	auto Buffer bufr = NULL;

	auto AuthenReply orgkey = NULL,
		         orgid  = NULL;

	auto IDtoken token = NULL;

	auto IDqueryReply reply = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;

	orgkey = NAAAIM_AuthenReply_Init();
	orgid  = NAAAIM_AuthenReply_Init();
	if ( (orgkey == NULL) || (orgid == NULL) )
		goto done;


	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\nHello\n", SERVER, \
		 SITE, LOCATION);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Read the organizational key elements. */
	bufr->reset(bufr);
	fputs("<Receiving organizational key elements.\n", stdout);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		err = "Error receiving key elements.";
		goto done;
	}
	if ( !orgkey->decode(orgkey, bufr) ) {
		err = "Error decoding key elements.";
		goto done;
	}
#if 0
	fputs(".elkey: ", stdout);
	orgkey->print(orgkey);
#endif

	/* Read the organizational identity elements. */
	bufr->reset(bufr);
	fputs("<Receiving organizational identity elements.\n", stdout);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		err = "Error receiving identity elements.";
		goto done;
	}
	if ( !orgid->decode(orgid, bufr) ) {
		err = "Error decoding identity elements.";
		goto done;
	}
#if 0
	fputs(".elid:  ", stdout);
	orgid->print(orgid);
#endif


	/*
	 * Search for identities which originated the identity elements
	 * in the identity query.
	 */
	if ( !setup_search_array(orgkey, orgid, bufr) ) {
		err = "Error creating search array.";
		goto done;
	}
	fprintf(stdout, ".Searching over %d %s.\n", Search_cnt, \
		Search_cnt > 1 ? "identities" : "identity");

	for (lp= 0; lp < Search_cnt; ++lp) {
		token = Search_list[lp].token;

		if ( IDfinder->search(IDfinder, token) ) {
			continue;
			// IDfinder->get_match(IDfinder, bfp);
		}
	}

	for (lp= 0; lp < Search_cnt; ++lp) {
		fprintf(stdout, ".slot %d: ", lp);
		reply = Search_list[lp].reply;
		if ( reply->is_type(reply, IDQreply_notfound) )
			fputs("not found.\n", stdout);
		else
			fputs("found.\n", stdout);
	}


	/* Return referral information. */
	fputs(">Sending identity referral.\n", stdout);
	for (lp= 0; lp < Search_cnt; ++lp) {
		bufr->reset(bufr);
		reply = Search_list[lp].reply;
		if ( !reply->encode(reply, bufr) ) {
			err = "Failed referral encoding.";
			goto done;
		}
		if ( !duct->send_Buffer(duct, bufr) ) {
			err = "Failed referral send.";
			goto done;
		}
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

	for (lp= 0; lp < Search_cnt; ++lp) {
		Search_list[lp].token->whack(Search_list[lp].token);
		Search_list[lp].reply->whack(Search_list[lp].reply);
	}

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( orgkey != NULL )
		orgkey->whack(orgkey);
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( reply != NULL )
		reply->whack(reply);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *config;

	auto int retn = 1;

	auto pid_t pid;

	auto Config parser = NULL;

	auto Duct duct = NULL;

 
	fprintf(stdout, "%s started.\n", SERVER);
	fflush(stdout);

	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "c:")) != EOF )
		switch ( retn ) {

			case 'c':
				config = optarg;
				break;
		}
	retn = 1;

	if ( config == NULL )
		config = "./identity-brokerage.conf";


	/* Initialize process table. */
	init_process_table();

	/* Initialize and organizational identity search object. */
	if ( (IDfinder = NAAAIM_OrgSearch_Init()) == NULL ) {
		fputs("Error allocating search object.\n", stderr);
		goto done;
	}
	fputs("\nLoading originating identity database.\n", stdout);
	if ( !IDfinder->load(IDfinder, "/u/usr/src/npi/npi-search.txt") ) {
		fputs("Error loading search object.\n", stderr);
		goto done;
	}

	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !duct->init_server(duct) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !duct->load_credentials(duct, "./org-private.pem", \
				     "./org-cert.pem") ) {
		fputs("Cannot load server credentials.\n", stderr);
		goto done;
	}

	if ( !duct->init_port(duct, NULL, 11993) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			fputs("Error on SSL connection accept.\n", stderr);
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			fputs("Connection fork failure.\n", stderr);
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
	if ( duct != NULL ) {
		if ( !duct->whack_connection(duct) )
			fputs("Error closing connection.\n", stderr);
		duct->whack(duct);
	}

	if ( parser != NULL )
		parser->whack(parser);
	if ( IDfinder != NULL )
		IDfinder->whack(IDfinder);

	return retn;
}
