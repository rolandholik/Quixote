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
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define SERVER "Identity Brokerage Server"

#define INSTALL_DIR "/opt/NAAAIM"
#define CONFIG_FILE INSTALL_DIR "/etc/identity-broker.conf"

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
#include "DBduct.h"


/* Variables static to this module. */
static pid_t process_table[100];

static OrgSearch IDfinder = NULL;

static unsigned int IDcnt = 0;

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
 * This function looks up and encodes an IP address to be returned as
 * resolution for a query.
 *
 * \param db	The database connection to be used for looking up the
 *		IP address information.
 *
 * \param reply	The object to be used for encoding the reply.
 *
 * \param id	The table id number of the organization.
 */

static void ip_reply(const DBduct const db, const IDqueryReply const reply, \
		     const char * const id)

{
	auto char query[256];


	snprintf(query, sizeof(query), "select host,port from ip where " \
		 "id = %s", id);
	if ( db->query(db, query) != 1 )
		return;

	if ( !reply->set_ip_reply(reply, db->get_element(db, 0, 0), \
				  atoi(db->get_element(db, 0, 1))) )
		fputs("!Error encoding ip reply.\n", stderr);

	return;
}


/**
 * Private function.
 *
 * This function looks up and encodes a telephone number to be used for
 * obtaining information on the patient.
 *
 * \param db		The database connection to be used for looking up the
 *			IP address information.
 *
 * \param reply		The object to be used for encoding the reply.
 *
 * \param orgtype	The type of provider originating the identity.
 *
 * \param id		The table id number of the organization.
 */

static void telephone_reply(const DBduct const db,	    \
			    const IDqueryReply const reply, \
			    const char * const orgtype, const char * const id)

{
	auto char query[256];

	auto String text;


	if ( (text = HurdLib_String_Init()) == NULL )
		return;

	snprintf(query, sizeof(query), "select telephone from %s where " \
		 "id = %s", orgtype, id);
	if ( db->query(db, query) != 1 ) {
		goto done;
	}

#if 0
	text->add(text, "Originating provider recommends telephone " \
		  "contact.\nPlease call: ");
#endif

	memset(query, '\0', sizeof(query));
	snprintf(query, sizeof(query), "%s\n", db->get_element(db, 0, 0));
	if ( strlen(query) == 11 ) {
		memmove(query+4, query+3, strlen(query+3)+1);
		*(query+3) = '-';
		memmove(query+8, query+7, strlen(query+7)+1);
		*(query+7) = '-';
	}
	text->add(text, query);
	if ( !reply->set_text_reply(reply, text) ) {
		fputs("!Error setting text reply\n", stderr);
	}


 done:
	if ( text != NULL )
		text->whack(text);

	return;
}


/**
 * Private function.
 *
 * This function looks up the full data record for the originating
 * organization and returns it to the caller.
 *
 * \param db		The database connection to be used for looking up the
 *			IP address information.
 *
 * \param reply		The object to be used for encoding the reply.
 *
 * \param orgtype	The type of provider originating the identity.
 *
 * \param id		The table id number of the organization.
 */

static void information_reply(const DBduct const db,	      \
			      const IDqueryReply const reply, \
			      const char * const orgtype,     \
			      const char * const id)

{
	auto char query[256];

	auto int col = 2;

	auto String text;


	if ( (text = HurdLib_String_Init()) == NULL )
		return;

	snprintf(query, sizeof(query), "select * from %s where " \
		 "id = %s", orgtype, id);
	if ( db->query(db, query) != 1 ) {
		goto done;
	}

	if ( strcmp(orgtype, "provider") == 0 ) {
		text->add(text, "Originating provider information:\n");
		snprintf(query, sizeof(query), "\tName: %s / %s\n", \
			 db->get_element(db, 0, 1), db->get_element(db, 0, 2));
		text->add(text, query);
		col = 3;
	}
	else {
		text->add(text, "Originating organization information:\n");
		snprintf(query, sizeof(query), "\tName: %s\n", \
			 db->get_element(db, 0, 1));
		text->add(text, query);
	}

#if 0
	snprintf(query, sizeof(query), "\tAddress: %s\n", \
		 db->get_element(db, 0, col++));
	text->add(text, query);
#endif
	snprintf(query, sizeof(query), "\t      %s\n", \
		 db->get_element(db, 0, col++));
	text->add(text, query);
	snprintf(query, sizeof(query), "\t      %s, ", \
		 db->get_element(db, 0, col++));
	text->add(text, query);

	snprintf(query, sizeof(query), "%s ", \
		 db->get_element(db, 0, col++));
	text->add(text, query);
	snprintf(query, sizeof(query), "%s\n\n", \
		 db->get_element(db, 0, col++));
	text->add(text, query);
	snprintf(query, sizeof(query), "\tTelephone: %s\n", \
		 db->get_element(db, 0, col++));
	text->add(text, query);
	snprintf(query, sizeof(query), "\tTaxonomy:  %s\n", \
		 db->get_element(db, 0, col));
	text->add(text, query);

	if ( !reply->set_text_reply(reply, text) ) {
		fputs("!Error setting text reply\n", stderr);
	}


 done:
	if ( text != NULL )
		text->whack(text);

	return;
}


/*
 * Private function.
 *
 * This function looks up and encodes an sms address to which an
 * informatory text message is to be sent on the patient.
 *
 * \param db		The database connection to be used for looking up the
 *			sms address information.
 *
 * \param reply		The object to be used for encoding the reply.
 *
 * \param id		The table id number of the organization.
 */

static void sms_reply(const DBduct const db, \
		      const IDqueryReply const reply, const char * const id)

{
	auto char query[256];

	auto String text;


	if ( (text = HurdLib_String_Init()) == NULL )
		return;

	snprintf(query, sizeof(query), "select address from sms where " \
		 "id = %s", id);
	if ( db->query(db, query) != 1 ) {
		goto done;
	}

	text->add(text, db->get_element(db, 0, 0));
	if ( !reply->set_sms_reply(reply, text) ) {
		fputs("!Error setting sms reply\n", stderr);
	}


 done:
	if ( text != NULL )
		text->whack(text);

	return;
}


/**
 * Private function.
 *
 * This function is responsible for creating the reply which is to be
 * generated for each identity in the requested query slots.
 *
 * \param slot		The query slot which is being resolved.
 *
 * \param db		The object describing the database connection to
 *			be used for looking up the organizatioinal identity.
 *
 * \param reply		The reply object which is to be populated.
 *
 * \param identity	A buffer containing the binary value of the
 *			identity which was matched.
 */

static void resolve_reply(unsigned const int slot, const DBduct const db, \
			  const IDqueryReply const reply,		  \
			  const Buffer const identity)

{
	auto char *p,
		  *id,
		  *orgtype,
		  *reply_type,
		  *err = NULL,
		  query[256],
		  orgid[NAAAIM_IDSIZE * 2 + 1];

	auto unsigned lp = 0;


	/* Generate the ASCII representation of the identity. */
	if ( identity->poisoned(identity) || \
	     (identity->size(identity) != NAAAIM_IDSIZE) ) {
		err = "Invalid organizational identity.";
		goto done;
	}

	p = orgid;
	memset(orgid, '\0', sizeof(orgid));
	while ( lp < identity->size(identity) ) {
		sprintf(p + lp*2, "%02x", *(identity->get(identity)+lp));
		++lp;
	}


	/*
	 * Determine if there is a mapping for this identity and if one
	 * exists retrieve the type of organization and the type o
	 * reply.
	 */
	snprintf(query, sizeof(query), "select idmap.id,idmap.type," \
		 "repdefn.reply from repdefn left join idmap on "    \
		 "idmap.id = repdefn.id where orgid= '%s'", orgid);
	if ( (lp = db->query(db, query)) == -1 ) {
		err = "Error executing database query.";
		goto done;
	}
	if ( lp == 0 )
		return;
	if ( lp > 1 ) {
		err =  "Multiple originating identities.";
		goto done;
	}
			

	/*
	 * A single query result was returned.  Lookup the type of response
	 * to be encoded and then encode the appropriate reply object.
	 */
	id	   = db->get_element(db, 0, 0);
	orgtype	   = db->get_element(db, 0, 1);
	reply_type = db->get_element(db, 0, 2);
	if ( (id == NULL) || (orgtype == NULL) || (reply_type == NULL) ) {
		err = "Failed to retrieve reply information.";
		goto done;
	}
	
	if ( orgtype[0] == '1' )
		orgtype = "provider";
	else
		orgtype = "organization";

	fprintf(stdout, ".Resolving slot %d - ", slot);
	switch ( reply_type[0] ) {
		case '0':
			fputs("ip referral.\n", stdout);
			ip_reply(db, reply, id);
			break;
		case '1':
			fputs("telephone referral.\n", stdout);
			telephone_reply(db, reply, orgtype, id);
			break;
		case '2':
			fputs("information referral.\n", stdout);
			information_reply(db, reply, orgtype, id);
			break;
		case '3':
			fputs("sms referral.\n", stdout);
			sms_reply(db, reply, id);
			break;
		case '4':
			fputs("bimodal sms referral.\n", stdout);
			ip_reply(db, reply, id);
			sms_reply(db, reply, id);
			break;
	}


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	return;
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

static _Bool handle_connection(const Duct const duct, \
			       const Config const config)

{
	auto char *err,
		  *site,
		  *location,
		  *dbparams,
		  banner[256];

	auto int retn = false;

	auto unsigned int lp;

	auto Buffer bufr = NULL;

	auto AuthenReply orgkey = NULL,
		         orgid  = NULL;

	auto IDtoken token = NULL;

	auto IDqueryReply reply;

	auto DBduct db = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;

	orgkey = NAAAIM_AuthenReply_Init();
	orgid  = NAAAIM_AuthenReply_Init();
	if ( (orgkey == NULL) || (orgid == NULL) )
		goto done;


	/* Abstract and verify configuration information. */
	if ( (dbparams = config->get(config, "database")) == NULL ) {
		err = "No database parameters defined.";
		goto done;
	}

	if ( (site = config->get(config, "site")) == NULL )
		site = "UNKNOWN";
	if ( (location = config->get(config, "location")) == NULL )
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
	fprintf(stdout, ".Searching %d originating identities for %d %s.\n", \
		IDcnt, Search_cnt, Search_cnt > 1 ? "identities" : "identity");

	for (lp= 0; lp < Search_cnt; ++lp) {
		token = Search_list[lp].token;

		if ( IDfinder->search(IDfinder, token) ) {
			reply = Search_list[lp].reply;
			bufr->reset(bufr);
			IDfinder->get_match(IDfinder, bufr);
			resolve_reply(lp, db, reply, bufr);
		}
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
	if ( db != NULL )
		db->whack(db);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *err	       = NULL,
		  *search_file = NULL,
		  *config_file = NULL;

	auto int port,
		 retn = 1;

	auto unsigned int processors;

	auto pid_t pid;

	auto Config config = NULL;

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


	/* Initialize and organizational identity search object. */
	if ( (IDfinder = NAAAIM_OrgSearch_Init()) == NULL ) {
		err = "Error allocating search object.";
		goto done;
	}
	fputs("\n.Loading originating identity database.\n", stdout);
	
	if ( (search_file = config->get(config, "search_file")) == NULL ) {
		err = "Search file not specified.";
		goto done;
	}
	IDcnt = IDfinder->load(IDfinder, search_file);
	if ( IDcnt == 0 ) {
		err = "Error loading search object.";
		goto done;
	}
	fputs(".Load completed.\n", stdout);

	if ( config->get(config, "processors") != NULL ) {
		processors = atoi(config->get(config, "processors"));
		if ( !IDfinder->setup_parallel(IDfinder, processors) ) {
			err = "Cannot initialize parallel search.";
			goto done;
		}
	}

	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
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
	if ( IDfinder != NULL )
		IDfinder->whack(IDfinder);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
