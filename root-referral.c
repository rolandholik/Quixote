/** \file
 * This file contains an implementation of the identity root referral
 * server.   This server is responsible for arbitrating all medical
 * identity referral requests.
 *
 * The server accepts an identity referral request which consists of
 * two authenticators.  The first authenticator identitifies the
 * device and contains an encrypted list of organizational modifier 
 * keys.  The second authenticator identifies the user and contains an
 * encrypted list of organizational identifiers.
 *
 * The server tranfers the two authenticators to the user and device
 * identity brokerage servers.  If these servers successfully authenticate
 * the device and user the decrypted organizational modifier keys and
 * identities are returned.
 *
 * The server then transfers the modifier and identity blocks to the
 * identity brokerage servers for discovery.  The identity query
 * responses are collected from the brokerage servers and returned to the
 * initiating client.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "Root Referral Server"

#define INSTALL_DIR "/opt/NAAAIM"
#define CONFIG_FILE INSTALL_DIR "/etc/root-referral.conf"

#define FAILED "Authentication failed."


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"
#include "AuthenReply.h"
#include "IDqueryReply.h"


/* Variables static to this module. */
static pid_t process_table[100];

/** The list of query slots to be filled. */
static unsigned int Query_count = 0;

static struct query_slot {
	_Bool filled;
	Buffer reply;
} *Query_slots = NULL;


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
 * This function reads and initializes the number of identity queries
 * the client is requesting.
 *
 * \param client	The SSL connection object which is requesting
 *			the query.
 *
 * \param bufr		The Buffer object to be used in communicating
 *			with the client.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the session was successfully initialized.  A
 *			true value indicates success.
 */

static _Bool initialize_query(const Duct const duct, const Buffer const bufr)

{
	auto _Bool retn = false;

	auto unsigned int lp;

	auto Buffer reply = NULL;


	/* Read the number of slots from the client. */
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;

	memcpy(&Query_count, bufr->get(bufr), sizeof(Query_count));
	Query_count = htonl(Query_count);
	fprintf(stdout, ".Client requesting %d query %s.\n", Query_count, \
		Query_count == 1 ? "slot" : "slots");


	/*
	 * Allocate an array of query structures to be filled and populate
	 * each array element with a query reply structure.
	 */
	Query_slots = malloc(Query_count * sizeof(struct query_slot));
	if ( Query_slots == NULL )
		goto done;

	for (lp= 0; lp < Query_count; ++lp) {
		if ( (reply = HurdLib_Buffer_Init()) == NULL )
			goto done;
		Query_slots[lp].reply  = reply;
		Query_slots[lp].filled = false;
	}

	retn = true;


 done:
	if ( retn == false )
		fputs("!Query initialized failed.\n", stderr);

	return retn;
}

			
/**
 * Private function.
 *
 * This function implements a connection to a user identity brokerage
 * server.  The binary authenticator object is transmitted to the
 * identity brokerage server for processing.
 *
 * \param client	The SSL connection object managing the connection
 *			from the client.
 *
 * \param config	The object holding the configuration for the
 *			server.
 *
 * \param bufr		The Buffer object to be used for communicating
 *			with the user identity brokerage.  The reply
 *			from the identity brokerage will be returned in
 *			this object.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of the device authentication.   A true
 *			value indicates the authentication has been
 *			successful.
 */

static int authenticate_user(const Duct const client,	\
			     const Config const config,	\
			     const Buffer const bufr)

{
	auto _Bool retn = false;

	auto char *certificate,
		  *server,
		  *portstr;

	auto int port;

	auto Duct broker = NULL;

	auto AuthenReply reply = NULL;


	/* Setup configuration for device brokerage connection. */
	if ( (certificate = config->get(config, "user_authn_cert")) \
	     == NULL ) {
		fputs("!User broker certificate not configured.\n", stderr);
		goto done;
	}

	if ( (server = config->get(config, "user_authn_server")) == NULL ) {
		fputs("!User authentication server not configured.\n", \
		      stderr);
		goto done;
	}

	if ( (portstr = config->get(config, "user_authn_port")) == NULL )  {
		fputs("!User authentication server port not configured.\n", \
		      stderr);
		goto done;
	}
	port = atoi(portstr);

	fprintf(stdout, "\n.Connecting to user authentication broker %s.\n", \
		server);


	/*
	 * Initialize SSL connection and connect to the user identity
	 * brokerage server.
	 */
	if ( (broker = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !broker->init_client(broker) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !broker->load_certificates(broker, certificate) ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, server, port) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	if ( !broker->init_connection(broker) ) {
		fputs("Cannot initialize connection.\n", stderr);
		goto done;
	}


	/* Obtain and print connection banner. */
	bufr->reset(bufr);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error on receive.\n", stderr);
		goto done;
	}
	print_buffer(bufr);


	/* Receive and re-transmit device authenticator. */
	fputs(">Sending user authentication.\n", stdout);
	bufr->reset(bufr);
	if ( !client->receive_Buffer(client, bufr) )
		goto done;

	if ( !broker->send_Buffer(broker, bufr) )
		goto done;


	/* Retrieve the decrypted identity elements. */
	bufr->reset(bufr);
	fputs("<Receiving user authentication reply.\n", stdout);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error receiving authentication reply.\n", stdout);
		goto done;
	}

	if ( (reply = NAAAIM_AuthenReply_Init()) == NULL ) {
		fputs("ERROR.\n", stderr);
		goto done;
	}
	if ( !reply->decode(reply, bufr) ) {
		fputs("!Cannot decode authentication reply.\n", stdout);
		goto done;
	}
#if 0
	fputs(".el: ", stdout);
	reply->print(reply);
#endif

	retn = true;


 done:
	if ( broker != NULL ) {
		if ( !broker->whack_connection(broker) )
			fputs("Error closing user broker connection.\n", \
			      stderr);
		broker->whack(broker);
	}

	if ( reply != NULL )
		reply->whack(reply);

	return retn;
}


/**
 * Private function.
 *
 * This function implements a connection to a device identity brokerage
 * server.  The binary authenticator object is transmitted to the
 * identity brokerage server for processing.
 *
 * \param client	The SSL connection object managing the connection
 *			from the client.
 *
 * \param config	The object holding the configuration for the
 *			server.
 *
 * \param bufr		The Buffer object to be used for communicating
 *			with the device identity brokerage.  The reply
 *			from the identity brokerage will be returned in
 *			this object.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of the device authentication.   A true
 *			value indicates the authentication has been
 *			successful.
 */

static int authenticate_device(const Duct const client,	  \
			       const Config const config, \
			       const Buffer const bufr)

{
	auto _Bool retn = false;

	auto char *certificate,
		  *server,
		  *portstr;

	auto int port;

	auto Duct broker = NULL;

	auto AuthenReply reply = NULL;


	/* Setup configuration for device brokerage connection. */
	if ( (certificate = config->get(config, "device_authn_cert")) \
	     == NULL ) {
		fputs("!Device broker certificate not configured.\n", stderr);
		goto done;
	}

	if ( (server = config->get(config, "device_authn_server")) == NULL ) {
		fputs("!Device authentication server not configured.\n", \
		      stderr);
		goto done;
	}

	if ( (portstr = config->get(config, "device_authn_port")) == NULL )  {
		fputs("!Device authentication server port not configured.\n", \
		      stderr);
		goto done;
	}
	port = atoi(portstr);

	fprintf(stdout, "\n.Connecting to device authentication broker " \
		"%s.\n", server);


	/*
	 * Initialize SSL connection and connect to the device identity
	 * brokerage server.
	 */
	if ( (broker = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !broker->init_client(broker) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !broker->load_certificates(broker, certificate) ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, server, port) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	if ( !broker->init_connection(broker) ) {
		fputs("Cannot initialize connection.\n", stderr);
		goto done;
	}


	/* Obtain and print connection banner. */
	bufr->reset(bufr);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error on receive.\n", stderr);
		goto done;
	}
	print_buffer(bufr);


	/* Receive and re-transmit device authenticator. */
	fputs(">Sending device authentication.\n", stdout);
	bufr->reset(bufr);
	if ( !client->receive_Buffer(client, bufr) )
		goto done;

	if ( !broker->send_Buffer(broker, bufr) )
		goto done;


	/* Retrieve the decrypted identity elements. */
	bufr->reset(bufr);
	fputs("<Receiving device authentication reply.\n", stdout);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error receiving authentication reply.\n", stdout);
		goto done;
	}

	if ( (reply = NAAAIM_AuthenReply_Init()) == NULL ) {
		fputs("ERROR.\n", stderr);
		goto done;
	}
	if ( !reply->decode(reply, bufr) ) {
		fputs("!Cannot decode authentication reply.\n", stdout);
		goto done;
	}

#if 0
	fputs(".el: ", stdout);
	reply->print(reply);
#endif

	retn = true;


 done:
	if ( broker != NULL ) {
		if ( !broker->whack_connection(broker) )
			fputs("Error closing device broker connection.\n", \
			      stderr);
		broker->whack(broker);
	}

	if ( reply != NULL )
		reply->whack(reply);

	return retn;
}


/**
 * Private function.
 *
 * This function dispatches the identity element authenticators to each
 * of the defined identity brokerages.
 *
 * \param config	The object holding the configuration for the
 *			server.
 *
 * \param devauth	The identity elements authenticated by the
 *			device authentication brokerage.
 *
 * \param userauth	The identity elements authenticated by the user
 *			authentication brokerage.
 *
 * \param bufr		A utility buffer passed from the caller to avoid
 *			the need to allocate a buffer within the
 *			function.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of processing by the identity brokerages.
 *			A true value indicates the authentication has been
 *			successful.
 */

static _Bool dispatch_brokers(const Config const config,   \
			      const Buffer const devauth,  \
			      const Buffer const userauth, \
			      const Buffer const bufr)

{
	auto _Bool retn = false;

	auto char *certificate,
		  *server,
		  *portstr;

	auto int port;

	auto unsigned int lp;

	auto Buffer bfp;

	auto Duct broker = NULL;

	auto IDqueryReply reply;


	/* Setup configuration for device brokerage connection. */
	if ( (certificate = config->get(config, "idbroker_cert")) \
	     == NULL ) {
		fputs("!Identity broker certificate not configured.\n", \
		      stderr);
		goto done;
	}

	if ( (server = config->get(config, "idbroker_server")) == NULL ) {
		fputs("!Identity broker server not configured.\n", stderr);
		goto done;
	}

	if ( (portstr = config->get(config, "idbroker_port")) == NULL )  {
		fputs("!Identity broker server port not configured.\n", \
		      stderr);
		goto done;
	}
	port = atoi(portstr);

	fprintf(stdout, "\n.Connecting to device authentication broker " \
		"%s.\n", server);


	/*
	 * Initialize SSL connection and connect to the device identity
	 * brokerage server.
	 */
	if ( (broker = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !broker->init_client(broker) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !broker->load_certificates(broker, certificate) ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, server, port) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	if ( !broker->init_connection(broker) ) {
		fputs("Cannot initialize connection.\n", stderr);
		goto done;
	}


	/* Obtain and print connection banner. */
	bufr->reset(bufr);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error on receive.\n", stderr);
		goto done;
	}
	print_buffer(bufr);


	/* Transmit key elements. */
	fputs(">Sending device key elements.\n", stdout);
	if ( !broker->send_Buffer(broker, devauth) ) {
		fputs("!Error sending elements.\n", stderr);
		goto done;
	}

	/* Transmit identity elements. */
	fputs(">Sending identity elements.\n", stdout);
	if ( !broker->send_Buffer(broker, userauth) ) {
		fputs("!Error sending elements.\n", stderr);
		goto done;
	}


	/* Receive identity referrals. */
	if ( (reply = NAAAIM_IDqueryReply_Init()) == NULL ) {
		fputs("!Error initializing query reply structure.\n", stderr);
		goto done;
	}

	fputs("<Receiving identity referrals.\n", stdout);
	for (lp= 0; lp < Query_count; ++lp) {
		bufr->reset(bufr);
		if ( !broker->receive_Buffer(broker, bufr) ) {
			fputs("!Error receiving referral.\n", stderr);
			goto done;
		}

		if ( !reply->decode(reply, bufr) ) {
			fputs("!Error decoding referral.\n", stderr);
			goto done;
		}

		if ( !reply->is_type(reply, IDQreply_notfound) ) {
			bfp = Query_slots[lp].reply;
			if ( !bfp->add_Buffer(bfp, bufr) ) {
				fputs("!Error saving referral.\n", stderr);
				goto done;
			}
			Query_slots[lp].filled = true;
		}
	}

	retn = true;


 done:
	if ( (broker != NULL) ) {
		if ( !broker->whack_connection(broker) )
			fputs("Error closing identity broker connection.\n", \
			      stderr);
		broker->whack(broker);
	}

	if ( reply != NULL )
		reply->whack(reply);

	return retn;
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
	auto char *site,
		  *location,
		  *equipment,
		  banner[256];

	auto int retn = false;

	auto unsigned int lp;

	auto Buffer bfp,
		    bufr     = NULL,
		    devauth  = NULL,
		    userauth = NULL;

	auto IDqueryReply reply = NULL;


	bufr	 = HurdLib_Buffer_Init();
	devauth  = HurdLib_Buffer_Init();
	userauth = HurdLib_Buffer_Init();
	if ( (bufr == NULL) || (devauth == NULL) || (userauth == NULL) )
 		goto done;


	/* Abstract and verify configuration information. */
	if ( (site = config->get(config, "site")) == NULL )
		site = "UNKNOWN";
	if ( (location = config->get(config, "location")) == NULL )
		location = "UNKNOWN";
	if ( (equipment = config->get(config, "equipment")) == NULL )
		equipment = "UNKNOWN";
		

	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\n%s\nHello\n", \
		 SERVER, site, location, equipment);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Receive the number of query slots from the client. */
	if ( !initialize_query(duct, bufr) ) {
		fputs("!Failed to initialize query.\n", stderr);
		goto done;
	}
	

	/* Read and process device authenticator. */
	if ( !authenticate_device(duct, config, bufr) )
		goto done;
	devauth->add_Buffer(devauth, bufr);
	
	/* Read and process user authenticator. */
	if ( !authenticate_user(duct, config, bufr) )
		goto done;
	userauth->add_Buffer(userauth, bufr);


	/* Dispatch authenticators to defined brokerage servers. */
	if ( !dispatch_brokers(config, devauth, userauth, bufr) )
		goto done;


	/* Return referral information to the client. */
	if ( (reply = NAAAIM_IDqueryReply_Init()) == NULL ) {
		fputs("!Error initializing null referral reply.\n", stderr);
		goto done;
	}
	bufr->reset(bufr);
	if ( !reply->encode(reply, bufr) ) {
		fputs("!Error encoding null referral reply.\n", stderr);
		goto done;
	}

	fputs(">Returning identity referrals.\n", stdout);
	for (lp= 0; lp < Query_count; ++lp) { 
		if ( Query_slots[lp].filled )
			bfp = Query_slots[lp].reply;
		else
			bfp = bufr;
		if ( !duct->send_Buffer(duct, bfp) ) {
			fputs("!Error sending referrals.\n", stdout);
			goto done;
		}
	}

	retn = true;


 done:
	if ( retn == false ) {
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) FAILED, strlen(FAILED));
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;
	}

	if ( Query_slots != NULL ) {
		for (lp= 0; lp < Query_count; ++lp)
			Query_slots[lp].reply->whack(Query_slots[lp].reply);
		free(Query_slots);
	}

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( devauth != NULL )
		devauth->whack(devauth);
	if ( userauth != NULL )
		userauth->whack(userauth);
	if ( reply != NULL )
		reply->whack(reply);

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
		     fputs("Error closing duct connection.\n", stderr);
	     duct->whack(duct);
	}
	
	if ( config != NULL )
		config->whack(config);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
