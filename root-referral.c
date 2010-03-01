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
#define EQUIPMENT "DakTech 5530"
#define SERVER "Root Referral Server"
#define SITE "Gardonville Cooperative Telephone"
#define LOCATION "Brandon, MN"

#define FAILED "Authentication failed."

/* Include files. */
#include <stdio.h>
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
 * This function implements a connection to a user identity brokerage
 * server.  The binary authenticator object is transmitted to the
 * identity brokerage server for processing.
 *
 * \param client	The SSL connection object managing the connection
 *			from the client.
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

static int authenticate_user(const Duct const client, const Buffer const bufr)

{
	auto _Bool retn = false;

	auto Duct broker = NULL;

	auto AuthenReply reply = NULL;


	fputs("\n.Connecting to user authentication brokerage.\n", stdout);

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

	if ( !broker->load_certificates(broker, "./org-cert.pem") ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, "localhost", 11992) ) {
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
			fputs("Error closing connection.\n", stderr);
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

static int authenticate_device(const Duct const client, \
			       const Buffer const bufr)

{
	auto _Bool retn = false;

	auto Duct broker = NULL;

	auto AuthenReply reply = NULL;


	fputs("\n.Connecting to device authentication brokerage.\n", stdout);

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

	if ( !broker->load_certificates(broker, "./org-cert.pem") ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, "localhost", 11991) ) {
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
			fputs("Error closing connection.\n", stderr);
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

static _Bool dispatch_brokers(const Buffer const devauth,  \
			      const Buffer const userauth, \
			      const Buffer const bufr)

{
	auto _Bool retn = false;

	auto Duct broker = NULL;


	fputs("\n.Connecting to identity brokerage.\n", stdout);

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

	if ( !broker->load_certificates(broker, "./org-cert.pem") ) {
		fputs("Cannot load certificates.\n", stderr);
		goto done;
	}

	if ( !broker->init_port(broker, "localhost", 11993) ) {
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

	fputs("<Receiving identity referrals.\n", stdout);
	bufr->reset(bufr);
	if ( !broker->receive_Buffer(broker, bufr) ) {
		fputs("Error receiving referrals.\n", stdout);
		goto done;
	}

	retn = true;


 done:
	if ( (broker != NULL) ) {
		if ( !broker->whack_connection(broker) )
			fputs("Error closing connection.\n", stderr);
		broker->whack(broker);
	}

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
	auto char banner[256];

	auto int retn = false;

	auto Buffer bufr     = NULL,
		    devauth  = NULL,
		    userauth = NULL;


	bufr	 = HurdLib_Buffer_Init();
	devauth  = HurdLib_Buffer_Init();
	userauth = HurdLib_Buffer_Init();
	if ( (bufr == NULL) || (devauth == NULL) || (userauth == NULL) )
 		goto done;

		
	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\n%s\nHello\n", \
		 SERVER, SITE, LOCATION, EQUIPMENT);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Read and process device authenticator. */
	if ( !authenticate_device(duct, bufr) )
		goto done;
	devauth->add_Buffer(devauth, bufr);
	
	/* Read and process user authenticator. */
	if ( !authenticate_user(duct, bufr) )
		goto done;
	userauth->add_Buffer(userauth, bufr);

	if ( !dispatch_brokers(devauth, userauth, bufr) )
		goto done;

	fputs(">Returning identity referrals.\n", stdout);
	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("!Error send referrals.\n", stderr);
		goto done;
	}

	retn = true;


 done:
	if ( retn == false ) {
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) FAILED, strlen(FAILED));
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;
	}

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( devauth != NULL )
		devauth->whack(devauth);
	if ( userauth != NULL )
		userauth->whack(userauth);

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
		config = "./root-referral.conf";


	/* Initialize process table. */
	init_process_table();


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

	if ( !duct->init_port(duct, NULL, 11990) ) {
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
			if ( handle_connection(duct) ) {
				retn = 0;
				goto done;
			}
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

	return retn;
}
