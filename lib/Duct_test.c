/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <NAAAIM.h>

#include "Duct.h"

#define KEY1 "0000000000000000000000000000000000000000000000000000000000000000"
#define KEY2 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define CR "\n"
#define OK "OK\n"


extern int main(int argc, char *argv[])

{
	_Bool do_reverse = false;

	enum {none, client, server} Mode = none;

	char *host = NULL;

	int retn;

	Duct duct = NULL;

	Buffer bufr = NULL;


        /* Get operational mode. */
        while ( (retn = getopt(argc, argv, "CSrh:")) != EOF )
                switch ( retn ) {
			case 'C':
				Mode = client;
				break;
			case 'S':
				Mode = server;
				break;

			case 'h':
				host = optarg;
				break;

			case 'r':
				do_reverse = true;
				break;
		}

	if ( Mode == none ) {
		fputs("No Duct mode specified.\n", stderr);
		return 1;
	}


	/* Initialize the communications Duct. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Cannot initialize communications duct.\n", stderr);
		goto done;
	}

	/* Send/receive buffer. */
	if ( (bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer initialization.\n", stderr);
		goto done;
	}


	/* Server management. */
	if ( Mode == server ) {
		struct in_addr *addr;

		fputs("Server mode start:\n", stdout);

		if ( !duct->init_server(duct) ) {
			fputs("Cannot set server mode.\n", stderr);
			goto done;
		}

		if ( (host != NULL) && !duct->set_server(duct, host) ) {
			fputs("Cannot set server address.\n", stderr);
			goto done;
		}

		if ( !duct->init_port(duct, NULL, 11990) ) {
			fputs("Cannot initialize port.\n", stderr);
			goto done;
		}

		duct->do_reverse(duct, do_reverse);

		if ( !duct->accept_connection(duct) ) {
			fputs("Error accepting connection.\n", stderr);
			goto done;
		}

		addr = duct->get_ipv4(duct);
		fprintf(stdout, "Accept connection from: %x / %s / %s\n", \
			ntohl(addr->s_addr), inet_ntoa(*addr),		  \
			duct->get_client(duct));
			

		if ( !duct->receive_Buffer(duct, bufr) ) {
			fputs("Error receiving data.\n", stderr);
			goto done;
		}
		fputs("Received:\n", stdout);
		bufr->print(bufr);

		bufr->reset(bufr);
		duct->receive_Buffer(duct, bufr);
		bufr->print(bufr);

		bufr->reset(bufr);
		duct->receive_Buffer(duct, bufr);
		bufr->print(bufr);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) OK, strlen(OK));
		if ( !duct->send_Buffer(duct, bufr) ) {
			fputs("Error on final send.\n", stderr);
			goto done;
		}

		fputs("Server mode ok.\n", stderr);
		sleep(1);
	}


	/* Client management. */
	if ( Mode == client ) {
		if ( host == NULL ) {
			fputs("No host specified.\n", stdout);
			goto done;
		}
		fputs("Client mode start:\n", stdout);

		if ( !duct->init_client(duct) ) {
			fputs("Cannot initialize client mode.\n", stderr);
			goto done;
		}

		if ( !duct->init_port(duct, host, 11990) ) {
			fputs("Cannot initialize port.\n", stderr);
			goto done;
		}

		bufr->add_hexstring(bufr, KEY1);
		duct->send_Buffer(duct, bufr);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) CR, strlen(CR));
		duct->send_Buffer(duct, bufr);
				    
		bufr->reset(bufr);
		bufr->add_hexstring(bufr, KEY2);
		duct->send_Buffer(duct, bufr);

		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) ) {
			fputs("Client receive failed.\n", stderr);
			goto done;
		}
		bufr->add(bufr, (unsigned char *) "\0", 1);
		fprintf(stdout, "Received: %s", bufr->get(bufr));

		fputs("Client mode ok.\n", stderr);
	}


 done:
	WHACK(duct);
	WHACK(bufr);

	return 0;
}
