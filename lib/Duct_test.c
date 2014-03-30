#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

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
	enum {none, client, server} Mode = none;

	int retn;

	Duct duct = NULL;

	Buffer bufr = NULL;


        /* Get operational mode. */
        while ( (retn = getopt(argc, argv, "CS")) != EOF )
                switch ( retn ) {
			case 'C':
				Mode = client;
				break;
			case 'S':
				Mode = server;
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
		fputs("Server mode start:\n", stdout);

		if ( !duct->init_server(duct) ) {
			fputs("Cannot set server mode.\n", stderr);
			goto done;
		}

		if ( !duct->init_port(duct, NULL, 11990) ) {
			fputs("Cannot initialize port.\n", stderr);
			goto done;
		}

		if ( !duct->accept_connection(duct) ) {
			fputs("Error accepting connection.\n", stderr);
			goto done;
		}

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
		fputs("Client mode start:\n", stdout);

		if ( !duct->init_client(duct) ) {
			fputs("Cannot initialize client mode.\n", stderr);
			goto done;
		}

		if ( !duct->init_port(duct, "xesd4.enjellic.com", 11990) ) {
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