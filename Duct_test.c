#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "Buffer.h"
#include "NAAAIM.h"
#include "Duct.h"

#define KEY1 "0000000000000000000000000000000000000000000000000000000000000000"
#define KEY2 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define CR "\n"
#define OK "OK\n"


extern int main(int argc, char *argv[])

{
	auto enum {none, client, server} Mode = none;

	auto int retn;

	auto Duct duct = NULL;

	auto Buffer bufr = NULL;


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


	/* SSL server management. */
	if ( Mode == server ) {
		fputs("Server mode start:\n", stdout);

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
		if ( duct->send_Buffer(duct, bufr) )
			goto done;

		fputs("Server mode ok.\n", stderr);
	}


	/* SSL server management. */
	if ( Mode == client ) {
		fputs("Client mode start:\n", stdout);

		if ( !duct->init_client(duct) ) {
			fputs("Cannot initialize client mode.\n", stderr);
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

		if ( !duct->init_connection(duct) ) {
			fputs("Cannot initialize connection.\n", stderr);
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
	if ( !duct->whack_connection(duct) )
		fputs("Error shutting down connection.\n" ,stderr);
	if ( duct != NULL )
		duct->whack(duct);

	if ( bufr != NULL )
		bufr->whack(bufr);

	return 0;
}
