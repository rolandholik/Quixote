#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <NAAAIM.h>

#include "PossumPipe.h"

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

	PossumPipe pipe = NULL;

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
		fputs("No PossumPipe mode specified.\n", stderr);
		return 1;
	}


	/* Initialize the communications Duct. */
	if ( (pipe = NAAAIM_PossumPipe_Init()) == NULL ) {
		fputs("Cannot initialize PossumPipe.\n", stderr);
		goto done;
	}

	/* Send/receive buffer. */
	if ( (bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer initialization.\n", stderr);
		goto done;
	}


	/* Server management. */
	if ( Mode == server ) {
		fputs("Initializing server connection.\n", stderr);
		if ( !pipe->init_server(pipe, host, 11990, do_reverse) ) {
			fputs("Cannot set server mode.\n", stderr);
			goto done;
		}

		fputs("Waiting for client connection.\n", stderr);
		if ( !pipe->accept_connection(pipe) ) {
			fputs("Error accepting connection.\n", stderr);
			goto done;
		}

		fputs("Starting host mode.\n", stderr);
		if ( !pipe->start_host_mode(pipe) ) {
			fputs("Startup of host mode failed.\n", stderr);
			goto done;
		}

		fputs("Host mode startup complete - waiting for packet.\n", \
		      stderr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}
		fputs("Received payload:\n", stdout);
		bufr->print(bufr);

		fputs("Returning payload.\n", stdout);
		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending packet.\n", stderr);
			goto done;
		}

		fputs("Waiting to shutdown.\n", stdout);
		sleep(5);
	}


	/* Client management. */
	if ( Mode == client ) {
		if ( host == NULL ) {
			fputs("No host specified.\n", stdout);
			goto done;
		}
		fputs("Client mode start:\n", stdout);

		if ( !pipe->init_client(pipe, host, 11990) ) {
			fputs("Cannot initialize client pipe.\n", stderr);
			goto done;
		}
		if ( !pipe->start_client_mode(pipe)) {
			fputs("Error starting client mode.\n", stderr);
			goto done;
		}

		fputs("Client mode setup complete - sending packet:\n", \
		      stderr);
		bufr->add_hexstring(bufr, KEY1);
		bufr->print(bufr);
		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending data packet.\n", stderr);
			goto done;
		}

		bufr->reset(bufr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}

		fputs("Received payload:\n", stdout);
		bufr->print(bufr);
	}


 done:
	WHACK(pipe);
	WHACK(bufr);

	return 0;
}
