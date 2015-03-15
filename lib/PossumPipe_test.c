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
		if ( !pipe->init_server(pipe, host, 11990, do_reverse) ) {
			fputs("Cannot set server mode.\n", stderr);
			goto done;
		}

		if ( !pipe->start_host_mode(pipe) ) {
			fputs("Startup of host mode failed.\n", stderr);
			goto done;
		}
	}


	/* Client management. */
	if ( Mode == client ) {
		if ( host == NULL ) {
			fputs("No host specified.\n", stdout);
			goto done;
		}
		fputs("Client mode start:\n", stdout);

		if ( !pipe->init_client(pipe, host, 11990) ) {
			fputs("Cannot initialize client mode.\n", stderr);
			goto done;
		}
		fputs("Client mode ok.\n", stderr);
	}


 done:
	WHACK(pipe);
	WHACK(bufr);

	return 0;
}
