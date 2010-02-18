#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "Buffer.h"
#include "NAAAIM.h"
#include "Duct.h"


extern int main(int argc, char *argv[])

{
	auto enum {none, client, server} Mode = none;

	auto int retn;

	auto Duct duct = NULL;


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


	/* SSL server management. */
	if ( Mode == server ) {
		if ( !duct->init_server(duct) ) {
			fputs("Cannot initialize server mode.\n", stderr);
			goto done;
		}

		if ( !duct->load_credentials(duct, "./org-private.pem", \
					     "./org-cert.pem") ) {
			fputs("Cannot load server credentials.\n", stderr);
			goto done;
		}

		if ( !duct->init_port(duct, 11990) ) {
			fputs("Cannot initialize port.\n", stderr);
			goto done;
		}

		if ( duct->accept_connection(duct) == -1 ) {
			fputs("Error accepting connection.\n", stderr);
			goto done;
		}

		fputs("Server mode ok.\n", stderr);
		
	}

		

 done:
	if ( duct != NULL )
		duct->whack(duct);

	return 0;
}
