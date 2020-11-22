/** \file
 * This file implements a utility for configuring network interfaces
 * and routes.  It runs in two modes, one for configuring interfaces
 * and the second for configuring routes.  Three additional arguements
 * are accepted which define either the interface or the route.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <HurdLib.h>

#include "Netconfig.h"


/**
 * Private function.
 *
 * This function carries out the configuration of a network interface.
 *
 * \param iface		A pointer to the interface which is to be
 *			configured.
 *
 * \param address	A character pointer to the address to be
 *			applied to the interface.
 *
 * \param mask		A character pointer to the netmask to be used
 *			on the interface.
 *
 * \return		No return value is defined.
 */

static void configure_interface(CO(char *, iface), CO(char *, address), \
				 CO(char *, mask))

{
	Netconfig netconfig = NULL;


	INIT(NAAAIM, Netconfig, netconfig, return);

	if ( !netconfig->set_address(netconfig, iface, address, mask) ) {
		fprintf(stdout, "Failed to set address: %d => %s\n", \
			netconfig->get_error(netconfig),	      \
			strerror(netconfig->get_error(netconfig)));
	}

	WHACK(netconfig);
	return;
}


/**
 * Private function.
 *
 * This function carries out the configuration of a network route.
 *
 * \param destination	A pointer to the destination network.
 *
 * \param gateway	A character pointer to the network address of
 *			the gateway for the route.
 *
 * \param mask		A character pointer to the netmask to be used
 *			on the destination address.
 *
 * \return		No return value is defined.
 */

static void configure_route(CO(char *, destination), CO(char *, gateway), \
			    CO(char *, mask))

{
	Netconfig netconfig = NULL;


	INIT(NAAAIM, Netconfig, netconfig, return);

	if ( !netconfig->set_route(netconfig, destination, gateway, mask) ) {
		fprintf(stdout, "Failed to set route: %d => %s\n", \
			netconfig->get_error(netconfig),	      \
			strerror(netconfig->get_error(netconfig)));
	}

	WHACK(netconfig);
	return;
}


/*
 * Main program starts here.
 */

extern int main(int argc, char *argv[])

{
	int opt;

	enum {none, interface, route} mode = none;


	/* Get the root image and passwd file name. */
	while ( (opt = getopt(argc, argv, "IR")) != EOF )
		switch ( opt ) {
			case 'I':
				mode = interface;
				break;
			case 'R':
				mode = route;
				break;
		}


	/* Verify arguements. */
	if ( mode == none ) {
		fputs("No mode specified.\n", stderr);
		return 1;
	}
	if ( argc != 5 ) {
		fputs("Insufficient arguements specified.\n", stderr);
		return 1;
	}


	/* Select operation mode. */
	switch ( mode ) {
		case interface:
			configure_interface(argv[optind], argv[optind+1], \
					    argv[optind+2]);
			break;

		case route:
			configure_route(argv[optind], argv[optind+1], \
					argv[optind+2]);
			break;

		case none:
			break;
	}

	return 0;
}
