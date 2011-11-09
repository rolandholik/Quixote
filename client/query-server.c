/** \file
 * This file contains an implementation of the query client server.
 * This application runs on an imbedded application platform and
 * handles interaction with the user through the input buttons on
 * the device.  Output is generated to the LCD display on the device.
 */

/**************************************************************************
 * (C)Copyright 2011, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define INSTALL_DIR "/opt/NAAAIM"
#define CONFIG_FILE INSTALL_DIR "/etc/query-server.conf"

#define CERTIFICATE "/opt/NAAAIM/lib/identity-provider/server-cert.pem"


/* Include files. */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "LCDriver.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	LCDriver lcd = NULL;


	if ( (lcd = NAAAIM_LCDriver_Init()) == NULL ) {
		fputs("Cannot initialize LCD driver.\n", stderr);
		return 1;
	}

	lcd->on(lcd);
	lcd->clear(lcd);
	lcd->center(lcd, 0, "IDfusion");
	lcd->center(lcd, 1, "NHIN Query Client");

	fprintf(stdout, "Key: %d\n", lcd->read_key(lcd));


	if ( lcd != NULL )
		lcd->whack(lcd);

	return 0;
}
