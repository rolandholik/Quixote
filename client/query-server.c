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
#include "SmartCard.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *p,
	     inbufr[80];

	unsigned int row;

	FILE *output;

	LCDriver lcd = NULL;

	SmartCard card = NULL;


	if ( (lcd = NAAAIM_LCDriver_Init()) == NULL ) {
		fputs("Cannot initialize LCD driver.\n", stderr);
		return 1;
	}

	lcd->on(lcd);
	lcd->clear(lcd);
	lcd->center(lcd, 0, "Enjellic");
	lcd->center(lcd, 1, "NHIN Query Client");

	while ( (card = NAAAIM_SmartCard_Init()) == NULL ) {
		lcd->clear(lcd);
		lcd->text(lcd, 0, 0, "Enjellic NHIN Client");
		lcd->center(lcd, 1, "No reader.");
		sleep(10);
	}

	lcd->clear(lcd);
	lcd->center(lcd, 0, "NHIN Query Client");
	lcd->center(lcd, 1, "Insert user card");
	if ( card->wait_for_insertion(card) )
		fputs("Card has been inserted.\n", stderr);
	else {
		fputs("Error on card insertion.\n", stderr);
		goto done;
	}


	lcd->clear(lcd);
	lcd->center(lcd, 0, "Remove card.");
	lcd->center(lcd, 1, "Press OK");

	system("/usr/local/bin/usblcd led 0 1");
	fprintf(stdout, "Key: %d\n", lcd->read_key(lcd));
	system("/usr/local/bin/usblcd led 0 0");

	while ( 1 ) {
		lcd->clear(lcd);
		lcd->center(lcd, 0, "Authenticated");
		lcd->center(lcd, 1, "Insert patient card");
		if ( !card->wait_for_insertion(card) )
			fputs("Error on card insertion.\n", stderr);

		lcd->clear(lcd);
		lcd->center(lcd, 0, "Remove patient card.");
		lcd->center(lcd, 1, "Running query.");

		fputs("Running query.\n", stderr);
		system("/opt/NAAAIM/bin/query-client -i " \
		       "/opt/NAAAIM/etc/random.idt | "	  \
		       "tee /var/tmp/query.output");

		fputs("Opening output file.\n", stderr);
		if ( (output = fopen("/var/tmp/query.output", "r")) == NULL ) {
			lcd->clear(lcd);
			lcd->center(lcd, 0, "Query error.");
			sleep(5);
		}

		lcd->clear(lcd);
		system("/usr/local/bin/usblcd led 0 1");
		row = 0;
		while ( fgets(inbufr, sizeof(inbufr), output) != NULL ) {
			if ( (p = strchr(inbufr, '\n')) != NULL )
				*p = '\0';
			if ( strlen(inbufr) == 0 )
				continue;
			fprintf(stderr, "Output line: %s\n", inbufr);
			lcd->text(lcd, row++, 0, inbufr);
			if ( row == 2 ) {
				lcd->read_key(lcd);
				row = 0;
			}
		}
		system("/usr/local/bin/usblcd led 0 0");
	}


 done:
	if ( lcd != NULL )
		lcd->whack(lcd);
	if ( card != NULL )
		card->whack(card);

	return 0;
}
