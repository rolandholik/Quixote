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
#include <String.h>
#include <NAAAIM.h>

#include "MQTTduct.h"


extern int main(int argc, char *argv[])

{
	char *msg     = NULL,
	     *topic   = NULL,
	     *broker  = NULL,
	     *user    = NULL,
	     *pwd     = NULL;

	int retn = 1;

	enum {none, publisher} Mode = none;

	MQTTduct duct = NULL;

	String str = NULL;


        /* Get operational mode. */
        while ( (retn = getopt(argc, argv, "Pb:m:p:t:u:")) != EOF )
                switch ( retn ) {
			case 'P':
				Mode = publisher;
				break;

			case 'b':
				broker = optarg;
				break;
			case 'm':
				msg = optarg;
				break;
			case 'p':
				pwd = optarg;
				break;
			case 't':
				topic = optarg;
				break;
			case 'u':
				user = optarg;
				break;
		}

	if ( Mode == none ) {
		fputs("No MQTTduct mode specified.\n", stderr);
		return 1;
	}


	/* Initialize the communications Duct. */
	if ( (duct = NAAAIM_MQTTduct_Init()) == NULL ) {
		fputs("Failed MQTT initialization.\n", stderr);
		goto done;
	}

	/* Send/receive buffer. */
	if ( (str = HurdLib_String_Init()) == NULL ) {
		fputs("Failed message object initialization.\n", stderr);
		goto done;
	}


	/* Publisher test. */
	if ( Mode == publisher ) {
		if ( broker == NULL ) {
			fputs("No broker specified.\n", stderr);
			goto done;
		}
		if ( msg == NULL ) {
			fputs("No message specified.\n", stderr);
			goto done;
		}
		if ( topic == NULL ) {
			fputs("No topic specified.\n", stderr);
			goto done;
		}

		if ( !duct->init_publisher(duct, broker, 0, topic, user, pwd) )
			ERR(goto done);

		if ( !str->add(str, msg) ) {
			fputs("Failed to create message.\n", stderr);
			goto done;
		}

		fputs("Sending string.\n", stderr);
		if ( !duct->send_String(duct, str) ) {
			fputs("Failed publication.\n", stderr);
			goto done;
		}
	}

	retn = 0;


 done:
	WHACK(duct);
	WHACK(str);

	return retn;
}
