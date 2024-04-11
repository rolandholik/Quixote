/** \file
 * This file contains the implementation of the Sancho interpreter.
 * This code runs in a thread that takes TTYduct encapsulated commands
 * from the Quixote instance and executes them.
 */

/**************************************************************************
 * (C)Copyright 2021, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Module definitions. */
#define IDSIZE 32


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <cmsis_os.h>
#include <rtosal.h>
#include <com_sockets.h>
#include <dc_common.h>
#include <cellular_service_task.h>

#include "HurdLib.h"
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <sancho-cmd.h>

#include "Base64.h"
#include "RSAkey.h"
#include "SecurityEvent.h"
#include "SecurityPoint.h"
#include "TSEM.h"
#include "TTYduct.h"
#include "Duct.h"

#include "sancho.h"


/* Communications object to be used by all functions. */
TTYduct Host;

/* Flag to specifier interpreter error. */
static _Bool Have_Error;

/* Static declarations for interpreter thread. */
static osSemaphoreId interpreter_semaphore = 0;
static osThreadId interpreter_id;


static void send_ok(TTYduct duct, Buffer bufr)

{
	static const char ok[] = "OK";


	bufr->reset(bufr);
	bufr->add(bufr, (void *) ok, sizeof(ok));

	duct->send_Buffer(duct, bufr);

	return;
}


/**
 * External function call.
 *
 * This function implements the Sancho command interpreter.
 *
 * \return	No return value is defined.
 */

static void interpreter(const void *arg)

{
	_Bool verify = false;

	char response[] = "This is Sancho.",
	     ok[]	= "OK",
	     key[]	= "key ",
	     error[]	= "ERROR",
	     invalid[]	= "Bad signature";

	Buffer bufr = NULL,
	       vfy  = NULL;

	TTYduct duct = NULL;

	TSEM model = NULL;

	Base64 b64 = NULL;

	String str = NULL;

	RSAkey rsakey = NULL;


	INIT(HurdLib, Buffer, bufr, (printf("init error.\n")));
	INIT(HurdLib, Buffer, vfy, (printf("init error.\n")));
	INIT(NAAAIM, TTYduct, duct, (printf("init error.\n")));

	duct->init_device(duct, NULL);

	Host = duct;

	INIT(HurdLib, String, str, (printf("String init error.\n")));
	INIT(NAAAIM, TSEM, model, (printf("Model init error.\n")));
	INIT(NAAAIM, Base64, b64, (printf("Base64 init error.\n")));
	INIT(NAAAIM, RSAkey, rsakey, (printf("RSAkey init error.\n")));

	while ( true ) {
		/* Receive the key. */
		if ( !duct->receive_Buffer(duct, bufr) )
			goto loop;

		if ( !str->add(str, (char *) bufr->get(bufr)) )
			goto loop;

		if ( !vfy->add(vfy, (void *) key, strlen(key)) )
			goto loop;
		if ( !vfy->add(vfy, (void *) str->get(str), \
			       str->size(str) + 1) )
			goto loop;

		bufr->reset(bufr);
		if ( !b64->decode(b64, str, bufr) )
			goto loop;

		if ( !bufr->add(bufr, (void *) "\0", 1) )
			goto loop;

		if ( !rsakey->load_public(rsakey, bufr) )
			goto loop;

		send_ok(duct, bufr);


		/* Receive string to verify. */
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			goto loop;

		if ( !vfy->add_Buffer(vfy, bufr) )
			goto loop;

		send_ok(duct, bufr);


		/* Receive signature. */
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			goto loop;

		str->reset(str);
		if ( !str->add(str, (char *) bufr->get(bufr)) )
			goto loop;

		bufr->reset(bufr);
		if ( !b64->decode(b64, str, bufr) )
			goto loop;


		/* Verify the string. */
		if ( !rsakey->verify(rsakey, bufr, vfy, &verify) ) {
			bufr->reset(bufr);
			bufr->add(bufr, (void *) error, sizeof(error));
		} else {
			bufr->reset(bufr);
			if ( verify )
				bufr->add(bufr, (void *) ok, sizeof(ok));
			else
				bufr->add(bufr, (void *) invalid, \
					  sizeof(invalid));
		}

		if ( !duct->send_Buffer(duct, bufr) ) {
			bufr->reset(bufr);
			continue;
		}

	loop:
		str->reset(str);
		bufr->reset(bufr);
		vfy->reset(vfy);
		Have_Error = false;
	}

	return;
}


/**
 * External function call.
 *
 * This function implements the initialization of the thread that
 * will run the interpreter function.
 *
 * \return	A pointer to the initialized Actor.  A null value
 *		indicates an error was encountered in object generation.
 */

_Bool interpreter_init(void)

{
	_Bool retn = false;


	interpreter_semaphore = rtosalSemaphoreNew(NULL, 1);
	rtosalSemaphoreAcquire(interpreter_semaphore, RTOSAL_WAIT_FOREVER);


	interpreter_id = rtosalThreadNew((unsigned char *) "interpreter", \
					 interpreter, osPriorityNormal,	  \
					 600, NULL);
	if ( interpreter_id == NULL )
		ERR(goto done);
	retn = true;

 done:
	return retn;
}


void Error(const char *file, const char *function, int line)

{
	char bufr[80];

	Buffer msg = NULL;


	if ( Have_Error )
		return;

	memset(bufr, '\0', sizeof(bufr));
	snprintf(bufr, sizeof(bufr), "T[%s,%s,%d]: Error location.", file, \
		 function, line);

	INIT(HurdLib, Buffer, msg, return);
	msg->add(msg, (unsigned char *) bufr, strlen(bufr) + 1);
	Host->send_Buffer(Host, msg);

	Have_Error = true;
	WHACK(msg);
	return;


}
