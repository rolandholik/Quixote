/** \file
 * This file contains a simple utility to test security event handling
 * with a threaded program.  A single thread is spawned which pauses
 * for five seconds and then reads and dumps the /etc/group file.
 *
 * The primary process pauses for 10 seconds and then reads and dumps
 * the /etc/passwd file.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <Buffer.h>
#include <File.h>


/**
 * Private function.
 *
 * This function is a wrapper function which is the target of the
 * thread first thread that is creating a security state event.
 *
 * \param mgr_args	The pointer to the structure containing the
 *			arguements for the thread.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the invoication of the manager was
 *			successful.  A false value indicates there was
 *			an error in starting the manager thread.  A
 *			true value indicates that it executed successfully.
 */

static void * thread_one(void *mgr_args)

{
	unsigned int wait_time = *(unsigned int *) mgr_args;

	Buffer bufr = NULL;

	File file = NULL;

	sleep(wait_time);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, "/etc/group") )
		ERR(goto done);

	if ( !file->slurp(file, bufr) )
		ERR(goto done);

	fputs("Secondary thread.\n", stdout);
	bufr->hprint(bufr);
	fflush(stdout);


 done:
	WHACK(bufr);
	WHACK(file);

	pthread_exit(NULL);
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1,
	    wait_time = 5;

	pthread_attr_t mgr_attr;

	pthread_t mgr_thread;

	Buffer bufr = NULL;

	File file = NULL;


	/* Start the manager thread. */
	if ( pthread_attr_init(&mgr_attr) != 0 ) {
		fputs("Unable to initialize thread attributes.\n", stderr);
		goto done;
	}

	if ( pthread_create(&mgr_thread, &mgr_attr, thread_one, &wait_time) \
	     != 0 ) {
			fputs("Cannot start thread manager.\n", stderr);
			goto done;
	}


	/* Access a file here. */
	sleep(2*wait_time);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, "/etc/passwd") )
		ERR(goto done);

	if ( !file->slurp(file, bufr) )
		ERR(goto done);

	fputs("Primary thread.\n", stdout);
	bufr->hprint(bufr);
	fflush(stdout);


 done:
	WHACK(bufr);
	WHACK(file);

	return retn;
}
