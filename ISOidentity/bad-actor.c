/** \file
 * This file implements a utility for testing and setting the bad
 * actor status of a process.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#define _GNU_SOURCE

#include <stdio.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <asm/unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>


/* sys_set_behavior system call interface definition. */
#define BAD_ACTOR 437

#define BAD_ACTOR_QUERY		0
#define BAD_ACTOR_SET		1
#define BAD_ACTOR_RELEASE	2


/**
 * System call wrapper for setting the actor status of a process.
 */
static inline int sys_set_bad_actor(pid_t pid, unsigned long flags)
{
	return syscall(BAD_ACTOR, pid, flags);
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool set     = false,
	      query   = false,
	      release = false;

	char *pidstr = NULL;

	int opt,
	    status,
	    retn = 1;

	pid_t pid;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "q:r:s:")) != EOF )
		switch ( opt ) {
			case 'q':
				query  = true;
				pidstr = optarg;
				break;

			case 'r':
				release = true;
				pidstr = optarg;
				break;

			case 's':
				set    = true;
				pidstr = optarg;
				break;
		}


	/* Verify arguements. */
	if ( !query && !set && !release ) {
		fputs("No mode specified, use -q PID, -s PID, or -r PID\n", \
		      stderr);
		goto done;
	}


	/* Convert the pid arguement to a number. */
	pid = strtoul(pidstr, NULL, 10);
	if ( errno == ERANGE ) {
		fprintf(stderr, "Invalid pid specified: %u\n", pid);
		goto done;
	}


	/* Query the status of a process. */
	if ( query ) {
		status = sys_set_bad_actor(pid, BAD_ACTOR_QUERY);
		if ( status < 0 ) {
			if ( errno == -ESRCH ) {
				fprintf(stderr, "Pid not found: %u\n", pid);
				goto done;
			}
			fprintf(stderr, "Error querying actor status: %s\n", \
				strerror(errno));
			goto done;
		}

		fprintf(stderr, "Process %u is a %s actor.\n", pid, \
			status ? "bad" : "good");
		retn = 0;
	}


	/* Set the process to be a bad actor. */
	if ( set ) {
		status = sys_set_bad_actor(pid, BAD_ACTOR_SET);
		if ( status < 0 ) {
			if ( errno == -ESRCH ) {
				fprintf(stderr, "Pid not found: %u\n", pid);
				goto done;
			}
			fprintf(stderr, "Error setting process: %s\n", \
				strerror(errno));
			goto done;
		}

		fprintf(stderr, "Process %u is now a bad actor.\n", pid);
		retn = 0;
	}


	/* Set the process to be a good actor. */
	if ( release ) {
		status = sys_set_bad_actor(pid, BAD_ACTOR_RELEASE);
		if ( status < 0 ) {
			if ( errno == -ESRCH ) {
				fprintf(stderr, "Pid not found: %u\n", pid);
				goto done;
			}
			fprintf(stderr, "Error setting process: %s\n", \
				strerror(errno));
			goto done;
		}

		fprintf(stderr, "Process %u is now a good actor.\n", pid);
		retn = 0;
	}


 done:
	return retn;
}
