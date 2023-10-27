/** \file
 *
 * This file implements a utility for reading and outputting the
 * security state event characteristics of the root security modeling
 * namespace in a kernel that is running in tsem_mode 2 or export only
 * mode.
 *
 * The security event characteristics are exported through the
 * following pseudo-file:
 *
 * /sys/kernel/security/tsem/ExternalTMA/0
 */

/**************************************************************************
 * Copyright (c) 2023, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#define _GNU_SOURCE

#define TSEM_ROOT_EXPORT "/sys/kernel/security/tsem/ExternalTMA/0"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <NAAAIM.h>
#include <HurdLib.h>
#include <String.h>

#include "quixote.h"


/**
 * Boolan flag to indicate that a termination signal has been received.
 */
static _Bool Stop = false;


/**
 * Private function.
 *
 * This function implements the signal handler for the utility.  It
 * sets the signal type in the Signals structure.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 */

void signal_handler(int signal, siginfo_t *siginfo, void *private)

{

	switch ( signal ) {
		case SIGINT:
		case SIGTERM:
		case SIGHUP:
		case SIGQUIT:
			Stop = true;
			break;
		default:
			break;

	}

	return;
}


/**
 * Private function.
 *
 * This function is responsible for reading and exporting the list of
 * security event descriptions that are in the kernel export list at
 * the time the function is invoked.
 *
 * \param fd	The file descriptor to the kernel security event
 *		export file.
 *
 * \return	A boolean value is used to indicate that status of
 *		the event exports.  A false value indicates an error
 *		was encountered while a true value indicates the
 *		events were successfully output.
 */

static _Bool export_events(const int fd)

{
	_Bool retn = false;

	char bufr[1024];

	int rc = 0;


	while ( true ) {
		memset(bufr, '\0', sizeof(bufr));

		rc = read(fd, bufr, sizeof(bufr));
		if ( Stop || (rc == 0) ) {
			retn = true;
			break;
		}

		if ( rc < 0 ) {
			if ( errno == ENODATA )
				break;
			else
				ERR(goto done);
		}

		fprintf(stdout, "%s", bufr);
		if ( lseek(fd, 0, SEEK_SET) < 0 )
			ERR(goto done);
	}

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible implementing 'follow' mode that outputs
 * the existing security event characteristics and then polls and
 * outputs events as they occur.
 *
 * \param fd	The file descriptor to the kernel security event
 *		export file.
 *
 * \return	A boolean value is used to indicate that status of
 *		the event exports.  A false value indicates an error
 *		was encountered while a true value indicates the
 *		events were successfully output.
 */

static _Bool follow_events(const int fd)

{
	_Bool retn = false;

	char bufr[1024];

	int rc = 0;

	struct pollfd poll_data[1];


	/* Flush existing entries. */
	if ( export_events(fd) )
		fflush(stdout);
	else
		ERR(goto done);


	/* Poll for additional events. */
	poll_data[0].fd	    = fd;
	poll_data[0].events = POLLIN;

	while ( true ) {
		rc = poll(poll_data, 1, -1);
		if ( Stop )
			break;

		if ( rc < 0 ) {
			if ( errno == EINTR ) {
				fputs("poll interrupted.\n", stderr);
				continue;
			}
		}

		if ( (poll_data[0].revents & POLLIN) == 0 )
			continue;

		while ( true ) {
			memset(bufr, '\0', sizeof(bufr));

			rc = read(fd, bufr, sizeof(bufr));
			if ( Stop || (rc == 0) )
				break;

			if ( rc < 0 ) {
				if ( errno != ENODATA ) {
					fputs("Fatal event read.\n", stderr);
					goto done;
				}
				break;
			}

			fprintf(stdout, "%s", bufr);
			if ( lseek(fd, 0, SEEK_SET) < 0 ) {
				fputs("Seek error.\n", stderr);
				goto done;
			}
		}
	}

	retn = true;


 done:
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool follow = false;

	char fname[80],
	     *stdio_buffer = NULL,
	     *buffer_size = NULL;

	int fd,
	    opt,
	    queue_size,
	    retn = 1;

	struct sigaction signal_action;


	while ( (opt = getopt(argc, argv, "fb:")) != EOF )
		switch ( opt ) {
			case 'f':
				follow = true;
				break;

			case 'b':
				buffer_size = optarg;
				break;
		}


	/* Open the root export file. */
	memset(fname, '\0', sizeof(fname));
	if ( snprintf(fname, sizeof(fname), TSEM_ROOT_EXPORT) \
	     >= sizeof(fname) )
		ERR(goto done);
	if ( (fd = open(fname, O_RDONLY)) < 0 )
		ERR(goto done);


	/* Set queue size if alternative is specified. */
	if ( buffer_size != NULL ) {
		queue_size = strtol(buffer_size, NULL, 0);
		if ( (errno == ERANGE) || (queue_size < 0) ) {
			fputs("Invalid queue_size specified.\n", stderr);
			goto done;
		}
		queue_size *= 1024 * 1024;

		if ( (stdio_buffer = malloc(queue_size)) == NULL ) {
			fputs("Cannot allocate stdio buffer.\n", stderr);
			goto done;
		}
		setbuffer(stdout, stdio_buffer, queue_size);
	}


	/* Setup signal handlers. */
	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		ERR(goto done);

	signal_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	signal_action.sa_sigaction = signal_handler;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTERM, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGHUP, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGQUIT, &signal_action, NULL) == -1 )
		goto done;


	/* Handle one shot output of event. */
	if ( !follow ) {
		if ( export_events(fd) )
			retn = 0;
		else
			fputs("Error exporting events.\n", stderr);
		goto done;
	}


	/* Implement 'follow' mode. */
	if ( follow_events(fd) )
		retn = 0;
	else
		fputs("Error following events.\n", stderr);


 done:
	close(fd);

	return retn;
}
