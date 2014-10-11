/** \file
 *
 * This file implements the identity generation daemon.  This daemon
 * is responsible for loading the identity tree root and then listens
 * for requests to generate identities.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#if 0
#define IDENTITY_ROOT "/etc/conf/idroot.conf"
#else
#define IDENTITY_ROOT "./idroot.conf"
#endif


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Config.h>


/* Static variable definitions. */

/* Structure to hold indicators as to which signal was generated. */
struct {
	_Bool sigusr1;
	_Bool sigint;
} signals;



/**
 * Private function.
 *
 * This function implements the signal handler for the utility.  It
 * sets the signal type in the signals structure.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 */

void signal_handler(int signal)

{
	switch ( signal ) {
		case SIGUSR1:
			signals.sigusr1 = true;
			break;
		case SIGINT:
			signals.sigint = true;
			break;
	}

	return;
}


/**
 * Private function.
 *
 * This function is responsible for checking for the presence of
 * a device identity on the root filesystem and loading it into
 * NVram if it is authentic.
 *
 * \return		A false value indicates the identity root
 *			was no properly initialized.  A true value
 *			indicates the identity state was properly
 *			initialized.
 */

static _Bool load_identity_root(void)

{
	_Bool retn = false;

	struct stat idfile;


	if ( stat(IDENTITY_ROOT, &idfile) == -1 ) {
		if ( errno == ENOENT ) {
			retn = true;
			goto done;
		}
	}

	retn = true;


 done:
	return retn;
}
		

/**
 * Private function.
 *
 * This function is responsible for implementing the identity gneration
 * processing loop.  This function pauses waiting for a SIGUSR1 signal.
 * When it receives a signal it reads the identity request structure
 * for the type of identity to be generated and the value to be
 * used for generating the identity.
 *
 * \param identity	The token which the identity manager is
 *			implementing identity services for.
 *
 * \return		No return value is specified.
 */

static void identity_generator(void)

{
	struct sigaction signal_action;

#if 0
	IDmgr idmgr = NULL;


	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->setup(idmgr) )
		goto done;
#endif

	signal_action.sa_handler = signal_handler;
	if ( sigaction(SIGUSR1, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;

	while ( 1 ) {
		pause();
		if ( signals.sigint )
			goto done;
		fputs("Processing identity request.\n", stderr);

#if 0
		if ( !idmgr->set_idtoken(idmgr, identity) )
			goto done;
#endif
		signals.sigint = false;
	}

 done:
#if 0
	WHACK(idmgr);
#endif

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	if ( !load_identity_root() ) {
		fputs("Failed to load identity root.\n", stderr);
		goto done;
	}

	identity_generator();
	retn = 0;


 done:
#if 0
	WHACK(identity);
#endif

	return retn;
}
