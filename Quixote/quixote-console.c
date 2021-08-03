
/** \file
 *
 * This file implements a utility for managing a quixote co-processor
 * implement.  It connects to the quixote management process through a
 * UNIX domain socket created in the following location:
 *
 * /var/run/quixote-mgmt.CARTRIDGE
 *
 * Where CARTRIDGE is the software cartridge being run.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <Buffer.h>

#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "LocalDuct.h"


/**
 * Private function.
 *
 * This function implements the receipt of a trajectory list from
 * the cartridge management daemon.  The protocol used is for the
 * management daemon to send the number of points in the trajectory
 * followed by each point in ASCII form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the trajectory
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Trajectory size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a forenscis list from
 * the cartridge management daemon.  The protocol used is for the
 * management daemon to send the number of events in the forensics
 * patch followed by each event in ASCII form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the forensics
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_forensics(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Forensics size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a contour list from
 * the cartridge management daemon.  The protocol used is for the
 * management daemon to send the number of points in the behavioral
 * field followed by point in ASCII hexadecimal form.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing processing the contour
 *			list.  A false value indicates an error occurred
 *			while a true value indicates the response was
 *			properly processed.
 */

static _Bool receive_contours(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "Contour size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the receipt of a list of AI events from
 * the cartridge management daemon.  The protocol used is for the
 * management daemon to send the number of events in the AI list
 * followed by each event as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmdbufr	The object used to process the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate the
 *			status of processing the event list.  A false
 *			value indicates an error occurred while a true
 *			value indicates the response was properly
 *			processed.
 */

static _Bool receive_ai_events(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	fprintf(stderr, "AI event size: %u\n", cnt);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}

	cmdbufr->reset(cmdbufr);
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements receipt and processing of the command
 * which was executed on the cartridge management daemon.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmdbufr	The object used to hold the remote command
 *			response.
 *
 * \return		A boolean value is returned to indicate an
 *			error was encountered while processing receipt
 *			of the command.  A false value indicates an
 *			error occurred while a true value indicates the
 *			response was properly processed.
 */

static _Bool receive_command(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr), \
			     int cmdnum)

{
	_Bool retn = false;


	switch ( cmdnum ) {
		case seal_event:
		case enable_cell:
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			fprintf(stdout, "%s\n", cmdbufr->get(cmdbufr));
			fflush(stdout);
			cmdbufr->reset(cmdbufr);
			retn = true;
			break;

		case show_measurement:
		case show_state:
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->print(cmdbufr);
			cmdbufr->reset(cmdbufr);
			retn = true;
			break;

		case show_trajectory:
			retn = receive_trajectory(mgmt, cmdbufr);
			break;

		case show_forensics:
			retn = receive_forensics(mgmt, cmdbufr);
			break;

		case show_contours:
			retn = receive_contours(mgmt, cmdbufr);
			break;

		case show_events:
			retn = receive_ai_events(mgmt, cmdbufr);
			break;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the parsing of the supplied command and
 * the translation of this command to a binary expression of the
 * command.  The binary command is sent over the command socket and
 * the socket is read for the command response.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param cmd		A character point to the null-terminated buffer
 *			containing the ASCII version of the command.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of commands should continue.  A
 *			false value indicates the processing of commands
 *			should be terminated while a true value indicates
 *			an additional command cycle should be processed.
 */

static _Bool process_command(CO(LocalDuct, mgmt), CO(char *, cmd))

{
	_Bool retn = false;

	int lp,
	    cmdnum = 0;

	struct sancho_cmd_definition *cp = Sancho_cmd_list;

	Buffer cmdbufr = NULL;


	/* Locate the command. */
	for (lp= 0; cp[lp].syntax != NULL; ++lp) {
		if ( strcmp(cp[lp].syntax, cmd) == 0 )
			cmdnum = cp[lp].command;
	}
	if ( cmdnum == 0 ) {
		fprintf(stdout, "Unknown command: %s\n", cmd);
		fflush(stdout);
		retn = true;
		goto done;
	}

	/* Send the command over the management socket. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	cmdbufr->add(cmdbufr, (unsigned char *) &cmdnum, sizeof(cmdnum));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);

	cmdbufr->reset(cmdbufr);
	if ( !receive_command(mgmt, cmdbufr, cmdnum) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(cmdbufr);
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *p,
	     inbufr[1024];

	int retn = 1;

	FILE *idfile = NULL;

	Buffer id_bufr = NULL,
	       cmdbufr = NULL;

	LocalDuct mgmt = NULL;

	File infile = NULL;


	/* Setup the management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));

	if ( !mgmt->init_client(mgmt) ) {
		fputs("Cannot set socket client mode.\n", stderr);
		goto done;
	}

	if ( !mgmt->init_port(mgmt, SOCKNAME) ) {
		fputs("Cannot initialize management port.\n", stderr);
		goto done;
	}


	/* Command loop. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	while ( 1 ) {
		memset(inbufr, '\0', sizeof(inbufr));

		fputs("Quixote>", stderr);
		if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL )
			goto done;
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';
		if ( strcmp(inbufr, "quit") == 0 ) {
			goto done;
		}

		if ( !process_command(mgmt, inbufr) )
			goto done;

	}


 done:
	if ( idfile != NULL )
		fclose(idfile);

	WHACK(id_bufr);
	WHACK(cmdbufr);
	WHACK(mgmt);
	WHACK(infile);

	return retn;
}
