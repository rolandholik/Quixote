/** \file
 * This file implements a test utility for issueing commands to the
 * sancho security co-processor.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <HurdLib.h>
#include <Buffer.h>

#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "TTYduct.h"

_Bool Sealed = false;


/**
 * Private function.
 *
 * This function is responsible for returning the current walltime
 * in milliseconds.
 *
 * \return		The epoch time in milli-seconds.
 */

static double wall_time(void)

{
	struct timeval walltime;


	if ( gettimeofday(&walltime, NULL) )
		return 0;

	return (double) (1000.0 * (double) walltime.tv_sec + \
			 (double) walltime.tv_usec / 1000.0);
}


/**
 * Private function.
 *
 * This function is responsible for receiving a set of contour points
 * from the sancho.
 *
 * \param duct		The communications object being used to
 *			communicate with the co-processor.

 * \param bufr		A pointer to Buffer object to be used for the
 *			communications.
 *
 * \return		No return value is defined.
 */

static void receive_points(CO(TTYduct, duct), CO(Buffer, bufr))

{
	unsigned int cnt;


	/* Get the number of points. */
	cnt = *(unsigned int *) bufr->get(bufr);
	fprintf(stderr, "Field size: %u\n", cnt);


	/* Output each point. */
	while ( cnt-- ) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", bufr->get(bufr));
	}

	bufr->reset(bufr);


 done:
	return;
}


/**
 * Private function.
 *
 * This function is responsible for receiving a set of security events
 * from the sancho co-processor.
 *
 * \param duct		The communications object being used to
 *			communicate with the co-processor.

 * \param bufr		A pointer to Buffer object to be used for the
 *			communications.
 *
 * \return		No return value is defined.
 */

static void receive_events(CO(TTYduct, duct), CO(Buffer, bufr))

{
	unsigned int cnt;


	/* Get the number of points. */
	cnt = *(unsigned int *) bufr->get(bufr);
	fprintf(stderr, "Event count: %u\n", cnt);


	/* Output each point. */
	while ( cnt-- ) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", bufr->get(bufr));
	}

	bufr->reset(bufr);


 done:
	return;
}


/**
 * Private function.
 *
 * This function is responsible for receiving the behavioral trajectory
 * from sancho.
 *
 * \param duct		The communications object being used to
 *			communicate with the co-processor.

 * \param bufr		A pointer to Buffer object to be used for the
 *			communications.
 *
 * \return		No return value is defined.
 */

static void receive_trajectory(CO(TTYduct, duct), CO(Buffer, bufr))

{
	unsigned int cnt;


	/* Get the number of points. */
	cnt = *(unsigned int *) bufr->get(bufr);
	fprintf(stderr, "Trajectory size: %u\n", cnt);


	/* Output each point. */
	while ( cnt-- ) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", bufr->get(bufr));
	}

	bufr->reset(bufr);


 done:
	return;
}


/**
 * Private function.
 *
 * This function is responsible for receiving a forensics log from the
 * sancho coprocessor.
 *
 * \param duct		The communications object being used to
 *			communicate with the co-processor.

 * \param bufr		A pointer to Buffer object to be used for the
 *			communications.
 *
 * \return		No return value is defined.
 */

static void receive_forensics(CO(TTYduct, duct), CO(Buffer, bufr))

{
	unsigned int cnt;


	/* Get the number of points. */
	cnt = *(unsigned int *) bufr->get(bufr);
	fprintf(stderr, "Forensics size: %u\n", cnt);


	/* Output each point. */
	while ( cnt-- ) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		fprintf(stdout, "%s\n", bufr->get(bufr));
	}

	bufr->reset(bufr);


 done:
	return;
}


/**
 * Private function.
 *
 * This function is responsible for verifying that the entered
 * command is consistent with the set of accepted actions for
 * the security co-processor and then transmits the command to
 * the processor with subsequent generation of the output if
 * needed.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the event was successful.  A
 *			false value indicates a failure in event
 *			processing while a true value indicates that
 *			event processing has succeeded.
 */

static _Bool process_command(CO(TTYduct, duct), CO(Buffer, bufr))

{
	_Bool retn = false;

	char *bp;

	int cmd;

	struct sancho_cmd_definition *cp;


	/* Locate the event type. */
	bp = (char *) bufr->get(bufr);

	for (cp= Sancho_cmd_list; cp->syntax != NULL; ++cp) {
		if ( strncmp(cp->syntax, bp, strlen(cp->syntax)) == 0 ) {
			cmd = cp->command;
			break;
		}
	}

	if ( cp->syntax == NULL ) {
		fprintf(stdout, "Unknown event: %s\n", bufr->get(bufr));
		goto done;
	}


	/* Dispatch the event. */
	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("Error sending command.\n", stderr);
		goto done;
	}

#if 1
	if ( Sealed ) {
		fputs("Sealed, dropping to terminal.\n", stdout);
		fflush(stdout);
		duct->terminal(duct);
	}
#endif

	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("Error receiving command.\n", stderr);
		goto done;
	}

	fputs("Sancho says:\n", stdout);

	switch ( cmd ) {
		case exchange_event:
		case aggregate_event:
		case seal_event:
		case TE_event:
		case enable_cell:
			fprintf(stdout, "%s\n", bufr->get(bufr));
			break;

		case show_state:
		case show_measurement:
			bufr->print(bufr);
			bufr->reset(bufr);
			break;

		case show_trajectory:
			receive_trajectory(duct, bufr);
			break;

		case show_forensics:
			receive_forensics(duct, bufr);
			break;

		case show_points:
			receive_points(duct, bufr);
			break;

		case show_events:
			receive_events(duct, bufr);
			break;

		default:
			fprintf(stdout, "Unknown event: %s\n", \
				bufr->get(bufr));
			break;
	}


 done:
	return retn;
}



/*
 * Program entry point.
 */

extern int main(int argc, char *argv[])

{
	_Bool timing = false;

	char *p,
	     inbufr[1024],
	     *device = "/dev/ttyACM0";

	int retn;

	double start,
	       end;

	TTYduct duct = NULL;

	Buffer bufr = NULL;


        /* Get operational mode. */
        while ( (retn = getopt(argc, argv, "tc:")) != EOF )
                switch ( retn ) {
			case 't':
				timing = true;
				break;

			case 'c':
				device = optarg;
				break;
		}

	if ( device == NULL ) {
		fputs("No device specified.\n", stderr);
		return 1;
	}


	/* Connect to the specified device and initialize communications. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, TTYduct, duct, ERR(goto done));
	if ( !duct->init_device(duct, device) )
		ERR(goto done);


	/* Get command input and process the command. */
	while ( true ) {
		memset(inbufr, '\0', sizeof(inbufr));
		fputs("sancho>", stdout);
		fflush(stdout);

		if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL )
			goto done;
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';
		if ( !bufr->add(bufr, (unsigned char *) inbufr, \
				strlen(inbufr) + 1) )
			ERR(goto done);
#if 0
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);

		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) ) {
			fputs("Error receiving command.\n", stderr);
			goto done;
		}

		fputs("Sancho says:\n", stdout);
		fprintf(stdout, "%s\n", bufr->get(bufr));
		bufr->reset(bufr);
#else

		if ( timing )
			start = wall_time();

		process_command(duct, bufr);

		if ( timing ) {
			end = wall_time();
			fprintf(stdout, "start=%.1f, end=%1.f, time=%.1f\n", \
				start, end, end - start);
		}

		bufr->reset(bufr);
#endif
	}


 done:
	WHACK(duct);
	WHACK(bufr);

	return 0;
}
