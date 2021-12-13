
/** \file
 *
 * This file implements a utility for managing a quixote co-processor
 * implement.  It connects to the quixote management process through
 * UNIX domain sockets created in the following locations:
 *
 * /var/lib/Quixote/mgmt/cartridges
 *
 * /var/lib/Quixote/mgmt/processes
 *
 * Depending on whether the security domain is running in cartridge or
 * process mode.
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

#include "quixote.h"
#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "LocalDuct.h"


/**
 * The following enumeration type specifies whether or not the utility
 * is running in one shot mode where the command to be processed is
 * specified by a command-line argument.
 */
enum Oneshot_mode {
	oneshot_none,
	oneshot_state,
	oneshot_trajectory,
	oneshot_forensics,
	oneshot_points,
	oneshot_events,
	oneshot_map
};

/**
 * The following enumeration type specifies whether or not
 * the measurements are being managed internally or by an SGX enclave.
 */
 enum {
	 show_mode,
	 process_mode,
	 cartridge_mode,
} Mode = show_mode;

/**
 * The following variable is used to indicate whether or not output
 * is being directed to a tty or a pipe.
 */
static _Bool TTY_output = false;


/**
 * Private function.
 *
 * This function implements show mode for quixote.  This mode displays
 * the set of security domains that are current active.
 *
 * \param root	A pointer to a null terminated buffer containing the
 *		root directory of the domain to be displayed.
 *
 * \return	No return value is defined.
 */

static void show_domains(const char *root)

{
	char *p;

	int rc;

	uint16_t lp;

	glob_t domains;

	String str = NULL;


	/* Generate the list of cartridges. */
	INIT(HurdLib, String, str, ERR(goto done));
	str->add(str, root);
	if ( !str->add(str, "/*") )
		ERR(goto done);

	rc = glob(str->get(str), 0, NULL, &domains);
	if ( rc == GLOB_NOMATCH ) {
		fputs("\tNo domains found.\n", stderr);
		goto done;
	}

	if ( rc != 0 ) {
		fprintf(stderr, "Failed read of domain directory %s, " \
			"code = %d\n", root, rc);
		goto done;
	}


	/* Iterate through and print the cartridges found .*/
	for (lp= 0; lp < domains.gl_pathc; ++lp) {
		str->reset(str);
		if ( !str->add(str, domains.gl_pathv[lp]) ) {
			fputs("Error processing domain list\n", stderr);
			goto done;
		}

		p = str->get(str);
		if ( (p = strrchr(str->get(str), '/')) == NULL )
			p = str->get(str);
		else
			++p;
		fprintf(stdout, "\t%s\n", p);
	}


 done:
	globfree(&domains);
	WHACK(str);

        return;
}


/**
 * Private function.
 *
 * This function sets up the UNIX domain management socket.
 *
 * \param mgmt		The object that will be used to handle management
 *			requests.
 *
 * \param pidstr	A null terminated string containing the number
 *			of the process id to be managed.
 *
 * \param cartridge	A null terminated string containing the name of
 *			the cartridge process to be managed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not setup of the management socket was
 *			successful.  A true value indicates the setup
 *			was successful while a false value indicates the
 *			setup failed.
 */

static _Bool setup_management(CO(LocalDuct, mgmt), const char *pidstr, \
			      const char *cartridge)

{
	_Bool retn = false;

	char pid[11];

	String sockpath = NULL;


	/* Initialize socket client mode. */
	if ( !mgmt->init_client(mgmt) ) {
		fputs("Cannot initialize management client mode.\n", stderr);
		goto done;
	}

	/* Create the appropriate path to the socket location. */
	INIT(HurdLib, String, sockpath, ERR(goto done));

	switch ( Mode ) {
		case show_mode:
			break;

		case process_mode:
			sockpath->add(sockpath, QUIXOTE_PROCESS_MGMT_DIR);
			if ( snprintf(pid, sizeof(pid), "/pid-%s", \
				      pidstr) >=  sizeof(pid) )
				ERR(goto done);
			if ( !sockpath->add(sockpath, pid) )
				ERR(goto done);
			break;

		case cartridge_mode:
			sockpath->add(sockpath, QUIXOTE_CARTRIDGE_MGMT_DIR);
			sockpath->add(sockpath, "/");
			if ( !sockpath->add(sockpath, cartridge) )
				ERR(goto done);
			break;
	}


	/* Create socket in designated path. */
	if ( !mgmt->init_port(mgmt, sockpath->get(sockpath)) ) {
		fprintf(stderr, "Cannot initialize socket: %s\n", \
			sockpath->get(sockpath));
		goto done;
	}

	retn = true;


 done:
	WHACK(sockpath);

	return retn;
}


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
	if ( TTY_output )
		fprintf(stdout, "Trajectory size: %u\n", cnt);


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
	if ( TTY_output )
		fprintf(stdout, "Forensics size: %u\n", cnt);


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

static _Bool receive_points(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	if ( TTY_output )
		fprintf(stdout, "State size: %u\n", cnt);


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
 * This function implements the receipt of a list of TE events from
 * the cartridge management daemon.  The protocol used is for the
 * management daemon to send the number of events in the TE list
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

static _Bool receive_TE_events(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Get the number of points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);
	if ( TTY_output )
		fprintf(stdout, "TE event size: %u\n", cnt);


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
 * This function implements the receipt and output of a security state
 * map.  The protocol is very simple with the aggregate value being
 * sent followed by each point in the security event namespace.
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

static _Bool receive_map(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	unsigned int cnt;


	/* Receive the aggregate value. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);

	fputs("aggregate ", stdout);
	cmdbufr->print(cmdbufr);


	/* Output the points. */
	cmdbufr->reset(cmdbufr);
	if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	cnt = *(unsigned int *) cmdbufr->get(cmdbufr);


	/* Output each point. */
	while ( cnt ) {
		cmdbufr->reset(cmdbufr);
		if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		fprintf(stdout, "state %s\n", cmdbufr->get(cmdbufr));
		--cnt;
	}
	fputs("seal\n", stdout);

	fputs("end\n", stdout);
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

		case show_points:
			retn = receive_points(mgmt, cmdbufr);
			break;

		case show_events:
			retn = receive_TE_events(mgmt, cmdbufr);
			break;

		case show_map:
			retn = receive_map(mgmt, cmdbufr);
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


/**
 * Private function.
 *
 * This function implements the processing of a quixote command that
 * is specified by a command-line argument.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
 *
 * \param mode		The enumeration type of the command that is to
 *			be run.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the command succeeded.  A
 *			false value indicates the command failed while a
 *			true value indicates the command was successfully
 *			processed.
 */

static _Bool process_oneshot(CO(LocalDuct, mgmt), enum Oneshot_mode mode)

{
	_Bool retn = false;

	char *cmd = 0;


	switch ( mode ) {
		case oneshot_state:
			cmd = Sancho_cmd_list[show_state - 1].syntax;
			break;

		case oneshot_trajectory:
			cmd = Sancho_cmd_list[show_trajectory - 1].syntax;
			break;

		case oneshot_forensics:
			cmd = Sancho_cmd_list[show_forensics - 1].syntax;
			break;

		case oneshot_points:
			cmd = Sancho_cmd_list[show_points - 1].syntax;
			break;

		case oneshot_events:
			cmd = Sancho_cmd_list[show_events - 1].syntax;
			break;

		case oneshot_map:
			cmd = Sancho_cmd_list[show_map - 1].syntax;
			break;

		case oneshot_none:
			break;
	}

	if ( cmd > 0 )
		retn = process_command(mgmt, cmd);


	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool tty_input = isatty(fileno(stdin));

	char *p,
	     *pid	 = NULL,
	     *cartridge	 = NULL,
	     inbufr[1024];

	int opt,
	    retn = 1;

	enum Oneshot_mode oneshot = oneshot_none;

	FILE *idfile = NULL;

	Buffer id_bufr = NULL,
	       cmdbufr = NULL;

	LocalDuct mgmt = NULL;

	File infile = NULL;


	while ( (opt = getopt(argc, argv, "EFMPSTc:p:")) != EOF )
		switch ( opt ) {
			case 'E':
				oneshot = oneshot_events;
				break;
			case 'F':
				oneshot = oneshot_forensics;
				break;
			case 'M':
				oneshot = oneshot_map;
				break;
			case 'P':
				oneshot = oneshot_points;
				break;
			case 'S':
				oneshot = oneshot_state;
				break;
			case 'T':
				oneshot = oneshot_trajectory;
				break;

			case 'c':
				Mode = cartridge_mode;
				cartridge = optarg;
				break;
			case 'p':
				Mode = process_mode;
				pid = optarg;
				break;
		}


	/* Configure for output type. */
	TTY_output = isatty(fileno(stdout));
	if ( TTY_output )
		setlinebuf(stdout);


	/* Handle show mode. */
	if ( (oneshot == oneshot_none) && (Mode == show_mode) ) {
		fprintf(stdout, "%s:\n", QUIXOTE_CARTRIDGE_MGMT_DIR);
		show_domains(QUIXOTE_CARTRIDGE_MGMT_DIR);
		fputs("\n", stdout);
		fprintf(stdout, "%s:\n", QUIXOTE_PROCESS_MGMT_DIR);
		show_domains(QUIXOTE_PROCESS_MGMT_DIR);
		retn = 0;
		goto done;
	}


	/* Verify that a socket type has been specified. */
	if ( (pid == NULL) && (cartridge == NULL) ) {
		fputs("No domain specified.\n", stderr);
		goto done;
	}


	/* Establish management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
	if ( !setup_management(mgmt, pid, cartridge) )
		ERR(goto done);


	/* Handle command-line specified commands. */
	if ( oneshot != oneshot_none ) {
		retn = process_oneshot(mgmt, oneshot);
		goto done;
	}


	/* Command loop. */
	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	while ( 1 ) {
		memset(inbufr, '\0', sizeof(inbufr));

		if ( tty_input ) {
			fputs("Quixote>", stdout);
			fflush(stdout);
		}
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
