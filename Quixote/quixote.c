/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in a kernel disciplined security domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of a software 'cartridge' in a subordinate process.
 *
 * The domain is managed through a UNIX domain socket that is created
 * in one of the the following locations:
 *
 * /var/run/Quixote/cartridges
 *
 * /var/run/Quixote/processes
 *
 * Depending on whether or not a runc based cartridge or a simple
 * process was run by the utility.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#define QUIXOTE_MAGAZINE "/var/lib/Quixote/Magazine"

#define MEASUREMENT_FILE "/sys/kernel/security/integrity/events/measurement"
#define STATE_FILE	 "/sys/kernel/security/integrity/events/state"
#define TRAJECTORY_FILE	 "/sys/kernel/security/integrity/events/trajectory"
#define POINTS_FILE	 "/sys/kernel/security/integrity/events/points"
#define FORENSICS_FILE	 "/sys/kernel/security/integrity/events/forensics"
#define SEAL_FILE	 "/sys/kernel/security/integrity/events/sealed"
#define MAP_FILE	 "/sys/kernel/security/integrity/events/map"

#define READ_SIDE  0
#define WRITE_SIDE 1

#define CLONE_EVENTS 0x00000040

#define CAP_TRUST 38

#define SYS_CONFIG_DOMAIN  436
#define IMA_TE_ENFORCE	   0x8
#define IMA_EVENT_EXTERNAL 0x10

#define SYS_CONFIG_ACTOR  437
#define DISCIPLINE_ACTOR  1
#define RELEASE_ACTOR	  2

#define _GNU_SOURCE


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <sched.h>
#include <glob.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "quixote.h"
#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "SHA256.h"

#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"


/**
 * Variable used to indicate that debugging is enabled and to provide
 * the filehandle to be used for debugging.
 */
static FILE *Debug = NULL;

/**
 * The process id of the cartridge monitor process.
 */
static pid_t Cartridge_pid;


/**
 * The seal status of the domain.  This variable is set by a
 * seal event for the domain.  Updates which are not in the
 * security state will cause disciplining requests to be generated
 * for the process initiating the event.
 */
static _Bool Sealed = false;

/**
 * The following variable holds booleans which describe signals
 * which were received.
 */
struct {
	_Bool sigint;
	_Bool sigterm;
	_Bool sighup;
	_Bool sigquit;
	_Bool stop;

	_Bool sigchild;
} Signals;

/**
 * The following enumeration type specifies whether or not
 * the measurements are being managed internally or by an SGX enclave.
 */
 enum {
	 show_mode,
	 process_mode,
	 cartridge_mode,
} Mode = cartridge_mode;


/**
 * System call wrapper for setting the security state of a process.
 */
static inline int sys_config_actor(pid_t pid, unsigned long flags)
{
	return syscall(SYS_CONFIG_ACTOR, pid, flags);
}

/**
 * System call wrapper for configuring a security event domain.
 */
static inline int sys_config_domain(unsigned char *bufr, size_t cnt, \
				    unsigned long flags)
{
	return syscall(SYS_CONFIG_DOMAIN, bufr, cnt, flags);
}


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
	if ( Debug )
		fprintf(Debug, "%s(%d): signal = %d\n", __func__, getpid(), \
			signal);

	switch ( signal ) {
		case SIGINT:
			Signals.stop = true;
			return;
		case SIGTERM:
			Signals.sigterm = true;
			return;
		case SIGHUP:
			Signals.stop = true;
			return;
		case SIGQUIT:
			Signals.stop = true;
			return;
		case SIGCHLD:
			Signals.sigchild = true;
			return;
	}

	return;
}


/**
 * Private function.
 *
 * This function implements checking for whether or not the cartridge
 * process has terminated.
 *
 * \param cartridge_pid	The pid of the cartridge.
 *
 *
 * \return		A boolean value is used to indicate whether
 *			or not the designed process has exited.  A
 *			false value indicates it has not while a
 *			true value indicates it has.
 */

static _Bool child_exited(const pid_t cartridge)

{
	int status;


	if ( waitpid(cartridge, &status, WNOHANG) != cartridge )
		return false;

	return true;
}


/**
 * Private function.
 *
 * This function sets up the UNIX domain management socket.
 *
 * \param mgmt		The object that will be used to handle management
 *			requests.
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

static _Bool setup_management(CO(LocalDuct, mgmt), const char *cartridge)

{
	_Bool rc,
	      retn = false;

	char pid[11];

	mode_t mask;

	String sockpath = NULL;


	/* Initialize socket server mode. */
	if ( !mgmt->init_server(mgmt) ) {
		fputs("Cannot set management server mode.\n", stderr);
		goto done;
	}


	/* Create the appropriate path to the socket location. */
	INIT(HurdLib, String, sockpath, ERR(goto done));

	switch ( Mode ) {
		case show_mode:
			break;

		case process_mode:
			sockpath->add(sockpath, QUIXOTE_PROCESS_MGMT_DIR);
			if ( snprintf(pid, sizeof(pid), "/pid-%u", \
				      getpid()) >=  sizeof(pid) )
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


	/* Create socket in desginated path. */
	if ( Debug )
		fprintf(Debug, "Opening management socket: %s\n", \
			sockpath->get(sockpath));

	mask = umask(0x2);
	rc = mgmt->init_port(mgmt, sockpath->get(sockpath));
	umask(mask);

	if ( !rc ) {

		fprintf(stderr, "Cannot initialize socket: %s.\n", \
			sockpath->get(sockpath));
		goto done;
	}

	retn = true;


 done:
	WHACK(sockpath);

	return retn;
}


#if 0
/**
 * Private function.
 *
 * This function is responsible for returning a list from the
 * co-processor to a management client.
 *
 * \param mgmt	The socket object used to communicate with
 *		the cartridge management instance.
 *
 * \param bufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_list(CO(TTYduct, duct), CO(LocalDuct, mgmt), \
		       CO(Buffer, bufr), CO(char *, cmd))

{
	_Bool retn = false;

	uint32_t cnt;


	/* Send the specified listing command. */
	bufr->reset(bufr);
	if ( !bufr->add(bufr, (unsigned char *) cmd, strlen(cmd)) )
		ERR(goto done);
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Return the result stream to the client. */
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		ERR(goto done);

	cnt = *(unsigned int *) bufr->get(bufr);
	if ( !mgmt->send_Buffer(mgmt, bufr) )
		ERR(goto done);

	while ( cnt-- > 0 ) {
		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		if ( !mgmt->send_Buffer(mgmt, bufr) )
			ERR(goto done);
	}

	retn = true;

 done:
	return retn;
}
#endif


/**
 * Private function.
 *
 * This function is responsible for returning the current forensics
 * list to the caller.  The protocol used is to send the number of
 * elements in the list followed by each point in the forensics
 * path as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_forensics(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, FORENSICS_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent forensics size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, FORENSICS_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security state
 * points to the caller.  The protocol used is to send the number of
 * elements in the map followed by each state in the model as a hexadecimal
 * ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_points(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, POINTS_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent points size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, POINTS_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security event
 * trajectory list to the caller.  The protocol used is to send the number
 * of elements in the list followed by each point as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
v */

static _Bool send_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t cnt = 0;

	String es = NULL;

	File ef = NULL;


	/*
	 * Compute the number of lines in the trajectory.
	 */
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, ef, ERR(goto done));
	if ( !ef->open_ro(ef, TRAJECTORY_FILE) )
		ERR(goto done);

	while ( ef->read_String(ef, es) ) {
		++cnt;
		es->reset(es);
	}

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent trajectory size: %zu\n", cnt);


	/* Send each trajectory point. */
	ef->reset(ef);
	if ( !ef->open_ro(ef, TRAJECTORY_FILE) )
		ERR(goto done);

	while ( cnt-- ) {
		es->reset(es);
		ef->read_String(ef, es);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (void *) es->get(es), es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(es);
	WHACK(ef);

	return retn;
}


/**
 * Private function.
 *
 * This function writes the directive needed to seal the security
 * domain to the 'sealed' pseudo-file.
 *
 * \param bufr		The object that will be used to hold the value
 *			to be written to the file.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the write to the seal file has been
 *			successfully executed.  A false value indicates
 *			failure while a true value indicates success.
 */

static _Bool seal(CO(Buffer, bufr))

{
	_Bool retn = false;

	File sf = NULL;

	static const unsigned char one[] = "1\n";


	INIT(HurdLib, File, sf, ERR(goto done));
	if ( !sf->open_wo(sf, SEAL_FILE) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, one, sizeof(one) - 1);

	if ( !sf->write_Buffer(sf, bufr) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(sf);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for sealing a security domain.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to seal the
 *			buffer and return the status information.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool seal_domain(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	static const unsigned char ok[] = "OK";


	/* Seal the domain. */
	cmdbufr->reset(cmdbufr);
	if ( !seal(cmdbufr) )
		ERR(goto done);

	/* Send response to caller. */
	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, ok, sizeof(ok));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the processing of a management command from
 * the quixote-console utility.
 *
 * \param mgmt		The socket object used to communicate with
 *			the security domain management instance.
 *
 * \param cmdbufr	The object containing the command to be
 *			processed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool process_command(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	char *cmd;

	int *cp;

	String estr = NULL;

	File efile = NULL;


	/* Validate management command. */
	if ( cmdbufr->size(cmdbufr) != sizeof(int) )
		ERR(goto done);

	cp = (int *) cmdbufr->get(cmdbufr);
	if ( (*cp < 1) || (*cp > sancho_cmds_max) )
		ERR(goto done);
	cmd = Sancho_cmd_list[*cp - 1].syntax;

	if ( Debug )
		fprintf(Debug, "%u: Processing management cmd: %s\n", \
			getpid(), cmd);


	/* Process management command. */
	INIT(HurdLib, String, estr, ERR(goto done));
	INIT(HurdLib, File, efile, ERR(goto done));

	switch ( *cp ) {
		case show_measurement:
			cmdbufr->reset(cmdbufr);
			if ( !efile->open_ro(efile, MEASUREMENT_FILE) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			retn = true;
			break;

		case show_state:
			cmdbufr->reset(cmdbufr);
			if ( !efile->open_ro(efile, STATE_FILE) )
				ERR(goto done);
			if ( !efile->read_String(efile, estr) )
				ERR(goto done);
			if ( !cmdbufr->add_hexstring(cmdbufr, \
						     estr->get(estr)) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			retn = true;
			break;

		case show_trajectory:
			retn = send_trajectory(mgmt, cmdbufr);
			break;

		case show_forensics:
			retn = send_forensics(mgmt, cmdbufr);
			break;

		case show_points:
			retn = send_points(mgmt, cmdbufr);
			break;

		case seal_event:
			retn = seal_domain(mgmt, cmdbufr);
			break;
	}


 done:
	WHACK(estr);
	WHACK(efile);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of a state value to the
 * current security model.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the hexadecimally encoded state value.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the state value succeeded.  A
 *			false value indicates the addition of the
 *			state failed while a true value indicates
 *			the state injection had succeeded.
 */

static _Bool add_state(CO(char *, inbufr))

{
	_Bool retn = false;

	Buffer bufr = NULL;

	File sf = NULL;


	/* Sanity check buffer. */
	if ( Debug )
		fprintf(Debug, "adding state: %s\n", inbufr);
	if ( strlen(inbufr) != (NAAAIM_IDSIZE * 2) )
		ERR(goto done);


	/* Write the hexadecimal point value to the pseudo-file. */
	INIT(HurdLib, File, sf, ERR(goto done));
	if ( !sf->open_wo(sf, MAP_FILE) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (void *) inbufr, NAAAIM_IDSIZE * 2);
	bufr->add(bufr, (void *) "\n", 1);

	if ( !sf->write_Buffer(sf, bufr) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sf);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for processing security domain definitions
 * that are to be programed into a kernel disciplined namespace.
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

static _Bool process_event(const char *event)

{
	_Bool retn = false;

	const char *event_arg;

	struct sancho_cmd_definition *cp;

	Buffer bufr = NULL;


	/* Locate the event type. */
	for (cp= Sancho_cmd_list; cp->syntax != NULL; ++cp) {
		if ( strncmp(cp->syntax, event, strlen(cp->syntax)) == 0 )
			break;
	}

	if ( cp->syntax == NULL ) {
		fprintf(stderr, "Unknown event: %s\n", event);
		goto done;
	}

	event_arg = event + strlen(cp->syntax);
	INIT(HurdLib, Buffer, bufr, ERR(goto done));


	/* Dispatch the event. */
	switch ( cp->command ) {
		case aggregate_event:
			retn = true;
			break;

		case sancho_state:
			retn = add_state(event_arg);
			break;

		case seal_event:
			if ( !seal(bufr) )
				ERR(goto done);
			if ( Debug )
				fputs("Sealed domain.\n", Debug);

			retn   = true;
			Sealed = true;
			break;

		default:
			fprintf(stderr, "Unknown event: %s\n", event);
			break;
	}


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the initialization of a behavioral map
 * for the cartridge being executed.
 *
 * \param mapfile	The name of the file containing the behavioral
 *			model.  The model is expected to consist of
 *			model events.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool initialize_state(FILE *mapfile)

{
	_Bool retn = false;

	char *p,
	     inbufr[256];


	/* Loop over the mapfile and process directives. */
	while ( fgets(inbufr, sizeof(inbufr), mapfile) != NULL ) {
		if ( (p = strchr(inbufr, '\n')) != 0 )
			*p = '\0';

		if ( Debug )
			fprintf(Debug, "Initialize: %s\n", inbufr);

		if ( !process_event(inbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function sets up a namespace and returns a file descriptor
 * to the caller which references the namespace specific /sysfs
 * measurement file.
 *
 * \param fdptr		A pointer to the variable which will hold the
 *			file descriptor for the cartridge measurement
 *			file.
 *
 * \param enforce	A flag variable used to indicate whether or not
 *			the security domain should be placed in
 *			enforcement mode.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the the creation of the namespace was
 *			successful.  A false value indicates setup of
 *			the namespace was unsuccessful while a true
 *			value indicates the namespace is setup and
 *			ready to be measured.
 */

static _Bool setup_namespace(_Bool enforce)

{
	_Bool retn = false;


	/* Create an independent and sealed security event domain. */
	if ( unshare(CLONE_EVENTS) < 0 )
		ERR(goto done);

	if ( enforce ) {
		if ( sys_config_domain(NULL, 0, IMA_TE_ENFORCE) < 0 )
			ERR(goto done);
	}


	/* Drop the ability to modify the security domain. */
	if ( cap_drop_bound(CAP_TRUST) != 0 )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements Quixote show mode.  This mode displays the
 * set of software security cartridges that are currently deployed
 * on the host.
 *
 * \param root	A pointer to the buffer containing the magazine root
 *		directory.
 *
 * \return	No return value is defined.
 */

static void show_magazine(CO(char *, root))

{
	char *p;

	int retn = 1;

	uint16_t lp;

	glob_t cartridges;

	String str = NULL;


	/* Generate the list of cartridges. */
	INIT(HurdLib, String, str, ERR(goto done));
	str->add(str, root);
	if ( !str->add(str, "/*") )
		ERR(goto done);

	if ( glob(str->get(str), 0, NULL, &cartridges) != 0 ) {
		fprintf(stderr, "Failed read of cartridge directory: %s\n", \
			root);
		goto done;
	}
	if ( cartridges.gl_pathc == 0 ) {
		fputs("No cartridges found:\n", stderr);
		goto done;
	}


	/* Iterate through and print the cartridges found .*/
	fprintf(stdout, "%s:\n", root);
	for (lp= 0; lp < cartridges.gl_pathc; ++lp) {
		str->reset(str);
		if ( !str->add(str, cartridges.gl_pathv[lp]) ) {
			fputs("Error processing cartridge list\n", stderr);
			goto done;
		}

		p = str->get(str);
		if ( (p = strrchr(str->get(str), '/')) == NULL )
			p = str->get(str);
		else
			++p;
		fprintf(stdout, "\t%s\n", p);
	}

	retn = 0;


 done:
	globfree(&cartridges);
	WHACK(str);

	exit(retn);
}


/**
 * Private function.
 *
 * This function is responsible for launching a software cartridge
 * in an independent measurement domain.  A pipe is established
 * between the parent process and the child that is used to return
 * the namespace specific events for injection into the security
 * co-processor.
 *
 * \param root		A pointer to the buffer containing the root
 *			directory to be used to display the cartridges.
 *
 * \param map		A pointer to the file descriptor that contains
 *			security state directives to be loaded into
 *			the domain.  This value will be null if a
 *			state map has not been specified.
 *
 * \param mgmt_read	A file descriptor to the read end of the pipe
 *			from which management commands will be received.
 *
 * \param mgmt_write	The file descriptor to the write end of the pipe
 *			over which the results of the management command
 *			will be sent.
 *
 * \param enforce	A flag used to indicate whether or not the
 *			security domain should be placed in enforcement
 *			mode.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the launch.  A false value indicates an error was
 *		encountered while a true value indicates the cartridge
 *		was successfully launched.
 */

static _Bool fire_cartridge(CO(char *, cartridge), FILE *map, int *endpoint, \
			    _Bool enforce)

{
	_Bool retn = false;

	char *bundle = NULL;

	String cartridge_dir = NULL;


	/* Create the name of the bundle directory if in cartridge mode . */
	if ( Mode == cartridge_mode ) {
		INIT(HurdLib, String, cartridge_dir, ERR(goto done));
		cartridge_dir->add(cartridge_dir, QUIXOTE_MAGAZINE);
		cartridge_dir->add(cartridge_dir, "/");
		if ( !cartridge_dir->add(cartridge_dir, cartridge) )
			ERR(goto done);
		bundle = cartridge_dir->get(cartridge_dir);
	}


	/* Create a subordinate cartridge process. */
	if ( !setup_namespace(enforce) )
		exit(1);

	if ( Debug )
		fprintf(Debug, "Monitor process: %d\n", getpid());


	/* Load the state map if one has been specified. */
	if ( map != NULL ) {
		if ( !initialize_state(map) )
			ERR(goto done);
	}


	/* Fork again to run the cartridge. */
	Cartridge_pid = fork();
	if ( Cartridge_pid == -1 )
		exit(1);

	/* Child process - run the cartridge. */
	if ( Cartridge_pid == 0 ) {
		if ( Mode == cartridge_mode ) {
			execlp("runc", "runc", "run", "-b", bundle, \
			       cartridge, NULL);
			fputs("Cartridge execution failed.\n", stderr);
			exit(1);
		}

		if ( Mode == process_mode ) {
			if ( geteuid() != getuid() ) {
				if ( Debug )
					fprintf(Debug, "Changing to real " \
						"id: \%u\n",  getuid());
				if ( setuid(getuid()) != 0 ) {
					fputs("Cannot change uid.\n", stderr);
					exit(1);
				}
			}

			if ( Debug )
				fputs("Executing cartridge process.\n", Debug);
			execlp("bash", "bash", "-i", NULL);
			fputs("Cartridge process execution failed.\n", stderr);
			exit(1);
		}
	}


	/* Parent process - return and monitor child. */
	retn = true;


 done:
	WHACK(cartridge_dir);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for issueing the runc command needed
 * to terminate a software cartridge.  The function waits until the
 * process spawned to execute the runc process terminates.
 *
 * \param name		A pointer to a character buffer containing the
 *			name of the software cartridge.
 *
 * \param wait		A boolean flag used to indicate whether or
 *			not the runc kill process should be waited for.
 *
 * \return	No return value is defined.
 */

static void kill_cartridge(const char *cartridge, const _Bool wait)

{
	int status;

	static pid_t kill_process = 0;


	/* Signal the monitor process to shutdown the cartridge process. */
	if ( Mode == process_mode ) {
		if ( Debug )
			fprintf(Debug, "%u sending SIGHUP to %u.\n", \
				getpid(), Cartridge_pid);
		kill(Cartridge_pid, SIGTERM);
		return;
	}


	/* Check to see if runc kill has finished. */
	if ( kill_process ) {
		waitpid(kill_process, &status, WNOHANG);
		if ( !WIFEXITED(status) )
			return;

		if ( Debug )
			fprintf(Debug, "Cartridge kill status: %d\n", \
				WEXITSTATUS(status));
		if ( WEXITSTATUS(status) == 0 ) {
			kill_process = 0;
			return;
		}
	}


	/* Fork a process to use runc to send the termination signal. */
	kill_process = fork();
	if ( kill_process == -1 )
		return;

	/* Child process - execute runc in kill mode. */
	if ( kill_process == 0 ) {
		if ( Debug )
			fputs("Killing runc cartridge.\n", Debug);
		execlp("runc", "runc", "kill", cartridge, "SIGKILL", \
		       NULL);
		exit(1);
	}

	/* Parent process - wait for the kill process to complete. */
	if ( wait )
		waitpid(kill_process, &status, 0);

	return;
}



/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool enforce	= false,
	      connected = false;

	char *debug	= NULL,
	     *map	= NULL,
	     *cartridge	= NULL;

	int opt,
	    fd	 = 0,
	    retn = 1;

	struct pollfd poll_data[1];

	struct sigaction signal_action;

	Buffer cmdbufr = NULL;

	LocalDuct mgmt = NULL;

	File infile = NULL;

	FILE *state = NULL;


	while ( (opt = getopt(argc, argv, "CPSec:d:m:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = cartridge_mode;
				break;
			case 'P':
				Mode = process_mode;
				break;
			case 'S':
				Mode = show_mode;
				break;
			case 'e':
				enforce = true;
				break;

			case 'c':
				cartridge = optarg;
				break;
			case 'd':
				debug = optarg;
				break;
			case 'm':
				map = optarg;
				break;
		}


	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( (Mode == cartridge_mode) && (cartridge == NULL) ) {
		fputs("No software cartridge specified.\n", stderr);
		goto done;
	}


	/* Handle a debug invocation. */
	if ( debug ) {
		if ( (Debug = fopen(debug, "w+")) == NULL ) {
			fputs("Cannot open debug file.\n", stderr);
			goto done;
		}
		setlinebuf(Debug);
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
	if ( sigaction(SIGSEGV, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGFPE, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGILL, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGBUS, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTRAP, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGCHLD, &signal_action, NULL) == -1 )
		goto done;


	/* Load and seal a behavior map if specified. */
	if ( map != NULL ) {
		if ( (state = fopen(map, "r")) == NULL )
			ERR(goto done);
		if ( Debug )
			fprintf(Debug, "Opened state map: %s\n", map);
	}


	/* Setup the management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
	if ( !setup_management(mgmt, cartridge) )
		ERR(goto done);


	/* Launch the software cartridge. */
	if ( Debug )
		fprintf(Debug, "Primary process: %d\n", getpid());

	if ( !fire_cartridge(cartridge, state, &fd, enforce) )
		ERR(goto done);

	if ( !mgmt->get_socket(mgmt, &poll_data[0].fd) ) {
		fputs("Error setting up polling data.\n", stderr);
		goto done;
	}
	poll_data[0].events = POLLIN;


	/* Dispatch loop. */
	if ( Debug ) {
		fprintf(Debug, "%d: Calling event loop\n", getpid());
		fprintf(Debug, "descriptor 1: %d,\n", poll_data[0].fd);
	}

	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	opt = 0;
	while ( 1 ) {
		if ( Debug )
			fprintf(Debug, "\n%d: Poll cycle: %d\n", getpid(), \
				++opt);

		retn = poll(poll_data, 1, -1);
		if ( retn < 0 ) {
			if ( Signals.stop || Signals.sigterm ) {
				if ( Debug )
					fputs("Quixote terminated.\n", Debug);
				kill_cartridge(cartridge, true);
				goto done;
			}
			if ( Signals.sigchild ) {
				if ( !child_exited(Cartridge_pid) )
					continue;
				fputs("Cartridge process terminated.\n", \
				      stdout);
				goto done;
			}
		}

		if ( Debug )
			fprintf(Debug, "Events: %d, Mgmt poll=%0x\n", retn, \
				poll_data[0].revents);

		if ( poll_data[0].revents & POLLIN ) {
			if ( !connected ) {
				if ( Debug )
					fputs("Have socket connection.\n", \
					      Debug);

				if ( !mgmt->accept_connection(mgmt) )
					ERR(goto done);
				if ( !mgmt->get_fd(mgmt, &poll_data[0].fd) )
					ERR(goto done);
				connected = true;
				continue;
			}
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				continue;
			if ( mgmt->eof(mgmt) ) {
				if ( Debug )
					fputs("Terminating management.\n", \
					      Debug);
				mgmt->reset(mgmt);
				if ( !mgmt->get_socket(mgmt, \
						       &poll_data[0].fd) )
					ERR(goto done);
				connected = false;
				continue;
			}

			if ( !process_command(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->reset(cmdbufr);
		}
	}


 done:
	WHACK(cmdbufr);
	WHACK(mgmt);
	WHACK(infile);

	if ( fd > 0 )
		close(fd);

	return retn;
}
