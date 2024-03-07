/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in an independent hardware security domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of a software 'cartridge' in a subordinate process.  The parent
 * process monitors the following file:
 *
 * /sys/kernel/security/tsem/ExternalTMA/NNNNNNNNNN
 *
 * Where NNNNNNNNNN is the id number of the security event modeling
 * namespace.
 *
 * The security model state change events are transmitted to a
 * hardware based Sancho Trusted Modeling Agent.  Based on feedback
 * from the co-processor the process eliciting the event is woken with
 * its bad actor status bit set or cleraed.  This security status bit
 * is interrogated by the TSEM linux security module that can then
 * interdict security sensitive events.
 *
 * The domain is managed through a UNIX domain socket that is created
 * in one of the the following locations:
 *
 * /var/lib/Quixote/mgmt/cartridges
 *
 * /var/lib/Quixote/mgmt/processes
 *
 * Depending on whether or not a runc based cartridge or a simple
 * process was run by the utility.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#define READ_SIDE  0
#define WRITE_SIDE 1

#define _GNU_SOURCE

#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


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

#include <TSEMcontrol.h>
#include <TSEMevent.h>

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "SecurityPoint.h"
#include "SecurityEvent.h"


/**
 * The object used to communicate with the SanchoMCU implementation.
 */
static TTYduct Sancho = NULL;

/**
 * The control object for the model.
 */
static TSEMcontrol Control = NULL;

/**
 * Variable used to indicate that debugging is enabled and to provide
 * the filehandle to be used for debugging.
 */
static FILE *Debug = NULL;

/**
 * The process id of the cartridge monitor process.
 */
static pid_t Monitor_pid;

/**
 * The process id of the workload process.
 */
static pid_t Workload_pid;

/**
 * This variable is used to signal that a modeling error has occurred
 * and signals the disciplining code to unilaterally release a process
 * rather then model is status in the security domain.
 */
static _Bool Model_Error = false;

/**
 * This object holds the aggregate value that was injected into the
 * Sancho instance.
 */
static Buffer Aggregate = NULL;

/**
 * This variable is used to indicate that an execution trajectory
 * should be generated.
 */
static _Bool Trajectory = false;

/**
 * This variable is used to control whether the security event
 * descriptions are to reference the initial user namespace or
 * the current user namespace that the process is running in.
 */
static _Bool Current_Namespace = false;

/**
 * The name of the hash function to be used for the namespace.
 */
static char *Digest = NULL;

/**
 * A string defining the size of the atomic magazine to be
 * allocated for a namespace.
 */
static unsigned long Magazine_Size = 0;

/*
 * The object that will be used for parsing the TSEM events.
 */
static TSEMevent Event = NULL;

/**
 * The name of the runc workload.
 */
static const char *Runc_name = NULL;

/**
 * A flag to indicate whether or not the security model is to
 * be enforced.
 */
static _Bool Enforce = false;

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
 * The following enumeration type specifies the mode the utility is
 * be running in.
 */
enum {
	show_mode,
	process_mode,
	cartridge_mode,
} Mode = cartridge_mode;


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

		case SIGSEGV:
			if ( Workload_pid != 0 ) {
				if ( Debug )
					fprintf(Debug, "%u Killing workload " \
						"%u.\n", getpid(),	      \
						Workload_pid);
				kill(Workload_pid, SIGSEGV);
			} else {
				if ( Debug )
					fprintf(Debug, "%u no workload to "
						"kill.\n", getpid());
			}

			if ( Monitor_pid == 0 )
				_exit(1);
			if ( Debug )
				fprintf(Debug, "%u: Killing monitor %u.\n", \
					getpid(), Monitor_pid);
			kill(Monitor_pid, SIGSEGV);

			fputs("Orchestrator segmentation fault.\n", stderr);
			_exit(1);
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
 * This function is responsible for issueing the runc command needed
 * to terminate a software cartridge.  The function waits until the
 * process spawned to execute the runc process terminates.
 *
 * \param wait		A boolean flag used to indicate whether or
 *			not the runc kill process should be waited for.
 *
 * \return	No return value is defined.
 */

static void kill_cartridge(const _Bool wait)

{
	int status;

	static pid_t kill_process = 0;


	/* Signal the monitor process to shutdown the cartridge process. */
	if ( Mode == process_mode ) {
		if ( Debug )
			fprintf(Debug, "%u sending SIGHUP to %u.\n", \
				getpid(), Monitor_pid);
		kill(Monitor_pid, SIGTERM);
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

		execlp("runc", "runc", "kill", Runc_name, "SIGKILL", NULL);
		exit(1);
	}

	/* Parent process - wait for the kill process to complete. */
	if ( wait )
		waitpid(kill_process, &status, 0);

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
			sockpath->add_sprintf(sockpath, "%s/pid-", \
					      QUIXOTE_PROCESS_MGMT_DIR);
			if ( cartridge != NULL ) {
				if ( !sockpath->add(sockpath, cartridge) )
					ERR(goto done);
			} else {
				if ( !sockpath->add_sprintf(sockpath, "%u", \
							    getpid()) )
					ERR(goto done);
			}
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
	mask = umask(mask);

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


/**
 * Private function.
 *
 * This function carries out the addition of the hardware aggregate
 * measurement to the current security state model.
 *
 * \param duct	A pointer to the object used to communicate with
 *		the MCU based TMA.
 *
 * \param str	The object that will be used to extract the string
 *		value from the event.
 *
 * \return	A boolean value is returned to indicate whether or
 *		addition of the aggregate value succeeded.  A false
 *		value indicates the addition failed while a true
 *		value indicates the addition succeeded.
 */

static _Bool add_aggregate(CO(TTYduct, duct), String str)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	static const char *aggregate = "aggregate ";


	/* The aggregate only gets added once. */
	if ( Aggregate != NULL )
		return true;

	str->reset(str);
	if ( !Event->get_text(Event, "value", str) )
		ERR(goto done);

	if ( Debug )
		fprintf(Debug, "aggregate %s\n", str->get(str));


	/* Capture the aggregate locally. */
	INIT(HurdLib, Buffer, Aggregate, ERR(goto done));
	if ( !Aggregate->add_hexstring(Aggregate, str->get(str)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (unsigned char *) aggregate, strlen(aggregate));
	if ( !bufr->add(bufr, (void *) str->get(str), str->size(str) + 1) )
		ERR(goto done);

	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("Error sending command.\n", stderr);
		goto done;
	}

	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("Error receiving command.\n", stderr);
		goto done;
	}

	if ( Debug )
		fprintf(Debug, "Sancho says: %s\n", bufr->get(bufr));

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for interpreting the measurement
 * event generated by the kernel.  It does this be iterating over
 * the the defined commands and then switching execution based
 * on the enumeration type of the event.
 *
 * \param event		A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the event was successful.  A
 *			false value indicates a failure in event
 *			processing while a true value indicates that
 *			event processing has succeeded.
 */

static _Bool process_event(CO(TTYduct, duct))

{
	_Bool trusted,
	      retn = false;

	char *bp;

	pid_t pid;

	enum TSEM_export_type event;

	Buffer bufr = NULL;

	String update = NULL;

	SecurityEvent exchange = NULL;

	static const char *export      = "export ",
			  *discipline  = "DISCIPLINE ",
			  *release     = "RELEASE ";


	if ( Debug )
		fprintf(Debug, "%u: Processing event: '%s'\n", getpid(), \
			Event->get_event(Event));

	INIT(HurdLib, String, update, ERR(goto done));
	Event->reset(Event);


	/* Dispatch the event. */
	event = Event->extract_export(Event);

	switch ( event ) {
		case TSEM_EVENT_AGGREGATE:
			retn = add_aggregate(duct, update);
			goto done;

		case TSEM_EVENT_EVENT:
		case TSEM_EVENT_ASYNC_EVENT:
			if ( !Event->extract_event(Event) )
				ERR(goto done);

			update->add(update, export);
			if ( !Event->encode_event(Event, update) )
				ERR(goto done);
			break;

		case TSEM_EVENT_LOG:
			if ( !Event->encode_log(Event, update) )
				ERR(goto done);
			break;

		default:
			fprintf(stderr, "Unknown event: %s\n", \
				Event->get_event(Event));
			break;
	}


	/* Dispatch the event. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) update->get(update), \
			update->size(update) + 1) )
		ERR(goto done);

	if ( Debug )
		fprintf(Debug, "%u: Sending cmd: '%s'\n", getpid(), \
			update->get(update));

	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("Error sending command.\n", stderr);
		goto done;
	}

	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("Error receiving command.\n", stderr);
		goto done;
	}

	if ( Debug )
		fprintf(Debug, "Sancho says: %s\n", bufr->get(bufr));


	/* Check event return, OK if other then a security event. */
	bp = (char *) bufr->get(bufr);

	if ( (event != TSEM_EVENT_EVENT) && \
	     (event != TSEM_EVENT_ASYNC_EVENT) ) {
		if ( strncmp(bp, "OK", 2) == 0 )
			retn = true;
		goto done;
	}


	/*
	 * If this is a model error release the actor so the runc
	 * instance can release the domain.
	 */
	if ( Model_Error ) {
		INIT(NAAAIM, SecurityEvent, exchange, ERR(goto done));
		if ( !exchange->parse(exchange, update) )
			ERR(goto done);
		if ( !exchange->get_pid(exchange, &pid) )
			ERR(goto done);

		if ( Debug )
			fprintf(Debug, "Model error, releasing %u.\n", pid);

		if ( !Control->release(Control, pid) ) {
			fprintf(stderr, "Bad actor release error: "  \
				"%d:%s\n", errno, strerror(errno));
		}
		else
			retn = true;

		goto done;
	}


	/* Verify this is a valid release or discipline event. */
	if ( (strncmp(bp, release, strlen(release)) != 0) && \
	     (strncmp(bp, discipline, strlen(discipline)) != 0) )
		ERR(goto done);
	trusted = strncmp(bp, release, strlen(release)) == 0;

	/* Handle an asynchronous event. */
	if ( event == TSEM_EVENT_ASYNC_EVENT ) {
		if ( trusted ) {
			retn = true;
			goto done;
		}
		if ( Debug )
			fputs("Atomic context security violation.\n", Debug);
		if ( Enforce ) {
			fputs("Security violation in atomic context, "
			      "shutting down workload.\n", stderr);
			kill_cartridge(true);
		}
		retn = true;
		goto done;
	}

	/* Extract the PID from the security event event. */
	if ( (bp = strchr(bp, ' ')) == NULL )
		goto done;

	pid = strtoll(++bp, NULL, 10);
	if ( errno == ERANGE )
		ERR(goto done);

	/* Set the process trust status. */
	bp = (char *) bufr->get(bufr);

	if ( !trusted ) {
		if ( !Control->discipline(Control,pid) ) {
			fprintf(stderr, "Failed discipline: errno=%d, "\
				"error=%s\n", errno, strerror(errno));
		}
		else {
			if ( Debug )
				fprintf(Debug, "Disciplined: %d\n", pid);
		}
		retn = true;
		goto done;
	}

	if ( !Control->release(Control, pid) ) {
		fprintf(stderr, "Failed release: errno=%d, error=%s\n", \
			errno, strerror(errno));
	}
	else {
		if ( Debug )
			fprintf(Debug, "Released: %d\n", pid);
	}
	retn = true;


 done:
	WHACK(bufr);
	WHACK(update);
	WHACK(exchange);

	return retn;
}


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


/**
 * Private function.
 *
 * This function is responsible for returning the current state map
 * from the co-processor to a management client.
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

static _Bool send_map(CO(TTYduct, duct), CO(LocalDuct, mgmt), \
		      CO(Buffer, bufr))

{
	_Bool retn = false;


	/* Send the specified listing command. */
	if ( !mgmt->send_Buffer(mgmt, Aggregate) )
		ERR(goto done);

	retn = true;


	/* Return the point stream to the client. */
	retn = send_list(duct, mgmt, bufr, "show points");


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the processing of a command from the
 * cartridge management utility.  This command comes in the form
 * of a binary encoding of the desired command to be run.
 *
 * \param mgmt		The socket object used to communicate with
 *			the cartridge management instance.
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

static _Bool process_command(CO(TTYduct, duct), CO(LocalDuct, mgmt), \
			     CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	char *cmd;

	int *cp;

	static const char *seal_cmd	   = "seal",
			  *measurement_cmd = "show measurement",
			  *state_cmd	   = "show state",
			  *cellular_cmd	   = "enable cellular";


	if ( cmdbufr->size(cmdbufr) != sizeof(int) )
		ERR(goto done);

	cp = (int *) cmdbufr->get(cmdbufr);
	if ( (*cp < 1) || (*cp > sancho_cmds_max) )
		ERR(goto done);
	cmd = Sancho_cmd_list[*cp - 1].syntax;

	if ( Debug )
		fprintf(Debug, "Processing managment cmd: %s\n", cmd);

	switch ( *cp ) {
		case seal_event:
			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr,		       \
					   (unsigned char *) seal_cmd, \
					   strlen(seal_cmd) + 1) )
			       ERR(goto done);
			if ( !duct->send_Buffer(duct, cmdbufr) )
				ERR(goto done);

			cmdbufr->reset(cmdbufr);
			if ( !duct->receive_Buffer(duct, cmdbufr) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);

			retn = true;
			break;

		case show_measurement:
			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr,			      \
					   (unsigned char *) measurement_cmd, \
					   strlen(measurement_cmd) + 1) )
				ERR(goto done);
			if ( !duct->send_Buffer(duct, cmdbufr) )
				ERR(goto done);

			cmdbufr->reset(cmdbufr);
			if ( !duct->receive_Buffer(duct, cmdbufr) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);

			retn = true;
			break;

		case show_state:
			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr,			\
					   (unsigned char *) state_cmd, \
					   strlen(state_cmd) + 1) )
				ERR(goto done);
			if ( !duct->send_Buffer(duct, cmdbufr) )
				ERR(goto done);

			cmdbufr->reset(cmdbufr);
			if ( !duct->receive_Buffer(duct, cmdbufr) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);

			retn = true;
			break;

		case show_trajectory:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show trajectory");
			break;

		case show_coefficients:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show coefficients");
			break;

		case show_counts:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show counts");
			break;

		case show_forensics:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show forensics");
			break;

		case show_forensics_coefficients:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show forensics_coefficients");
			break;

		case show_forensics_counts:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show forensics_counts");
			break;

		case show_events:
			retn = send_list(duct, mgmt, cmdbufr, \
					 "show events");
			break;

		case show_map:
			retn = send_map(duct, mgmt, cmdbufr);
			break;

		case enable_cell:
			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr,			   \
					   (unsigned char *) cellular_cmd, \
					   strlen(cellular_cmd) + 1) )
			       ERR(goto done);
			if ( !duct->send_Buffer(duct, cmdbufr) )
				ERR(goto done);

			cmdbufr->reset(cmdbufr);
			if ( !duct->receive_Buffer(duct, cmdbufr) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);

			retn = true;
			break;

		case sancho_reset:
			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr, (void *) cmd,
					   strlen(cmd) + 1) )
				ERR(goto done);
			if ( !duct->send_Buffer(duct, cmdbufr) )
				ERR(goto done);

			cmdbufr->reset(cmdbufr);
			if ( !duct->receive_Buffer(duct, cmdbufr) )
				ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);

			retn = true;
			break;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the initialization of a security model from
 * a file.
 *
 * \param duct		The object that will be used to communicate
 *			with the SanchoMCU instance.
 *
 * \param model_file	The name of the file containing the security
 *			processed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool load_model(CO(TTYduct, duct), char *model_file)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	String str = NULL;

	File model = NULL;

	static const char *load_cmd = "load ";


	/* Open the file containing the security map. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, model, ERR(goto done));
	if ( !model->open_ro(model, model_file) )
		ERR(goto done);


	/* Load the security event descriptions into the model. */
	if ( !str->add(str, load_cmd) )
		ERR(goto done);

	while ( model->read_String(model, str) ) {
		if ( Debug )
			fprintf(Debug, "Model entry: %s\n", str->get(str));

		if ( !bufr->add(bufr, (void *) str->get(str), \
				str->size(str) + 1) )
			ERR(goto done);
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);

		bufr->reset(bufr);
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);
		if ( Debug )
			fprintf(Debug, "Sancho says: %s\n", bufr->get(bufr));

		if ( strncmp((char *) bufr->get(bufr), "OK", 2) != 0 )
			ERR(goto done);

		str->reset(str);
		if ( !str->add(str, load_cmd) )
			ERR(goto done);
		bufr->reset(bufr);
	}

	retn = true;


 done:
	WHACK(bufr);
	WHACK(str);
	WHACK(model);

	return retn;
}


/**
 * Private function.
 *
 * This is a helper function that adds a hexadecimally encoded state
 * point to a String object.
 *
 * \param str	The object that is to have the buffer encoded.
 *
 * \param bufr	A pointer to the buffer whose contents is to be
 *		encoded into the String object.
 *
 * \param cnt	The number of bytes to encode from the buffer.
 *
 * \return	No return value is defined.
 */

static void _encode_buffer(CO(String, str), unsigned char *bufr, \
			   const size_t size)

{
	unsigned char *p = bufr;

	unsigned int lp;


	for (lp= 0; lp < size; ++lp) {
		str->add_sprintf(str, "%02x", *p);
		++p;
	}

	return;
}


/**
 * Private function.
 *
 * This function implements the output of a security execution trajectory.
 *
 * \param fname		The name of the file that the security trajectrory
 *			will be written to.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the trajectory was output.  A false value
 *			indicates output failed while a true value
 *			indicates the trajectory was successfully output.
 */

static _Bool output_trajectory(CO(char *, fname))

{
	_Bool retn = false;

	size_t lp;

	uint32_t cnt = 0;

	Buffer es   = NULL,
	       bufr = NULL;

	File outfile = NULL;

	static const char *cmd = "show trajectory";


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, Buffer, es, ERR(goto done));

	INIT(HurdLib, File, outfile, ERR(goto done));
	if ( !outfile->open_rw(outfile, fname) )
		ERR(goto done);

	/* Send the command to show the trajectory. */
	if ( !bufr->add(bufr, (unsigned char *) cmd, strlen(cmd)) )
		ERR(goto done);
	if ( !Sancho->send_Buffer(Sancho, bufr) )
		ERR(goto done);

	/* Output each trajectory point. */
	bufr->reset(bufr);
	if ( !Sancho->receive_Buffer(Sancho, bufr) )
		ERR(goto done);
	cnt = *(unsigned int *) bufr->get(bufr);

	for (lp= 0; lp < cnt; ++lp ) {
		es->reset(es);
		if ( !Sancho->receive_Buffer(Sancho, es) )
			ERR(goto done);

		bufr->reset(bufr);
		bufr->add(bufr, es->get(es), es->size(es));
		bufr->add(bufr, (void *) "\n", 1);
		if ( !outfile->write_Buffer(outfile, bufr) )
			ERR(goto done);
		es->reset(es);
	}

	retn = true;

 done:
	WHACK(bufr);
	WHACK(es);
	WHACK(outfile);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the output of a security model.
 *
 * \param fname		The name of the file that the security model
 *			will be written to.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the model was output.  A false value
 *			indicates output failed while a true value
 *			indicates the model was successfully output.
 */

static _Bool output_model(CO(char *, fname))

{
	_Bool retn = false;

	uint32_t lp,
		 cnt = 0;

	Buffer bufr = NULL;

	String str = NULL;

	File outfile = NULL;

	static const char *cmd 		 = "show coefficients",
			  *aggregate_cmd = "aggregate ",
			  *state_cmd	 = "state ",
			  *seal_cmd	 = "seal\n",
			  *end_cmd	 = "end\n";


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, outfile, ERR(goto done));
	if ( !outfile->open_rw(outfile, fname) )
		ERR(goto done);


	/* Output the aggregate value. */
	if ( !str->add(str, aggregate_cmd) )
		ERR(goto done);
	_encode_buffer(str, Aggregate->get(Aggregate), \
		       Aggregate->size(Aggregate));
	if ( !str->add(str, "\n") )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);

	/* Send the command to show the security event points. */
	if ( !bufr->add(bufr, (unsigned char *) cmd, strlen(cmd)) )
		ERR(goto done);
	if ( !Sancho->send_Buffer(Sancho, bufr) )
		ERR(goto done);

	/* Output each security event point. */
	bufr->reset(bufr);
	if ( !Sancho->receive_Buffer(Sancho, bufr) )
		ERR(goto done);
	cnt = *(unsigned int *) bufr->get(bufr);

	for (lp= 0; lp < cnt; ++lp ) {
		bufr->reset(bufr);
		if ( !Sancho->receive_Buffer(Sancho, bufr) )
			ERR(goto done);

		str->reset(str);
		str->add(str, state_cmd);
		str->add(str, (char *) bufr->get(bufr));
		if ( !str->add(str, "\n") )
			ERR(goto done);

		if ( !outfile->write_String(outfile, str) )
			ERR(goto done);
	}

	/* Output the closing tags. */
	str->reset(str);
	if ( !str->add(str, seal_cmd) )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);

	str->reset(str);
	if ( !str->add(str, end_cmd) )
		ERR(goto done);
	if ( !outfile->write_String(outfile, str) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(str);
	WHACK(outfile);

	return retn;
}


/**
 * Private function.
 *
 * This function creates an independent security event domain that
 * is modeled by a userspace Trusted Modeling Agent implementation.
 *
 * \param fdptr		A pointer to the variable that will hold the
 *			file descriptor of the pseudo-file that will
 *			emit model events for the domain.
 *
 * \param enforce	A flag variable used to indicate whether or not
 *			the security model should be placed in
 *			enforcement mode.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the the creation of the domain was
 *			successful.  A false value indicates setup of
 *			the domain was unsuccessful while a true
 *			value indicates the domains is setup and
 *			ready to be modeled.
 */

static _Bool setup_namespace(int *fdptr, _Bool enforce)

{
	_Bool retn = false;

	char fname[PATH_MAX];

	int fd;

	uint64_t id;

	enum TSEMcontrol_ns_config ns = 0;


	/* Create and configure a security model namespace. */
	if ( Current_Namespace )
		ns = TSEMcontrol_CURRENT_NS;

	if ( !Control->create_ns(Control, TSEMcontrol_TYPE_EXTERNAL, Digest, \
				 ns, Magazine_Size) )
		ERR(goto done);
	if ( !Control->id(Control, &id) )
		ERR(goto done);
	if ( enforce ) {
		if ( !Control->enforce(Control) )
			ERR(goto done);
	}

	/* Create the pathname to the event update file. */
	memset(fname, '\0', sizeof(fname));
	if ( snprintf(fname, sizeof(fname), TSEM_UPDATE_FILE, \
		      (long long int) id) >= sizeof(fname) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Update file: %s\n", fname);

	if ( (fd = open(fname, O_RDONLY)) < 0 )
		ERR(goto done);
	retn = true;


 done:
	if ( retn )
		*fdptr = fd;
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
 * This function is responsible for monitoring the child process that
 * is running the modeled workload.  The event loop monitors for a
 * a child exit and process management requests.
 *
 * \param mgmt		The object that will be used to receive management
 *			requests.
 *
 * \param cartridge	A pointer to a null terminated buffer containing
 *			the name of the cartridge being run.
 *
 * \param fd		The file descriptor from which security domain
 *			updates will be read from.
 *
 * \return		A boolean value is used to indicate the status
 *			of the child monitor.  A true value indicates
 *			that management was successfully completed while
 *			a false value indicates an error occurred.
 */

static _Bool child_monitor(LocalDuct mgmt, CO(char *, cartridge), int fd)

{
	_Bool event,
	      retn = false,
	      connected = false;

	int rc;

	unsigned int cycle = 0;

	struct pollfd poll_data[2];

	Buffer cmdbufr = NULL;


	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	poll_data[0].fd	    = fd;
	poll_data[0].events = POLLIN;

	if ( !mgmt->get_socket(mgmt, &poll_data[1].fd) ) {
		fputs("Error setting up polling data.\n", stderr);
		goto done;
	}
	poll_data[1].events = POLLIN;


	/* Dispatch loop. */
	if ( Debug ) {
		fprintf(Debug, "%d: Calling event loop\n", getpid());
		fprintf(Debug, "descriptor 1: %d, descriptor 2: %d\n", \
			poll_data[0].fd, poll_data[1].fd);
	}

	while ( 1 ) {
		if ( Debug )
			fprintf(Debug, "\n%d: Poll cycle: %d\n", getpid(), \
				++cycle);

		rc = poll(poll_data, 2, -1);
		if ( rc < 0 ) {
			if ( Signals.stop ) {
				if ( Debug )
					fputs("Quixote terminated.\n", Debug);
				kill_cartridge(true);
				retn = true;
				goto done;
			}
			if ( Signals.sigchild ) {
				if ( !child_exited(Monitor_pid) )
					continue;
				retn = true;
				goto done;
			}

			fputs("Poll error.\n", stderr);
			kill_cartridge(true);
			retn = true;
			goto done;
		}
		if ( rc == 0 ) {
			if ( Debug )
				fputs("Poll timeout.\n", Debug);
			continue;
		}

		if ( Debug )
			fprintf(Debug, "Poll retn=%d, Data poll=%0x, "	     \
				"Mgmt poll=%0x\n", rc, poll_data[0].revents, \
				poll_data[1].revents);

		if ( poll_data[0].revents & POLLHUP ) {
			if ( Signals.stop ) {
				retn = true;
				goto done;
			}
			if ( Signals.sigchild ) {
				if ( !child_exited(Monitor_pid) )
					continue;
				retn = true;
				goto done;
			}
		}

		if ( poll_data[0].revents & POLLIN ) {
			if ( !Event->read_event(Event, fd) ) {
				kill_cartridge(false);
				break;
			}

			event = true;
			while ( event ) {
				if ( !Event->fetch_event(Event, &event) ) {
					kill_cartridge(false);
					break;
				}
				if ( !process_event(Sancho) ) {
					if ( Debug )
						fprintf(Debug, "Event "	     \
							"processing error, " \
							"%u killing %u\n",   \
							getpid(), Monitor_pid);
					Model_Error = true;
					break;
				}
			}
			if ( Model_Error ) {
				kill_cartridge(false);
				break;
			}
		}

		if ( poll_data[1].revents & POLLIN ) {
			if ( !connected ) {
				if ( Debug )
					fputs("Have socket connection.\n", \
					      Debug);

				if ( !mgmt->accept_connection(mgmt) )
					ERR(goto done);
				if ( !mgmt->get_fd(mgmt, &poll_data[1].fd) )
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
						       &poll_data[1].fd) )
					ERR(goto done);
				connected = false;
				continue;
			}

			if ( !process_command(Sancho, mgmt, cmdbufr) ) {
				Model_Error = true;
				kill_cartridge(false);
			}
			cmdbufr->reset(cmdbufr);
		}
	}


 done:
	WHACK(cmdbufr);

	return retn;
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
 * \param enforce	A flag used to indicate whether or not the
 *			security domain should be placed in enforcement
 *			mode.
 *
 * \param outfile	A pointer to a null-terminated array
 *			containing the name of the output file that
 *			is to be generated.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the launch.  A false value indicates an error was
 *		encountered while a true value indicates the cartridge
 *		was successfully launched.
 */

static _Bool fire_cartridge(CO(LocalDuct, mgmt), CO(char *, cartridge), \
			    _Bool enforce, char *outfile)

{
	_Bool retn = false;

	char *bundle = NULL,
	     bufr[1024];

	int rc,
	    event_pipe[2],
	    event_fd = 0;

	pid_t cartridge_pid;

	struct pollfd poll_data[1];

	String cartridge_dir = NULL;


	/* Create the name of the bundle directory if in cartridge mode. */
	if ( Mode == cartridge_mode ) {
		INIT(HurdLib, String, cartridge_dir, ERR(goto done));
		cartridge_dir->add(cartridge_dir, QUIXOTE_MAGAZINE);
		cartridge_dir->add(cartridge_dir, "/");
		if ( !cartridge_dir->add(cartridge_dir, cartridge) )
			ERR(goto done);
		bundle = cartridge_dir->get(cartridge_dir);
		Runc_name = cartridge;
	}


	/* Create the subordinate cartridge process. */
	if ( pipe(event_pipe) == -1 )
		ERR(goto done);

	Monitor_pid = fork();
	if ( Monitor_pid == -1 )
		ERR(goto done);

	/* Monitor parent process. */
	if ( Monitor_pid > 0 ) {
		if ( Debug )
			fprintf(Debug, "Monitor process: %d\n", Monitor_pid);

		close(event_pipe[WRITE_SIDE]);
		if ( !child_monitor(mgmt, cartridge, event_pipe[READ_SIDE]) )
			ERR(goto done);

		if ( outfile != NULL ) {
			truncate(outfile, 0);
			if ( Trajectory )
				retn = output_trajectory(outfile);
			else
				retn = output_model(outfile);
		}
		else
			retn = true;
		goto done;
	}

	/* Child process - create an independent namespace for this process. */
	if ( Monitor_pid == 0 ) {
		close(event_pipe[READ_SIDE]);
		if ( !setup_namespace(&event_fd, enforce) )
			_exit(1);

		/* Fork again to run the cartridge. */
		cartridge_pid = fork();
		if ( cartridge_pid == -1 )
			exit(1);

		/* Child process - run the cartridge. */
		if ( cartridge_pid == 0 ) {
			if ( Debug )
				fprintf(Debug, "Workload process: %d\n",
					getpid());

			/* Drop the ability to modify the trust state. */
			if ( cap_drop_bound(CAP_MAC_ADMIN) != 0 )
				ERR(goto done);

			if ( Mode == cartridge_mode ) {
				execlp("runc", "runc", "run", "-b", bundle, \
				       cartridge, NULL);
				fputs("Cartridge execution failed.\n", stderr);
				exit(1);
			}

			if ( Mode == process_mode ) {
				if ( geteuid() != getuid() ) {
					if ( Debug )
						fprintf(Debug, "Changing to " \
							"real id: %u\n",      \
							getuid());
					if ( setuid(getuid()) != 0 ) {
						fputs("Cannot change uid.\n", \
						      stderr);
						exit(1);
					}
				}

				if ( Debug )
					fputs("Executing cartridge process.\n",
					      Debug);
				execlp("bash", "bash", "-i", NULL);
				fputs("Cartridge process execution failed.\n",\
				      stderr);
				exit(1);
			}
		}

		/* Parent process - monitor for events. */
		Workload_pid = cartridge_pid;

		poll_data[0].fd	    = event_fd;
		poll_data[0].events = POLLIN;

		while ( true ) {
			if ( Signals.stop ) {
				if ( Debug )
					fputs("Monitor process stopped.\n", \
					      Debug);
				retn = true;
				goto done;
			}

			if ( Signals.sigterm ) {
				if ( Debug )
					fputs("Monitor process terminated.\n",\
					      Debug);
				kill_cartridge(false);
				sleep(1);
				if ( Debug )
					fprintf(Debug, "%u: Sending SIGKILL " \
						"to %u.\n", getpid(),	      \
						cartridge_pid);
				kill(cartridge_pid, SIGKILL);
			}

			if ( Signals.sigchild ) {
				if ( child_exited(cartridge_pid) ) {
					close(event_fd);
					close(event_pipe[WRITE_SIDE]);
					_exit(0);
				}
			}

			memset(bufr, '\0', sizeof(bufr));

			rc = poll(poll_data, 1, -1);
			if ( Debug )
				fprintf(Debug, "Poll returns: %d\n", rc);
			if ( rc < 0 ) {
				if ( errno == -EINTR ) {
					fputs("poll interrupted.\n", stderr);
					continue;
				}
			}

			if ( (poll_data[0].revents & POLLIN) == 0 )
				continue;

			while ( true ) {
				rc = read(event_fd, bufr, sizeof(bufr));
				if ( rc == 0 )
					break;
				if ( rc < 0 ) {
					if ( errno != ENODATA ) {
						fputs("Fatal event read.\n", \
						      stderr);
						exit(1);
					}
					break;
				}
				if ( rc > 0 ) {
					write(event_pipe[WRITE_SIDE], bufr, \
					      rc);
					lseek(event_fd, 0, SEEK_SET);
				}
			}

			if ( lseek(event_fd, 0, SEEK_SET) < 0 ) {
				fputs("Seek error.\n", stderr);
				break;
			}
		}
	}


 done:
	WHACK(cartridge_dir);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for issueing a reset request to the
 * Sancho micro-controller implementation.
 *
 * \param duct		A pointer to the object being used to communicate
 *			with the micro-controller.
 *
 * \param bufr		The object which will be used to hold the command
 *			to be sent.
 *
 * \return	No return value is defined.
 */

static void send_reset(CO(TTYduct, duct))

{

	static unsigned char cmd[] = "reset";

	Buffer bufr = NULL;


	if ( Debug )
		fputs("Sending reset.\n", Debug);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( bufr->add(bufr, cmd, sizeof(cmd)) )
		duct->send_Buffer(duct, bufr);


 done:
	WHACK(bufr);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool enforce = false;

	char *debug	    = NULL,
	     *model	    = NULL,
	     *outfile	    = NULL,
	     *cartridge	    = NULL,
	     *magazine_size = NULL,
	     *device	    = "/dev/ttyACM0";

	int opt,
	    fd	 = 0,
	    retn = 1;

	struct sigaction signal_action;

	LocalDuct mgmt = NULL;


	while ( (opt = getopt(argc, argv, "CPSetuc:d:h:m:n:o:p:s:")) != EOF )
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
				Enforce = true;
				break;
			case 't':
				Trajectory = true;
				break;
			case 'u':
				Current_Namespace = true;
				break;

			case 'c':
				cartridge = optarg;
				break;
			case 'd':
				debug = optarg;
				break;
			case 'h':
				Digest = optarg;
				break;
			case 'm':
				model = optarg;
				break;
			case 'n':
				magazine_size = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 's':
				device = optarg;
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

	/* Verify the magazine size if specified. */
	if ( magazine_size != NULL ) {
		Magazine_Size = strtoul(magazine_size, NULL, 0);
		if ( (errno == EINVAL) || (errno == ERANGE) ) {
			fputs("Invalid magazine size.\n", stderr);
			goto done;
		}
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


	/* Initialize the TSEM control object. */
	INIT(NAAAIM, TSEMevent, Event, ERR(goto done));

	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));
	if ( !Control->generate_key(Control) )
		ERR(goto done);


	/* Open a connection to the co-processor. */
	INIT(NAAAIM, TTYduct, Sancho, ERR(goto done));
	if ( !Sancho->init_device(Sancho, device) ) {
		WHACK(Sancho);
		fprintf(stderr, "quixote-mcu: Cannot connect to SanchoMCU" \
			"instance via %s.\n", device);
		goto done;
	}


	/* Load and seal a security model if specified. */
	if ( model != NULL ) {
		if ( Debug )
			fprintf(Debug, "Loading security model: %s\n", model);

		if ( !load_model(Sancho, model) ) {
			fputs("Cannot initialize security model.\n", stderr);
			goto done;
		}
	}


	/* Setup the management socket. */
	INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
	if ( !setup_management(mgmt, cartridge) )
		ERR(goto done);

	/* Fire the workload cartridge. */
	if ( Debug )
		fprintf(Debug, "Launch process: %d\n", getpid());
	if ( !fire_cartridge(mgmt, cartridge, enforce, outfile) )
		ERR(goto done);

	waitpid(Monitor_pid, NULL, 0);

	if ( outfile != NULL ) {
		if ( Trajectory )
			fputs("Wrote execution trajectory to: ", stdout);
		else
			fputs("Wrote security map to: ", stdout);
		fprintf(stdout, "%s\n", outfile);
	}


 done:
	if ( Sancho != NULL )
		send_reset(Sancho);

	WHACK(mgmt);

	WHACK(Aggregate);
	WHACK(Sancho);
	WHACK(Control);
	WHACK(Event);

	if ( fd > 0 )
		close(fd);

	return retn;
}
