/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in a userspace disciplined security domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of a software 'cartridge' in a subordinate process.  The parent
 * process monitors the following file:
 *
 * /sys/fs/tsem/update-NNNNNNNNNN
 *
 * Where NNNNNNNNNN is the id number of the security event modeling
 * domain.
 *
 * The security domain state change events are transmitted to a Sancho
 * Trusted Modeling Agent userspace process that is responsible for
 * modeling the security domain.
 *
 * The userspace evaluator advises the setting of the bad actor status
 * bit of the process generating the security state change events based on
 * the security model that was specified.  This security status bit is
 * interrogated by the TSEM linux security module that can then interdict
 * security sensitive events.
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

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "SHA256.h"

#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"
#include "TSEMcontrol.h"


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
 * The modeling object for the canister.
 */
static TSEM Model = NULL;

/**
 * The control object for the model.
 */
static TSEMcontrol Control = NULL;

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
 * This variable is set by the code that loads the security model
 * in order to advise the namespace setup that the security model
 * should be sealed from the kernel's perspective.
 */
static _Bool Sealed = false;

/**
 * This variable is used to indicate that an execution trajectory
 * should be generated.
 */
static _Bool Trajectory = false;

/**
 * The following variable holds the current measurement.
 */
#if 0
static unsigned char Measurement[32];
#endif

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
 * This function carries out the addition of a measurement value
 * generated by the kernel to the current measurement state of the
 * security domain.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the hexadecimally encoded measurement from
 *			the domain.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the measurement succeeded.  A
 *			false value indicates the addition of the
 *			measurement failed while a true value indicates
 *			the measurement had succeeded.
 */

static _Bool add_measurement(CO(char *, bufr))

{
	_Bool retn = false;

	Buffer bf,
	       input = NULL;

	Sha256 sha256 = NULL;


	/* Convert the ASCII measurement into a binary buffer. */
	INIT(HurdLib, Buffer, input, ERR(goto done));
	if ( !input->add_hexstring(input, bufr) )
		ERR(goto done);


	/* Update the internal measurement. */
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	sha256->add(sha256, input);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	bf = sha256->get_Buffer(sha256);

	input->reset(input);
	input->add(input, Measurement, sizeof(Measurement));
	input->add_Buffer(input, bf);

	sha256->reset(sha256);
	sha256->add(sha256, input);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	memcpy(Measurement, bf->get(bf), bf->size(bf));
	if ( Debug )
		fprintf(Debug, "Add measurement: %s\n", bufr);

	retn = true;


 done:
	WHACK(input);
	WHACK(sha256);

	return retn;
}
#endif


/**
 * Private function.
 *
 * This function carries out the addition of a security state event
 * to the current security state model.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII encoded state description.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the event succeeded.  A
 *			false value indicates the addition failed while
 *			a true value indicates the addition succeeded.
 */

static _Bool add_event(CO(char *, inbufr))

{
	_Bool status,
	      discipline,
	      sealed,
	      retn = false;

	pid_t pid;

	String update = NULL;

	SecurityEvent event = NULL;


	/* Parse the event. */
	INIT(HurdLib, String, update, ERR(goto done));
	if ( !update->add(update, inbufr) )
		ERR(goto done);

	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, update) )
		ERR(goto done);


	/*
	 * If this is a model error release the actor so the runc
	 * instance can release the domain.
	 */
	if ( Model_Error ) {
		if ( Debug )
			fputs("Model error, releasing actor.\n", Debug);

		if ( !event->get_pid(event, &pid) )
			ERR(goto done);
		if ( !Control->release(Control, pid) < 0 ) {
			fprintf(stderr, "Bad actor release error: "  \
				"%d:%s\n", errno, strerror(errno));
		}
		else
			retn = true;

		goto done;
	}


	/* Proceed with modeling the event. */
	if ( !Model->update(Model, event, &status, &discipline, &sealed) )
		ERR(goto done);

	Model->discipline_pid(Model, &pid);

	if ( Debug )
		fprintf(Debug, "Model update: status=%d, discipline=%d\n",
			status, discipline);


	/* Security domain is not being disciplined, release the process. */
	if ( !sealed ) {
		if ( Debug )
			fputs("Unsealed, releasing actor.\n", Debug);
		if ( !Control->release(Control, pid) < 0 )
			fprintf(stderr, "[%s]: Release actor status: %d:%s\n",
				__func__, errno, strerror(errno));
	}


	/*
	 * Security domain is being disciplined.  Release processes
	 * that are not in the event map as bad actors and others as
	 * good actors.
	 */
	if ( sealed ) {
		if ( discipline ) {
			if ( Debug )
				fputs("Sealed, releasing bad actor.\n", Debug);
			if ( !Control->discipline(Control, pid) ) {
				fprintf(stderr, "Bad actor release error: "  \
					"%d:%s\n", errno, strerror(errno));
					retn = false;
					goto done;
			}
		} else {
			if ( Debug )
				fputs("Sealed, releasing actor.\n", Debug);
			if ( !Control->release(Control,pid) < 0 ) {
				fprintf(stderr, "Good actor release error: "  \
					"%d:%s\n", errno, strerror(errno));
					retn = false;
					goto done;
			}
		}
	}

	retn = true;


 done:
	if ( !status )
		WHACK(event);

	WHACK(update);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of the hardware aggregate
 * measurement to the current security state model.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII hardware aggregate measurement.
 *
 * \return		A boolean value is returned to indicate whether
 *			or addition of the aggregate value succeeded.  A
 *			false value indicates the addition failed while
 *			a true value indicates the addition succeeded.
 */

static _Bool add_aggregate(CO(char *, inbufr))

{
	_Bool retn = false;


	if ( Debug )
		fprintf(Debug, "aggregate %s", inbufr);

	if ( Aggregate == NULL ) {
		INIT(HurdLib, Buffer, Aggregate, ERR(goto done));
		if ( !Aggregate->add_hexstring(Aggregate, inbufr) )
		ERR(goto done);
	}

	if ( !Model->set_aggregate(Model, Aggregate) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of a description of an
 * intercepted LSM event to the current security domain model.
 *
 * \param TSEM_event	A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or addition of the event.  A false value indicates
 *			the addition failed while a true value indicates
 *			the addition succeeded.
 */

static _Bool add_TSEM_event(CO(char *, TSEM_event))

{
	_Bool retn = false;

	String event = NULL;


	INIT(HurdLib, String, event, ERR(goto done));
	event->add(event, TSEM_event);
	if ( !Model->add_TSEM_event(Model, event) )
		ERR(goto done);

	retn = true;


 done:

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for the processing of Turing security
 * state events generated by the kernel.
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

	static const char *measurement = "measurement " ;


	/* Locate the event type. */
	if ( strncmp(event, measurement, strlen(measurement)) == 0 ) {
		retn = true;
		goto done;
	}

	for (cp= Sancho_cmd_list; cp->syntax != NULL; ++cp) {
		if ( strncmp(cp->syntax, event, strlen(cp->syntax)) == 0 )
			break;
	}

	if ( cp->syntax == NULL ) {
		fprintf(stderr, "Unknown event: %s\n", event);
		goto done;
	}

	event_arg = event + strlen(cp->syntax);


	/* Dispatch the event. */
	switch ( cp->command ) {
#if 0
		case measurement_event:
			retn = add_measurement(p);
			break;
#endif

		case export_event:
			retn = add_event(event_arg);
			break;

		case aggregate_event:
			retn = add_aggregate(event_arg);
			break;

		case seal_event:
			if ( Debug )
				fputs("Kernel sealed domain.\n", Debug);

			Model->seal(Model);
			break;

		case log_event:
			retn = add_TSEM_event(event_arg);
			break;

		default:
			fprintf(stderr, "Unknown event: %s\n", event);
			break;
	}


 done:
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
 */

static _Bool send_trajectory(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t lp,
	       cnt = 0;

	SecurityEvent event;

	String es = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = Model->trajectory_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent trajectory size: %zu\n", cnt);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	Model->rewind_event(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !Model->get_event(Model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;
		if ( !event->format(event, es) )
			ERR(goto done);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) es->get(es), \
			     es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		es->reset(es);
	}

	retn = true;

 done:
	WHACK(es);

	return retn;
}


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

	size_t lp,
	       cnt = 0;

	SecurityEvent event;

	String es = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = Model->forensics_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent forensics size: %zu\n", cnt);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	Model->rewind_forensics(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !Model->get_forensics(Model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;
		if ( !event->format(event, es) )
			ERR(goto done);

		/*
		 * The following is a safety check to make sure that
		 * the object event is populated in case there was
		 * an error such as a failure to reset the cursor
		 * between trajectory or forensics traversals.
		 */
		if ( es->size(es) == 0 ) {
			if ( !es->add(es, "Unknown event.") )
				ERR(goto done);
		}

		/* Send the contents of the string object. */
		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) es->get(es), \
			     es->size(es) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
		es->reset(es);
	}

	retn = true;

 done:
	WHACK(es);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security states
 * to the caller.  The protocol used is to send the number of elements in
 * the map followed by each state in the model as a hexadecimal ASCII
 * string.
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

	uint8_t *p,
		 pi;

	char point[NAAAIM_IDSIZE * 2 + 1];

	size_t lp,
	       cnt = 0;

	SecurityPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = Model->points_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent contour size: %zu\n", cnt);


	/* Send each trajectory point. */
	Model->rewind_points(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !Model->get_point(Model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;

		memset(point, '\0', sizeof(point));
		p = cp->get(cp);
		for (pi= 0; pi < NAAAIM_IDSIZE; ++pi)
			snprintf(&point[pi*2], 3, "%02x", *p++);

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) point, sizeof(point));
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;

 done:

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current set of
 * TE violations to the caller.  The protocol used is to send the number of
 * elements in the event list followed by each event as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates an error was encountered while sending
 *			the event list while a true value indicates the
 *			event list was succesfully sent.
 */

static _Bool send_events(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	size_t lp,
	       cnt = 0;

	String event = NULL;


	/*
	 * Compute the number of elements in the AI list and send it to
	 * the client.
	 */
	cnt = Model->TSEM_events_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent event size: %zu\n", cnt);


	/* Send each event. */
	Model->TSEM_rewind_event(Model);

	for (lp= 0; lp < cnt; ++lp) {
		if ( !Model->get_TSEM_event(Model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) event->get(event), \
			     event->size(event) + 1);
		if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current security state
 * event map to the caller.  This map can be used to define the desired
 * security state by feeding this map into the quixote utility with the
 * -m command-line switch.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information which will be transmitted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates an error was encountered while sending
 *			the event list while a true value indicates the
 *			event list was succesfully sent.
 */

static _Bool send_map(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;


	/* Send the domain aggregate. */
	cmdbufr->reset(cmdbufr);
	cmdbufr->add_Buffer(cmdbufr, Aggregate);
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);


	/* Send each point in the model. */
	retn = send_points(mgmt, cmdbufr);


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the processing of a command from the
 * quixote-console utility.
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

	static unsigned char ok[] = "OK";

	int *cp;


	if ( cmdbufr->size(cmdbufr) != sizeof(int) )
		ERR(goto done);

	cp = (int *) cmdbufr->get(cmdbufr);
	switch ( *cp ) {
		case show_measurement:
			cmdbufr->reset(cmdbufr);
			if ( !Model->get_measurement(Model, cmdbufr) )
					ERR(goto done);
			if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
				ERR(goto done);
			retn = true;
			break;

		case show_state:
			cmdbufr->reset(cmdbufr);
			if ( !Model->get_state(Model, cmdbufr) )
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

		case show_events:
			retn = send_events(mgmt, cmdbufr);
			break;

		case show_map:
			retn = send_map(mgmt, cmdbufr);
			break;

		case seal_event:
			Model->seal(Model);

			cmdbufr->reset(cmdbufr);
			if ( !cmdbufr->add(cmdbufr, ok, sizeof(ok)) )
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
 * \param model_file	The name of the file containing the security
 *			model.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the model was loaded.  A false value
 *			indicates the load of the model failed while
 *			a true value indicates the model was successfully
 *			loaded.
 */

static _Bool load_model(char *model_file)

{
	_Bool retn = false;

	String str = NULL;

	File model = NULL;


	/* Open the behavioral map and initialize the binary point object. */
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, model, ERR(goto done));
	if ( !model->open_ro(model, model_file) )
		ERR(goto done);


	/* Loop over the mapfile. */
	while ( model->read_String(model, str) ) {
		if ( Debug )
			fprintf(Debug, "Model entry: %s\n", str->get(str));

		if ( strcmp(str->get(str), "seal") == 0 )
			Sealed = true;

		if ( !Model->load(Model, str) )
			ERR(goto done);
		str->reset(str);
	}

	retn = true;


 done:
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

	size_t lp,
	       cnt = 0;

	SecurityEvent event;

	Buffer bufr = NULL;

	String es = NULL;

	File outfile = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, String, es, ERR(goto done));

	INIT(HurdLib, File, outfile, ERR(goto done));
	if ( !outfile->open_rw(outfile, fname) )
		ERR(goto done);


	/* Write each trajectory point. */
	Model->rewind_event(Model);
	cnt = Model->trajectory_size(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !Model->get_event(Model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;
		if ( !event->format(event, es) )
			ERR(goto done);

		bufr->reset(bufr);
		bufr->add(bufr, (void *) es->get(es), es->size(es));
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

	size_t lp,
	       cnt = 0;

	Buffer bufr = NULL;

	String str = NULL;

	SecurityPoint cp = NULL;

	File outfile = NULL;

	static const char *aggregate_cmd = "aggregate ",
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
	bufr->add(bufr, (void *) str->get(str), str->size(str));
	bufr->add(bufr, (void *) "\n", 1);
	if ( !outfile->write_Buffer(outfile, bufr) )
		ERR(goto done);

	/* Send the state points. */
	Model->rewind_points(Model);
	cnt = Model->points_size(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !Model->get_point(Model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;

		str->reset(str);
		if ( !str->add(str, state_cmd) )
			ERR(goto done);
		_encode_buffer(str, cp->get(cp), NAAAIM_IDSIZE);

		bufr->reset(bufr);
		bufr->add(bufr, (void *) str->get(str), str->size(str));
		bufr->add(bufr, (void *) "\n", 1);
		if ( !outfile->write_Buffer(outfile, bufr) )
			ERR(goto done);
	}

	/* Output the closing tags. */
	str->reset(str);
	bufr->reset(bufr);
	if ( !str->add(str, seal_cmd) )
		ERR(goto done);
	bufr->add(bufr, (void *) str->get(str), str->size(str));
	if ( !outfile->write_Buffer(outfile, bufr) )
		ERR(goto done);

	str->reset(str);
	bufr->reset(bufr);
	if ( !str->add(str, end_cmd) )
		ERR(goto done);
	bufr->add(bufr, (void *) str->get(str), str->size(str));
	if ( !outfile->write_Buffer(outfile, bufr) )
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


	/* Create and configure a security model namespace. */
	if ( !Control->external(Control) )
		ERR(goto done);
	if ( !Control->id(Control, &id) )
		ERR(goto done);
	if ( enforce ) {
		if ( !Control->enforce(Control) )
			ERR(goto done);
	}
	if ( Sealed ) {
		if ( !Control->seal(Control) )
			ERR(goto done);
	}

	/* Create the pathname to the event update file. */
	memset(fname, '\0', sizeof(fname));
	if ( snprintf(fname, sizeof(fname), SYSFS_UPDATES, \
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
		execlp("runc", "runc", "kill", cartridge, "SIGKILL", \
		       NULL);
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
	_Bool retn = false,
	      connected = false;

	char *p,
	     bufr[512];

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
				kill_cartridge(cartridge, true);
				goto done;
			}
			if ( Signals.sigchild ) {
				if ( !child_exited(Monitor_pid) )
					continue;
				goto done;
			}

			fputs("Poll error.\n", stderr);
			kill_cartridge(cartridge, true);
			goto done;
		}
		if ( rc == 0 ) {
			if ( Debug )
				fputs("Poll timeout.\n", Debug);
			continue;
		}

		if ( Debug )
			fprintf(Debug, "Events: %d, Data poll=%0x, "	\
				"Mgmt poll=%0x\n", retn,		\
				poll_data[0].revents, poll_data[1].revents);

		if ( poll_data[0].revents & POLLHUP ) {
			if ( Signals.stop )
				goto done;
			if ( Signals.sigchild ) {
				if ( !child_exited(Monitor_pid) )
					continue;
				goto done;
			}
		}

		if ( poll_data[0].revents & POLLIN ) {
			p = bufr;
			memset(bufr, '\0', sizeof(bufr));
			while ( 1 ) {
				retn = read(fd, p, 1);
				if ( retn < 0 ) {
					if ( errno != ENODATA )
						fprintf(stderr, "Have "	    \
							"error: retn=%d, "  \
							"error=%s\n", retn, \
							strerror(errno));
				}
				if ( *p != '\n' ) {
					++p;
					continue;
				}
				else
					*p = '\0';
				if ( Debug )
					fprintf(Debug,			  \
						"Processing event: %s\n", \
						bufr);
				if ( !process_event(bufr) ) {
					if ( Debug )
						fprintf(Debug, "Event "	     \
							"processing error, " \
							"%u killing %u\n",   \
							getpid(), Monitor_pid);
					Model_Error = true;
				}
				if ( Model_Error )
					kill_cartridge(cartridge, false);
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

			if ( !process_command(mgmt, cmdbufr) )
				ERR(goto done);
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


	/* Create the name of the bundle directory if in cartridge mode . */
	if ( Mode == cartridge_mode ) {
		INIT(HurdLib, String, cartridge_dir, ERR(goto done));
		cartridge_dir->add(cartridge_dir, QUIXOTE_MAGAZINE);
		cartridge_dir->add(cartridge_dir, "/");
		if ( !cartridge_dir->add(cartridge_dir, cartridge) )
			ERR(goto done);
		bundle = cartridge_dir->get(cartridge_dir);
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
			fprintf(Debug, "Monitor process: %d\n", getpid());
		close(event_pipe[WRITE_SIDE]);
		if ( !child_monitor(mgmt, cartridge, event_pipe[READ_SIDE]) )
			ERR(goto done);
		if ( outfile != NULL ) {
			if ( Trajectory )
				retn = output_trajectory(outfile);
			else
				retn = output_model(outfile);
		}
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
			if ( cap_drop_bound(CAP_TRUST) != 0 )
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
							"real id: \%u\n",     \
							getuid());
					if ( setuid(getuid()) != 0 ) {
						fputs("Cannot change uid.\n", \
						      stderr);
						exit(1);
					}
				}

				if ( Debug )
					fputs("Executing cartridge " \
					      "process.\n", Debug);
				execlp("bash", "bash", "-i", NULL);
				fputs("Cartridge process execution failed.\n",\
				      stderr);
				exit(1);
			}
		}

		/* Parent process - monitor for events. */
		poll_data[0].fd	    = event_fd;
		poll_data[0].events = POLLIN;

		while ( true ) {
			if ( Signals.stop ) {
				if ( Debug )
					fputs("Monitor process stopped\n", \
					      Debug);
				retn = true;
				goto done;
			}

			if ( Signals.sigterm ) {
				if ( Debug )
					fputs("Monitor procss terminated.\n", \
					      Debug);
				kill(cartridge_pid, SIGHUP);
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



/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool enforce = false;

	char *debug	= NULL,
	     *model	= NULL,
	     *outfile	= NULL,
	     *cartridge	= NULL;

	int opt,
	    fd	 = 0,
	    retn = 1;

	struct sigaction signal_action;

	LocalDuct mgmt = NULL;


	while ( (opt = getopt(argc, argv, "CPSetc:d:m:o:p:")) != EOF )
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
			case 't':
				Trajectory = true;
				break;

			case 'c':
				cartridge = optarg;
				break;
			case 'd':
				debug = optarg;
				break;
			case 'm':
				model = optarg;
				break;
			case 'o':
				outfile = optarg;
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
	if ( sigaction(SIGUSR1, &signal_action, NULL) == -1 )
		goto done;


	/* Initialize the security model and its controller. */
	INIT(NAAAIM, TSEM, Model, ERR(goto done));
	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));


	/* Load and seal a security model if specified. */
	if ( model != NULL ) {
		if ( Debug )
			fprintf(Debug, "Loading security model: %s\n", model);

		if ( !load_model(model) ) {
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
	WHACK(mgmt);

	WHACK(Aggregate);
	WHACK(Model);
	WHACK(Control);

	if ( fd > 0 )
		close(fd);

	return retn;
}
