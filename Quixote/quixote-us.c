/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in a userspace disciplined security domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of a software 'cartridge' in a subordinate process.  The parent
 * process monitors the following file:
 *
 * /sys/kernel/security/tsem/update-NNNNNNNNNN
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
#include <Process.h>

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
#include "TSEMevent.h"
#include "TSEMworkload.h"


/**
 * Variable used to indicate that debugging is enabled and to provide
 * the filehandle to be used for debugging.
 */
static FILE *Debug = NULL;

/**
 * The object representing the workload under management.
 */
static TSEMworkload Workload = NULL;

/**
 * The modeling object for the canister.
 */
static TSEM Model = NULL;

/**
 * This variable is used to indicate that a model violation has occurred
 * in an event running in atomic context and the workload is being
 * shutdown.
 */

static _Bool In_Shutdown = false;

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
 * The name of the hash function to be used for the namespace.
 */
static char *Digest = NULL;

/**
 * A string defining the size of the atomic magazine to be
 * allocated for a namespace.
 */
static unsigned long Magazine_Size = 0;

/**
 * A flag to indicate whether or not the security model is to
 * be enforced.
 */
static _Bool Enforce = false;

/**
 * The alternate TSEM model that is to be used.
 */
static char *TSEM_model = NULL;

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
	 container_mode,
	 execute_mode
} Mode = container_mode;


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
		case execute_mode:
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

		case container_mode:
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


/**
 * Private function.
 *
 * This function carries out the addition of a security state event
 * to the current security state model.
 *
 * \param update	The object containing the event description
 *			to be processed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the event succeeded.  A
 *			false value indicates the addition failed while
 *			a true value indicates the addition succeeded.
 */

static _Bool add_event(CO(String, update))

{
	_Bool status,
	      discipline,
	      sealed,
	      retn = false;

	uint64_t tnum;

	pid_t pid;

	SecurityEvent event = NULL;


	/* Parse the event. */
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

		if ( !event->get_pid(event, &pid, &tnum) )
			ERR(goto done);
		if ( !Workload->release(Workload, pid, tnum) ) {
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

	Model->discipline_pid(Model, &pid, &tnum);

	if ( Debug )
		fprintf(Debug, "Model update: status=%d, discipline=%d, " \
			"pid=%d, tnum=%lu\n", status, discipline, pid, tnum);

	/* Security domain is not being disciplined, release the process. */
	if ( !sealed ) {
		if ( Debug )
			fprintf(Debug, "Unsealed, releasing pid %d/%lu.\n", \
				pid, tnum);
		if ( !Workload->release(Workload, pid, tnum) )
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
			if ( In_Shutdown) {
				Workload->discipline(Workload, pid, tnum);
				retn = true;
				goto done;
			}
			if ( !Workload->discipline(Workload, pid, tnum) ) {
				fprintf(stderr, "Bad actor release error: "  \
					"%d:%s\n", errno, strerror(errno));
					retn = false;
					goto done;
			}
		} else {
			if ( Debug )
				fputs("Sealed, releasing actor.\n", Debug);
			if ( In_Shutdown) {
				Workload->release(Workload, pid, tnum);
				retn = true;
				goto done;
			}
			if ( !Workload->release(Workload, pid, tnum) ) {
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

	return retn;
}


/**
 * Private function.
 *
 * This function handles the receive of an asynchronous security event.
 *
 * \param update	A pointer to the object that will be used to
 *			hold the ASCII encoded state description.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the event succeeded.  A
 *			false value indicates the addition failed while
 *			a true value indicates the addition succeeded.
 */

static _Bool add_async_event(CO(String, update))

{
	_Bool status,
	      violation,
	      sealed,
	      retn = false;

	uint64_t tnum;

	pid_t pid;

	SecurityEvent event = NULL;


	/* Parse the event. */
	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, update) )
		ERR(goto done);

	/*
	 * If this is a model error release the actor so the runc
	 * instance can release the domain.
	 */
	if ( Model_Error ) {
		if ( Debug )
			fputs("Model error.\n", Debug);
		goto done;
	}


	/* Proceed with modeling the event. */
	if ( !Model->update(Model, event, &status, &violation, &sealed) )
		ERR(goto done);
	Model->discipline_pid(Model, &pid, &tnum);

	if ( Debug )
		fprintf(Debug, "Async model update: status=%d, "	\
			"violation=%d, pid=%d, tnum=%lu\n", status,	\
			violation, pid, tnum);

	if ( In_Shutdown ) {
		if ( violation ) {
			if ( Debug )
				fputs("In shutdown, disciplining PID.\n", \
				      Debug);
			Workload->discipline(Workload, pid, tnum);
		}
		else {
			if ( Debug )
				fputs("In shutdown, releasing PID.\n", \
				      Debug);
			Workload->release(Workload, pid, tnum);
		}
		retn = true;
		goto done;
	}


	/* Handle a sealed model that is in violation. */
	if ( sealed && violation && Enforce ) {
		if ( Debug )
			fputs("Atomic context security violation:\n", Debug);
		fputs("Security violation in atomic context, "
		      "shutting down workload.\n", stderr);
		In_Shutdown = true;
		Workload->discipline(Workload, pid, tnum);
		Workload->shutdown(Workload, true);
	}

	retn = true;


 done:
	if ( !status )
		WHACK(event);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of the hardware aggregate
 * measurement to the current security state model.
 *
 * \param str	The object containing the description of the aggregate
 *		value.
 *
 * \return	A boolean value is returned to indicate whether or
 *		addition of the aggregate value succeeded.  A false
 *		value indicates the addition failed while a true
 *		value indicates the addition succeeded.
 */

static _Bool add_aggregate(CO(String, str))

{
	_Bool retn = false;


	if ( Debug )
		fprintf(Debug, "aggregate %s\n", str->get(str));

	if ( Aggregate == NULL ) {
		INIT(HurdLib, Buffer, Aggregate, ERR(goto done));
		if ( !Aggregate->add_hexstring(Aggregate, str->get(str)) )
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
 * intercepted LSM security violation event.
 *
 * \param TSEM_event	A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or addition of the event.  A false value indicates
 *			the addition failed while a true value indicates
 *			the addition succeeded.
 */

static _Bool add_log(CO(String, event))

{
	_Bool retn = false;


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
 * \param event		The object that contains the exported event that
 *			is to be processed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the event was successful.  A
 *			false value indicates a failure in event
 *			processing while a true value indicates that
 *			event processing has succeeded.
 */

static _Bool process_event(CO(TSEMevent, event))

{
	_Bool retn = false;

	enum TSEM_export_type type;

	String str = NULL;


	if ( Debug )
		fprintf(Debug, "Processing event: '%s'\n", \
			event->get_event(event));


	/* Dispatch the event. */
	if ( Debug )
		fputs("Resetting event.\n", Debug);
	event->reset(event);
	if ( (type = event->extract_export(event)) == TSEM_EVENT_UNKNOWN )
		ERR(goto done);

	INIT(HurdLib, String, str, ERR(goto done));
	if ( !str->add(str, event->get_event(event)) )
		ERR(goto done);

	switch ( type ) {
		case TSEM_EVENT_AGGREGATE:
			str->reset(str);
			if ( !event->get_text(event, "value", str) )
				ERR(goto done);
			retn = add_aggregate(str);
			break;

		case TSEM_EVENT_EVENT:
			retn = add_event(str);
			break;

		case TSEM_EVENT_ASYNC_EVENT:
			retn = add_async_event(str);
			break;

		case TSEM_EVENT_LOG:
			retn = add_log(str);
			break;

		default:
			break;
	}


 done:
	WHACK(str);

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
 * This function is responsible for returning the population counts for
 * coefficients on the trajectory list.
 *
 * \param mgmt		The socket object used to communicate with
 *			the quixote-console management instance.
 *
 * \param cmdbufr	The object which will be used to hold the
 *			information that will be transmitted.
 *
 * \param type		A flag used to indicate what type of counts
 *			are to be set.  A true value indicates that
 *			the counts of valid points are to be returned
 *			while a false value indicates that invalid
 *			points are to be returned.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_trajectory_counts(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr), \
				    const _Bool type)

{
	_Bool retn = false;

	char bufr[21];

	size_t lp,
	       cnt = 0;

	SecurityPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	if ( type ) {
		cnt = Model->points_size(Model);
		cnt -= Model->forensics_size(Model);
	}
	else
		cnt = Model->forensics_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent coefficient counts size: %zu\n", cnt);

	/* Send each trajectory point. */
	Model->rewind_points(Model);

	for (lp= 0; lp < Model->points_size(Model); ++lp ) {
		if ( !Model->get_point(Model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;
		if ( cp->is_valid(cp) != type )
			continue;

		snprintf(bufr, sizeof(bufr), "%lu", cp->get_count(cp));

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) bufr, sizeof(bufr));
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
 * \param type		A boolean variable used to indicate which
 *			security state coefficients are to be returned.
 *			A true value sends valid coefficients while
 *			a false value sends invalid coefficients.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the command was processed.  A false value
 *			indicates the processing of commands should be
 *			terminated while a true value indicates an
 *			additional command cycle should be processed.
 */

static _Bool send_trajectory_coefficients(CO(LocalDuct, mgmt), \
					  CO(Buffer, cmdbufr), \
					  const _Bool type)

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
	if ( type ) {
		cnt = Model->points_size(Model);
		cnt -= Model->forensics_size(Model);
	}
	else
		cnt = Model->forensics_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Sent coefficient size: %zu\n", cnt);


	/* Send each trajectory point. */
	Model->rewind_points(Model);

	for (lp= 0; lp < Model->points_size(Model); ++lp ) {
		if ( !Model->get_point(Model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;
		if ( cp->is_valid(cp) != type )
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
	retn = send_trajectory_coefficients(mgmt, cmdbufr, true);


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

		case show_coefficients:
			retn = send_trajectory_coefficients(mgmt, cmdbufr, \
							    true);
			break;

		case show_counts:
			retn = send_trajectory_counts(mgmt, cmdbufr, true);
			break;

		case show_forensics:
			retn = send_forensics(mgmt, cmdbufr);
			break;

		case show_forensics_coefficients:
			retn = send_trajectory_coefficients(mgmt, cmdbufr, \
							    false);
			break;

		case show_forensics_counts:
			retn = send_trajectory_counts(mgmt, cmdbufr, false);
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
 * \param workload	The object that is managing the workload.
 *
 * \param container	A pointer to a null-terminated character buffer
 *			containing the name of the container that is
 *			being executed.
 *
 * \param outfile	A pointer to a null-terminated array
 *			containing the name of the output file that
 *			is to be generated.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the workload.  A false value indicates an error was
 *		encountered while a true value indicates the workload
 *		was successfuly executed.
 */

static _Bool run_workload(CO(TSEMworkload, workload), CO(char *, container), \
			  CO(char *, outfile))

{
	_Bool retn = false;

	pid_t workload_pid;

	LocalDuct mgmt = NULL;


	/* Create the namespace management process. */
	workload_pid = fork();
	if ( workload_pid == -1 )
		ERR(goto done);

	/* Parent process - Security Monitor. */
	if ( workload_pid > 0 ) {
		/* Setup the management socket. */
		INIT(NAAAIM, LocalDuct, mgmt, ERR(goto done));
		if ( !setup_management(mgmt, container) )
			ERR(goto done);

		if ( !workload->run_monitor(workload, workload_pid, mgmt, \
					    process_event, process_command) )
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

		WHACK(mgmt);
		goto done;
	}

	/* Child process - run the workload and model events. */
	if ( !workload->run_workload(workload) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool current_namespace = false;

	char *debug	    = NULL,
	     *model	    = NULL,
	     *outfile	    = NULL,
	     *container	    = NULL,
	     *magazine_size = NULL;

	int opt,
	    fd	 = 0,
	    retn = 1;


	while ( (opt = getopt(argc, argv, "CPSXetuM:c:d:h:m:n:o:p:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = container_mode;
				break;
			case 'P':
				Mode = process_mode;
				break;
			case 'S':
				Mode = show_mode;
				break;
			case 'X':
				Mode = execute_mode;
				break;
			case 'e':
				Enforce = true;
				break;
			case 't':
				Trajectory = true;
				break;
			case 'u':
				current_namespace = true;
				break;

			case 'M':
				TSEM_model = optarg;
				break;

			case 'c':
				container = optarg;
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
		}

	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( (Mode == container_mode) && (container == NULL) ) {
		fputs("No software container specified.\n", stderr);
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


	/* Load and seal a security model if specified. */
	INIT(NAAAIM, TSEM, Model, ERR(goto done));

	if ( model != NULL ) {
		if ( Debug )
			fprintf(Debug, "Loading security model: %s\n", model);

		if ( !load_model(model) ) {
			fputs("Cannot initialize security model.\n", stderr);
			goto done;
		}
	}


	/* Initialize and configure the workload. */
	INIT(NAAAIM, TSEMworkload, Workload, ERR(goto done));

	Workload->set_debug(Workload, Debug);
	if ( !Workload->configure_external(Workload, TSEM_model, Digest,     \
					   magazine_size, current_namespace, \
					   Enforce) )
		ERR(goto done);

	switch ( Mode ) {
		case container_mode:
			if ( !Workload->set_container_mode(Workload, 	     \
							   QUIXOTE_MAGAZINE, \
							   container) )
				ERR(goto done);
			break;

		case execute_mode:
			Workload->set_execute_mode(Workload, argc, argv);
			break;

		default:
			break;
	}

	if ( Debug )
		fprintf(Debug, "Launch process: %d\n", getpid());
	if ( !run_workload(Workload, container, outfile) )
		ERR(goto done);

	if ( outfile != NULL ) {
		if ( Trajectory )
			fputs("Wrote execution trajectory to: ", stdout);
		else
			fputs("Wrote security map to: ", stdout);
		fprintf(stdout, "%s\n", outfile);
	}


 done:
	WHACK(Aggregate);
	WHACK(Model);
	WHACK(Workload);

	if ( fd > 0 )
		close(fd);

	return retn;
}
