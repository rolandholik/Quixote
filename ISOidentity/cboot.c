/** \file
 *
 * This file implements a utility for running and managing a canister
 * in an independent measurement domain.  After creating an
 * independent measurement domain the utility forks and then executes
 * the boot of the canister in the subordinate process.  The parent
 * process monitors the following file:
 *
 * /sys/fs/iso-identity/update
 *
 * For measurement domain updates.
 *
 * The domain is managed through a UNIX domain socket which is created
 * in the following location:
 *
 * /var/run/cboot.PIDNUM
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define ENCLAVE_NAME	"/opt/IDfusion/lib/enclaves/ISOidentity.signed.so"
#define VERIFIERS	"/opt/IDfusion/etc/verifiers/ISOmanager/*.ivy"
#define CANISTERS	"/var/run/Canisters"

#define CLONE_BEHAVIOR 0x00001000

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <Buffer.h>
#include <LocalDuct.h>
#include <SHA256.h>
#include <IDtoken.h>

#include <SGX.h>
#include <ISOenclave.h>

#include "ContourPoint.h"
#include "ExchangeEvent.h"
#include "ISOidentity.h"
#include "cboot.h"


/**
 * Variable used to indicate whether canister is to run in debug mode.
 */
static _Bool Debug = false;


/**
 * The modeling object for the canister.
 */
static ISOidentity Model = NULL;

/**
 * The seal status of the encounter.  This variable is set by a
 * seal event from the canister.  Updates which are not in the
 * behavioral map will cause disciplining requests to be generated
 * for the canister.
 */
static _Bool Sealed = false;


/**
 * The following structure is used to define the arguements to be
 * passed to the thread which runs the management ECALL.
 */
struct manager_args {
	uint16_t port;
	char *spid;
	Buffer id;
};


/**
 * Event definitions.
 */
enum {
	measurement_event=1,
	contour_event,
	exchange_event,
	aggregate_event,
	seal_event,
	ai_event
} event_types;

struct event_definition {
	uint8_t event;
	char *syntax;
};

struct event_definition event_list[] = {
	{measurement_event,	"measurement "},
	{contour_event,		"contour "},
	{exchange_event,	"exchange "},
	{aggregate_event,	"aggregate "},
	{seal_event,		"seal"},
	{ai_event,		"ai_event "},
	{0, NULL}
};


/**
 * The following variable holds the current measurement.
 */
static unsigned char Measurement[32];

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
	 internal,
	 sgx,
	 measure,
	 show
} Mode = sgx;

/**
 * The following object is used to manage the measurement enclave
 * when running in SGX mode.
 */
static ISOenclave Enclave = NULL;

/**
 * System call wrapper for setting the actor status of a process.
 */
static inline int sys_set_bad_actor(pid_t pid, unsigned long flags)
{
	return syscall(327, pid, flags);
}


/**
 * Private function.
 *
 * This function implements loading of loading identifier verifiers
 * that will be used to specify the set of counter-parties that are
 * permitted access to the SGX management thread.  This function is
 * only called when the utility is running in SGX mode.
 *
 * If the identity verifier arguement is a NULL pointer this function
 * will attempt to load all verifiers from the following directory:
 *
 * /opt/IDfusion/etc/verifiers/ISOmanager
 *
 * \param enclave	The object representing the enclave that the
 *			identity verifiers were to be loaded into.
 *
 * \param infile	The object that will be used for doing I/O to
 *			the identity verifiers.
 *
 * \param verifier	A character pointer to the name of the file
 *			containing the specific identity verifier
 *			to use.  Otherwise the default set is
 *			loaded per the discussion above.
 *
 * \return		A boolean value is used to indicate the status
 *			of the verifier load.  A false value indicates
 *			an error was encounter while a true value
 *			indicates all of the identity verifiers were
 *			loaded.
 */

static _Bool add_verifiers(CO(ISOenclave, enclave), CO(File, infile), \
			   CO(char *, verifier))

{
	_Bool retn = false;

	glob_t identities;

	uint16_t lp;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	/* Load the specified verifier. */
	if ( verifier != NULL ) {
		infile->open_ro(infile, verifier);
		if ( !infile->slurp(infile, bufr) )
			ERR(goto done);

		if ( !enclave->add_verifier(enclave, bufr) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/* Load a verifier list. */
	if ( glob(VERIFIERS, 0, NULL, &identities) != 0 )
		ERR(goto done);
	if ( identities.gl_pathc == 0 )
		ERR(goto done);

	for (lp= 0; lp < identities.gl_pathc; ++lp) {
		infile->open_ro(infile, identities.gl_pathv[lp]);
		if ( !infile->slurp(infile, bufr) )
			ERR(goto done);

		if ( !enclave->add_verifier(enclave, bufr) )
			ERR(goto done);

		bufr->reset(bufr);
		infile->reset(infile);
	}

	retn = true;


 done:
	globfree(&identities);
	WHACK(bufr);

	return retn;
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

void signal_handler(int signal)

{
	switch ( signal ) {
		case SIGINT:
			Signals.stop = true;
			break;
		case SIGTERM:
			Signals.stop = true;
			break;
		case SIGHUP:
			Signals.stop = true;
			break;
		case SIGQUIT:
			Signals.stop = true;
			break;
		case SIGCHLD:
			Signals.sigchild = true;
			break;
	}

	return;
}


/**
 * Private function.
 *
 * This function implements checking for whether or not the canister
 * process has terminated.
 *
 * \param canister_pid	The pid of the canister.
 *
 *
 * \return		A boolean value is used to indicate whether
 *			or not the designed process has exited.  A
 *			false value indicates it has not while a
 *			true value indicates it has.
 */

static _Bool child_exited(const pid_t canister)

{
	int status;


	if ( waitpid(canister, &status, WNOHANG) != canister )
		return false;

	return true;
}


/**
 * Private function.
 *
 * This function carries out the addition of a measurement value
 * generated by the kernel to the current measurement state of the
 * canister.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the hexadecimally encoded measurement from
 *			the canister.
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

	SHA256 sha256 = NULL;


	/* Convert the ASCII measurement into a binary buffer. */
	INIT(HurdLib, Buffer, input, ERR(goto done));
	if ( !input->add_hexstring(input, bufr) )
		ERR(goto done);


	/* Update the enclave measurement if we are running in SGX mode. */
#if 0
	if ( Mode == sgx ) {
		ecall0_table.len    = input->size(input);
		ecall0_table.buffer = input->get(input);
		if ( !Enclave->boot_slot(Enclave, 0, &ocall_table, \
					 &ecall0_table, &rc) ) {
			fprintf(stderr, "Enclave returned: %d\n", rc);
			ERR(goto done);
		}

		retn = true;
		goto done;
	}
#endif


	/* Update the internal measurement. */
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

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
		fprintf(stderr, "Add measurement: %s\n", bufr);

	retn = true;


 done:
	WHACK(input);
	WHACK(sha256);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of a measurement value
 * generated by the kernel to the current measurement state of the
 * canister.
~ *
 * \param bufr		A pointer to the character buffer containing
 *			the hexadecimally encoded measurement from
 *			the canister.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the measurement succeeded.  A
 *			false value indicates the addition of the
 *			measurement failed while a true value indicates
 *			the measurement had succeeded.
 */

static _Bool add_contour(CO(char *, inbufr))

{
	_Bool retn = false;

	Buffer bufr = NULL;


	/* Convert the ASCII encoded contour point to binary. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !bufr->add_hexstring(bufr, inbufr) )
		ERR(goto done);
	if ( bufr->size(bufr) != NAAAIM_IDSIZE )
		ERR(goto done);


	/* Add the contour point to the model. */
	if ( Mode == internal ) {
		if ( !Model->update_map(Model, bufr) )
			ERR(goto done);
	}
	else {
		if ( !Enclave->update_map(Enclave, bufr) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the injection of an information exchange
 * event to a behavior model being implement in an SGX enclave.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII encoded information exchange event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not addition of the event succeeded.  A
 *			false value indicates the addition failed while
 *			a true value indicates the injection had
 &			succeeded.
 */

static _Bool add_sgx_event(CO(char *, inbufr))

{
	_Bool discipline,
	      retn = false;

	String update = NULL;


	INIT(HurdLib, String, update, ERR(goto done));
	if ( !update->add(update, inbufr) )
		ERR(goto done);


	if ( !Enclave->update(Enclave, update, &discipline) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(update);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of an information exchange
 * event to the current model behavior of a canister.
 *
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII encoded information exchange event.
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
	      retn = false;

	pid_t pid;

	String update = NULL;

	ExchangeEvent event = NULL;


	INIT(HurdLib, String, update, ERR(goto done));
	if ( !update->add(update, inbufr) )
		ERR(goto done);

	INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));
	if ( !event->parse(event, update) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);
	if ( !Model->update(Model, event, &status, &discipline) )
		ERR(goto done);

	/* Discipline process in the canister if needed. */
	if ( Sealed ) {
		if ( discipline ) {
			Model->discipline_pid(Model, &pid);
			discipline = sys_set_bad_actor(pid, 0);
			if (discipline < 0 ) {
				fprintf(stderr, "actor status error: %d:%s\n",\
					errno, strerror(errno));
			        retn = false;
				goto done;
			}
			if ( discipline > 0 ) {
				if ( Debug )
					fprintf(stderr, "PID is " \
						"disciplined: %d\n", pid);
			}
			else {
				if ( Debug )
					fprintf(stderr, "PID not "  \
						"disciplined: %d, " \
						"disciplining.\n", pid);
				discipline = sys_set_bad_actor(pid, 1);
				if ( discipline < 0 ) {
					fprintf(stderr, "actor status error:" \
						" %d:%s\n", errno, 	      \
						strerror(errno));
					retn = false;
					goto done;
				}
			}
		}
	}

	if ( !status )
		WHACK(event);
	retn = true;


 done:
	WHACK(update);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of the hardware aggregate
 * measurement to the current canister model behavior.
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

	Buffer aggregate = NULL;


	INIT(HurdLib, Buffer, aggregate, ERR(goto done));
	if ( !aggregate->add_hexstring(aggregate, inbufr) )
		ERR(goto done);

	if ( Debug ) {
		fputs("aggregate ", stderr);
		aggregate->print(aggregate);
	}

	if ( Mode == internal ) {
		if ( !Model->set_aggregate(Model, aggregate) )
			ERR(goto done);
	}
	else {
		if ( Debug )
			fputs("Setting enclave aggregate.\n", stderr);

		if ( !Enclave->set_aggregate(Enclave, aggregate) )
			ERR(goto done);
	}

	retn = true;


 done:
	WHACK(aggregate);

	return retn;
}


/**
 * Private function.
 *
 * This function carries out the addition of an autonomous introspection
 * event to the current canister model.
 *
 * \param ai_event	A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or addition of the event.  A false value indicates
 *			the addition failed while a true value indicates
 *			the addition succeeded.
 */

static _Bool add_ai_event(CO(char *, ai_event))

{
	_Bool retn = false;

	String event = NULL;


	INIT(HurdLib, String, event, ERR(goto done));
	event->add(event, ai_event);
	if ( Mode == internal ) {
		if ( !Model->add_ai_event(Model, event) )
			ERR(goto done);
	} else {
		if ( !Enclave->add_ai_event(Enclave, event) )
			ERR(goto done);
	}

	retn = true;


 done:

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
 * \param bufr		A pointer to the character buffer containing
 *			the ASCII encoded event.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the event was successful.  A
 *			false value indicates a failure in event
 *			processing while a true value indicates that
 *			event processing has succeeded.
 */

static _Bool process_event(char * bufr)

{
	_Bool retn = false;

	uint8_t event = 0;

	char *p;

	struct event_definition *ep;


	/* Remove the trailing newline from the command. */
	if ( (p = strchr(bufr, '\n')) == NULL )
		ERR(goto done);
	*p = '\0';


	/* Locate the event type. */
	for (ep= event_list; ep->syntax != NULL; ++ep) {
		if ( strncmp(ep->syntax, bufr, strlen(ep->syntax)) == 0 ) {
			p     = bufr + strlen(ep->syntax);
			event = ep->event;
		}
	}


	/* Dispatch the event. */
	switch ( event ) {
		case measurement_event:
			retn = add_measurement(p);
			break;

		case contour_event:
			retn = add_contour(p);
			break;

		case exchange_event:
			if ( Mode == internal )
				retn = add_event(p);
			else
				retn = add_sgx_event(p);
			break;

		case aggregate_event:
			retn = add_aggregate(p);
			break;

		case seal_event:
			if ( Debug )
				fputs("Sealed domain.\n", stderr);

			if ( Mode == internal ) {
				Model->seal(Model);
				retn   = true;
				Sealed = true;
			}
			else
				retn = Enclave->seal(Enclave);
			break;

		case ai_event:
			retn = add_ai_event(p);
			break;

		default:
			fprintf(stderr, "Unknown event: %s\n", bufr);
			break;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for returning the current trajectory
 * list to the caller.  The protocol used is to send the number of
 * elements in the list followed by each point as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
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

	ExchangeEvent event;

	String es = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	if ( Mode == internal )
		cnt = Model->size(Model);
	else
		cnt = Enclave->size(Enclave);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(stderr, "Sent trajectory size: %zu\n", cnt);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	if ( Mode == internal )
		Model->rewind_event(Model);
	else
		Enclave->rewind_event(Enclave);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( Mode == internal ) {
			if ( !Model->get_event(Model, &event) )
				ERR(goto done);
			if ( event == NULL )
				continue;
			if ( !event->format(event, es) )
				ERR(goto done);
		}
		else {
			if ( !Enclave->get_event(Enclave, es) )
				ERR(goto done);
		}

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
 *			the canister management instance.
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

	ExchangeEvent event;

	String es = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	if ( Mode == internal )
		cnt = Model->forensics_size(Model);
	else
		cnt = Enclave->forensics_size(Enclave);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(stderr, "Sent forensics size: %zu\n", cnt);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	if ( Mode == internal )
		Model->rewind_forensics(Model);
	else
		Enclave->rewind_forensics(Enclave);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( Mode == internal ) {
			if ( !Model->get_forensics(Model, &event) )
				ERR(goto done);
			if ( event == NULL )
				continue;
			if ( !event->format(event, es) )
				ERR(goto done);
		}
		else {
			if ( !Enclave->get_forensics(Enclave, es) )
				ERR(goto done);
		}

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
 * This function is responsible for returning the current behavioral
 * map to the caller.  The protocol used is to send the number of
 * elements in the map followed by each point in the map as a hexadecimal
 * ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
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

static _Bool send_contours(CO(LocalDuct, mgmt), CO(Buffer, cmdbufr))

{
	_Bool retn = false;

	uint8_t *p,
		 pi;

	char point[NAAAIM_IDSIZE * 2 + 1];

	size_t lp,
	       cnt = 0;

	ContourPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	if ( Mode == internal )
		cnt = Model->contours_size(Model);
	else
		cnt = Enclave->size(Enclave);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(stderr, "Sent contour size: %zu\n", cnt);


	/* Send each trajectory point. */
	if ( Mode == internal )
		Model->rewind_contours(Model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( Mode == internal ) {
			if ( !Model->get_contour(Model, &cp) )
				ERR(goto done);
			if ( cp == NULL )
				continue;
		}

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
 * AI events to the caller.  The protocol used is to send the number of
 * elements in the event list followed by each event as an ASCII string.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
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
	if ( Mode == internal )
		cnt = Model->ai_events_size(Model);
	else
		cnt = Enclave->size(Enclave);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	if ( Debug )
		fprintf(stderr, "Sent event size: %zu\n", cnt);


	/* Send each event. */
	if ( Mode == internal )
		Model->ai_rewind_event(Model);

	for (lp= 0; lp < cnt; ++lp) {
		if ( Mode == internal ) {
			if ( !Model->get_ai_event(Model, &event) )
				ERR(goto done);
			if ( event == NULL )
				continue;
		}

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) event->get(event), \
			     event->size(event));
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
 * This function implements the processing of a command from the
 * canister management utility.  This command comes in the form
 * of a binary encoding of the desired command to be run.
 *
 * \param mgmt		The socket object used to communicate with
 *			the canister management instance.
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

	int *cp;


	if ( cmdbufr->size(cmdbufr) != sizeof(int) )
		ERR(goto done);

	cp = (int *) cmdbufr->get(cmdbufr);
	switch ( *cp ) {
		case show_measurement:
			cmdbufr->reset(cmdbufr);
			if ( Mode == sgx ) {
				if ( !Enclave->get_measurement(Enclave, \
							       cmdbufr) )
					ERR(goto done);
			}
			else
				if ( !Model->get_measurement(Model, cmdbufr) )
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

		case show_contours:
			retn = send_contours(mgmt, cmdbufr);
			break;

		case show_events:
			retn = send_events(mgmt, cmdbufr);
			break;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function implements the initialization of a behavioral map
 * for the canister being executed.
 *
 * \param mapfile	The name of the file containing the behavioral
 *			model.  The model is expected to consist of
 *			model events.
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

static _Bool initialize_model(char *mapfile)

{
	_Bool retn = false;

	char inbufr[256];

	FILE *bmap = NULL;


	/* Open the behavioral map and initialize the binary point object. */
	if ( (bmap = fopen(mapfile, "r")) == NULL )
		ERR(goto done);


	/* Loop over the mapfile. */
	while ( fgets(inbufr, sizeof(inbufr), bmap) != NULL ) {
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
 *			file descriptor for the canister measurement
 *			file.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the the creation of the namespace was
 *			successful.  A false value indicates setup of
 *			the namespace was unsuccessful while a true
 *			value indicates the namespace is setup and
 *			ready to be measured.
 */

static _Bool setup_namespace(int *fdptr)

{
	_Bool retn = false;

	char fname[PATH_MAX];

	int fd;

	struct stat statbuf;


	if ( unshare(CLONE_BEHAVIOR) < 0 ) {
		perror("Unsharing behavior domain");
		ERR(goto done);
	}

	if ( stat("/proc/self/ns/behavior", &statbuf) < 0 )
		ERR(goto done);

	memset(fname, '\0', sizeof(fname));
	if ( snprintf(fname, sizeof(fname), "/sys/fs/iso-identity/update-%u", \
		      (unsigned int) statbuf.st_ino) >= sizeof(fname) )
		ERR(goto done);
	if ( Debug )
		fprintf(stderr, "Update file: %s\n", fname);

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
 * This function is a wrapper function which is the target of the
 * thread that will be started to run the ISOidentity model manager.
 *
 * \param mgr_args	The pointer to the structure containing the
 *			arguements for the manager.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the invoication of the manager was
 *			successful.  A false value indicates there was
 *			an error in starting the manager thread.  A
 *			true value indicates that it executed successfully.
 */

static void * sgx_mgr(void *mgr_args)

{
	struct manager_args *args = mgr_args;


	if ( !Enclave->manager(Enclave, args->id, args->port, args->spid) )
		ERR(goto done);


 done:
	pthread_exit(NULL);
}


/**
 * Private function.
 *
 * This function implements the measurement mode of the cboot utility.
 * Measurement mode generates a software attestation value for the
 * enclave specific to the host it is run on.
 *
 * \param enclave_name	A pointer to a character buffer containing the
 *			name of the enclave to be loaded.
 *
 * \param token		A pointer to a character buffer containing the
 *			name of the file holding the launch token for
 *			the enclave.
 *
 * \return		This function exits the program with a status
 *			code indicating whether or not generation
 *			of the measurement succeeded.  A non-zero value
 *			indicates an error was encountered while a
 *			zero return value indicates the measurement
 *			was succesfully generated.
 */

static void * measurement_mode(CO(char *, enclave_name), CO(char *, token))

{
	int retn = 1;

	Buffer bufr = NULL;


	INIT(NAAAIM, ISOenclave, Enclave, ERR(goto done));
	if ( !Enclave->load_enclave(Enclave, enclave_name, token) ) {
		fputs("Enclave measurement initialization failure.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !Enclave->generate_identity(Enclave, bufr) ) {
		fputs("Error generating enclave measurement.\n", stderr);
		goto done;
	}

	bufr->print(bufr);
	retn = 0;


 done:
	WHACK(Enclave);
	WHACK(bufr);

	exit(retn);
}


/**
 * Private function.
 *
 * This function implements the show mode of the cboot utility.
 * This mode displays the set of Canisters that are currently
 * provisioned on the host.
 *
 * \param root	A pointer to the buffer containing the root directory
 *		to be used to display the canisters.
 *
 * \return	This function exits the program with a status code
 *		indicating whether or not the generation of the
 *		canister list was successful.  A non-zero return value
 *		indicates an error was encountered while a return
 *		value of zero indicates the list was successfully
 *		generated.
 */

static void * show_mode(CO(char *, root))

{
	char *p;

	int retn = 1;

	uint16_t lp;

	glob_t canisters;

	String str = NULL;


	/* Generate the list of canisters. */
	INIT(HurdLib, String, str, ERR(goto done));
	str->add(str, root);
	if ( !str->add(str, "/*") )
		ERR(goto done);

	if ( glob(str->get(str), 0, NULL, &canisters) != 0 ) {
		fprintf(stderr, "Failed read of canister directory: %s\n", \
			root);
		goto done;
	}
	if ( canisters.gl_pathc == 0 ) {
		fputs("No canisters found:\n", stderr);
		goto done;
	}


	/* Iterate through and print the canisters found .*/
	fprintf(stdout, "%s:\n", root);
	for (lp= 0; lp < canisters.gl_pathc; ++lp) {
		str->reset(str);
		if ( !str->add(str, canisters.gl_pathv[lp]) ) {
			fputs("Error processing canister list\n", stderr);
			goto done;
		}

		p = str->get(str);
		if ( (p = strrchr(str->get(str), '/')) == NULL )
			p = str->get(str);
		else
			++p;
		fprintf(stdout, "%s\n", p);
	}

	retn = 0;


 done:
	globfree(&canisters);
	WHACK(str);

	exit(retn);
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool connected = false;

	char *bundle	    = NULL,
	     *canister	    = NULL,
	     *canister_name = NULL,
	     *verifier	    = NULL,
	     *map	    = NULL,
	     *port	    = "11990",
	     *id_token	    = "/opt/IDfusion/etc/host.idt",
	     *spid_fname    = SPID_FILENAME,
	     *token	    = SGX_TOKEN_DIRECTORY"/ISOidentity.token",
	     *enclave_name  = ENCLAVE_NAME,
	     bufr[1024],
	     sockname[UNIX_PATH_MAX];


	int opt,
	    fd	 = 0,
	    retn = 1;

	pid_t canister_pid;

	FILE *idfile = NULL;

	struct manager_args mgr_args;

	struct pollfd poll_data[2];

	struct sigaction signal_action;

	pthread_attr_t mgr_attr;

	pthread_t mgr_thread;

	Buffer ivy     = NULL,
	       id_bufr = NULL,
	       cmdbufr = NULL;

	String spid	    = NULL,
	       canister_dir = NULL;

	LocalDuct mgmt = NULL;

	IDtoken idt = NULL;

	File infile = NULL;


	while ( (opt = getopt(argc, argv, "LMSdb:c:e:i:m:n:p:s:t:v:")) != EOF )
		switch ( opt ) {
			case 'L':
				Mode = internal;
				break;
			case 'M':
				Mode = measure;
				break;
			case 'S':
				Mode = show;
				break;
			case 'd':
				Debug = true;
				break;

			case 'b':
				bundle = optarg;
				break;
			case 'c':
				canister = optarg;
				break;
			case 'e':
				enclave_name = optarg;
				break;
			case 'i':
				id_token = optarg;
				break;
			case 'm':
				map = optarg;
				break;
			case 'n':
				canister_name = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 's':
				spid_fname = optarg;
				break;
			case 't':
				token = optarg;
				break;
			case 'v':
				verifier = optarg;
				break;
		}


	/* Execute measurement mode. */
	if ( Mode == measure )
		measurement_mode(enclave_name, token);


	/* Execute canister display mode. */
	if ( Mode == show )
		show_mode(CANISTERS);


	/*
	 * If this is a canister invocation setup the name of the
	 * budle directory and the canister name.
	 */
	if ( canister != NULL ) {
		if ( canister_name == NULL )
			canister_name = canister;

		INIT(HurdLib, String, canister_dir, ERR(goto done));
		canister_dir->add(canister_dir, CANISTERS);
		canister_dir->add(canister_dir, "/");
		if ( !canister_dir->add(canister_dir, canister) ) {
			fputs("Unable to setup canister location.\n", stderr);
			goto done;
		}

		bundle = canister_dir->get(canister_dir);
	}


	/* Verify we have a canister name. */
	if ( canister_name == NULL ) {
		fputs("No canister name specified.\n", stderr);
		goto done;
	}


	/* Setup signal handlers. */
	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		ERR(goto done);

	signal_action.sa_flags = 0;
	signal_action.sa_handler = signal_handler;
	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGTERM, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGHUP, &signal_action, NULL) == -1 )
		goto done;
	if ( sigaction(SIGQUIT, &signal_action, NULL) == -1 )
		goto done;


	/* Setup measurement enclave if SGX is being used. */
	if ( Mode == sgx ) {
		if ( id_token == NULL ) {
			fputs("SGX mode but no identity token specified.\n", \

			      stderr);
			goto done;
		}

		INIT(NAAAIM, ISOenclave, Enclave, ERR(goto done));
		if ( !Enclave->load_enclave(Enclave, enclave_name, token) ) {
			fputs("SGX enclave initialization failure.\n", stderr);
			goto done;
		}

		if ( Debug )
			Enclave->debug(Enclave, true);

		/* Load the identity token. */
		INIT(NAAAIM, IDtoken, idt, goto done);
		if ( (idfile = fopen(id_token, "r")) == NULL ) {
			fputs("Cannot open identity token file.\n", stderr);
			goto done;
		}
		if ( !idt->parse(idt, idfile) ) {
			fputs("Enable to parse identity token.\n", stderr);
			goto done;
		}

		INIT(HurdLib, Buffer, id_bufr, ERR(goto done));
		if ( !idt->encode(idt, id_bufr) ) {
			fputs("Error encoding identity token.\n", stderr);
			goto done;
		}

		/* Load the identifier verifiers. */
		INIT(HurdLib, File, infile, ERR(goto done));
		if ( !add_verifiers(Enclave, infile, verifier) ) {
			fputs("Unable to load identity verifiers.\n", stderr);
			goto done;
		}

		/* Setup the SPID key. */
		INIT(HurdLib, String, spid, ERR(goto done));

		infile->reset(infile);
		if ( !infile->open_ro(infile, spid_fname) )
			ERR(goto done);
		if ( !infile->read_String(infile, spid) )
			ERR(goto done);

		if ( spid->size(spid) != 32 ) {
			fputs("Invalid SPID size: ", stdout);
			spid->print(spid);
			goto done;
		}


		/* Start SGX manager thread. */
		if ( pthread_attr_init(&mgr_attr) != 0 ) {
			fputs("Unable to initialize thread attributes.\n", \
			      stderr);
			goto done;
		}

		mgr_args.spid = spid->get(spid);
		mgr_args.id   = id_bufr;

		mgr_args.port = strtol(port, NULL, 0);
		if ( (errno == ERANGE) || (errno == EINVAL) ) {
			fputs("Error in port specification.\n", stderr);
			goto done;
		}
		if ( (mgr_args.port < 0) || (mgr_args.port > UINT16_MAX)) {
			fputs("Invalid port number specified.\n", stderr);
			goto done;
		}

		if ( pthread_create(&mgr_thread, &mgr_attr, sgx_mgr, \
				    &mgr_args) != 0 ) {
			fputs("Cannot start SGX manager thread.\n", stderr);
			goto done;
		}
	}


	/* Load and seal the behavioral map. */
	INIT(NAAAIM, ISOidentity, Model, ERR(goto done));

	if ( map != NULL ) {
		if ( !initialize_model(map) ) {
			fputs("Cannot initialize behavioral map.\n", stderr);
			goto done;
		}
	}


	/* Setup the management socket. */
	if ( snprintf(sockname, sizeof(sockname), "%s.%s", SOCKNAME, \
		      canister_name) >= sizeof(sockname) ) {
		fputs("Socket name overflow.\n", stderr);
		goto done;
	}

	if ( (mgmt = NAAAIM_LocalDuct_Init()) == NULL ) {
		fputs("Error creating management socket.\n", stderr);
		goto done;
	}

	if ( !mgmt->init_server(mgmt) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	if ( !mgmt->init_port(mgmt, sockname) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}


	/* Setup the behavior namespace. */
	if ( !setup_namespace(&fd) )
		ERR(goto done);


	/*
	 * At this point in time we will create a subordinate process
	 * from which we will start the canister.
	 */
	canister_pid = fork();
	if ( canister_pid == -1 ) {
		fputs("Error creating canister process.\n", stderr);
		goto done;
	}


	/* Child process - start the canister process. */
	if ( canister_pid == 0 ) {
		close(fd);
		mgmt->get_socket(mgmt, &fd);
		close(fd);


		if ( bundle == NULL )
			execlp("runc", "runc", "run", canister_name, NULL);
		else
			execlp("runc", "runc", "run", "-b", bundle, \
			       canister_name, NULL);

		fputs("Canister execution failed.\n", stderr);
		exit(1);
	}


	/*
	 * Parent process - install a SIGCHLD handler to monitor for
	 * canister exit.
	 */
	if ( sigaction(SIGCHLD, &signal_action, NULL) == -1 )
		goto done;


	/* Poll for measurement and/or management requests. */
	poll_data[0].fd = fd;
	poll_data[0].events = POLLPRI;

	if ( !mgmt->get_socket(mgmt, &poll_data[1].fd) ) {
		fputs("Error setting up polling data.\n", stderr);
		goto done;
	}
	poll_data[1].events = POLLIN;


	/* Dispatch loop. */
	if ( Debug ) {
		fputs("Calling event loop\n", stderr);
		fprintf(stderr, "descriptor 1: %d, descriptor 2: %d\n", \
		poll_data[0].fd, poll_data[1].fd);
	}

	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	opt = 0;
	while ( 1 ) {
		if ( Debug )
			fprintf(stderr, "Poll cycle: %d\n", ++opt);

		retn = poll(poll_data, 2, -1);
		if ( retn < 0 ) {
			if ( Signals.stop )
				break;
			if ( Signals.sigchild ) {
				if ( !child_exited(canister_pid) )
					continue;
				fputs("Canister exited.\n", stdout);
				goto done;
			}
			fprintf(stderr, "Poll error: cause=%s\n", \
				strerror(errno));
			goto done;
		}
		if ( retn == 0 ) {
			if ( Debug )
				fputs("Poll timeout.\n", stderr);
			continue;
		}

		if ( Debug )
			fprintf(stderr, "Events: %d, Data poll=%0x, "	\
				"Mgmt poll=%0x\n", retn,		\
				poll_data[0].revents, poll_data[1].revents);

		if ( poll_data[0].revents & POLLPRI ) {
			while ( 1 ) {
				memset(bufr, '\0', sizeof(bufr));
				retn = read(fd, bufr, sizeof(bufr));
				if ( retn < 0 ) {
					if ( errno != ENODATA )
						fprintf(stderr, "Have "	    \
							"error: retn=%d, "  \
							"error=%s\n", retn, \
							strerror(errno));
					break;
				}

				if ( process_event(bufr) ) {
					if ( lseek(fd, 0, SEEK_SET) < 0 ) {
						fputs("Seek error.\n", stderr);
						break;
					}
				}
				else
					ERR(goto done);
			}
		}

		if ( poll_data[1].revents & POLLIN ) {
			if ( !connected ) {
				if ( Debug )
					fputs("Have socket connection.\n", \
					      stderr);

				if ( !mgmt->accept_connection(mgmt) )
					ERR(goto done);
				if ( !mgmt->get_fd(mgmt, &poll_data[1].fd) )
					ERR(goto done);
				poll_data[1].events = POLLIN;
				connected = true;
				continue;
			}
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) )
				continue;
			if ( mgmt->eof(mgmt) ) {
				if ( Debug )
					fputs("Terminating management.\n", \
					      stderr);
				mgmt->reset(mgmt);
				if ( !mgmt->get_socket(mgmt, \
						       &poll_data[1].fd) )
					ERR(goto done);
				poll_data[1].events = POLLIN;
				connected = false;
				continue;
			}

			if ( !process_command(mgmt, cmdbufr) )
				ERR(goto done);
			cmdbufr->reset(cmdbufr);
		}
	}


 done:
	WHACK(ivy);
	WHACK(id_bufr);
	WHACK(cmdbufr);
	WHACK(spid);
	WHACK(canister_dir);
	WHACK(mgmt);
	WHACK(idt);
	WHACK(infile);

	WHACK(Enclave);
	WHACK(Model);

	if ( fd > 0 )
		close(fd);

	return retn;
}
