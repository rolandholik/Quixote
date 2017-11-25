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
#define SGX_DEVICE "/dev/isgx"
#define SGX_ENCLAVE "/lib/sgx-pcr.signed.so"

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <Buffer.h>
#include <LocalDuct.h>
#include <SHA256.h>

#include "../SGX/SGX.h"
#include "../SGX/SGXenclave.h"

#include "ContourPoint.h"
#include "ExchangeEvent.h"
#include "ISOidentity.h"
#include "cboot.h"


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
 * Event definitions.
 */
enum {
	measurement_event=1,
	exchange_event,
	aggregate_event,
	seal_event
} event_types;

struct event_definition {
	uint8_t event;
	char *syntax;
};

struct event_definition event_list[] = {
	{measurement_event,	"measurement "},
	{exchange_event,	"exchange "},
	{aggregate_event,	"aggregate "},
	{seal_event,		"seal"},
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
	 sgx
} Mode = internal;

/**
 * The following object is used to manage the measurement enclave
 * when running in SGX mode.
 */
SGXenclave Enclave = NULL;

/**
 * System call wrapper for setting the actor status of a process.
 */
static inline int sys_set_bad_actor(pid_t pid, unsigned long flags)
{
	return syscall(327, pid, flags);
}

/* Define the OCALL interface for the 'print string' call. */
struct ocall1_interface {
	char* str;
} ocall1_string;

int ocall1_handler(struct ocall1_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

static const struct OCALL_api ocall_table = {
	1, {ocall1_handler}
};


/* Define the ECALL interfaces .*/
static struct ecall0_table {
	uint8_t *buffer;
	size_t len;
} ecall0_table;

static struct ecall1_table {
	uint8_t *buffer;
	size_t len;
} ecall1_table;


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
 * This function is responsible for loading an SGX enclave
 * which will be used to hold the measurement status of the canister
 * which is being booted.
 *
 * \param token		A pointer to the SGX EINITTOKEN which will
 *			be used to initialize the measurement enclave.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not setup of the enclave succeeded.  A false
 *			value indicates there was a failure in the
 *			enclave setup, a true value indicates the enclave
 *			is ready to accept commands.
 */

static _Bool load_enclave(CO(char *, token))

{
	_Bool retn = false;

	struct SGX_einittoken *einit_token;

	Buffer tbufr = NULL;

	File token_file = NULL;


	/* Load the EINITTOKEN. */
	INIT(HurdLib, File, token_file, ERR(goto done));
	INIT(HurdLib, Buffer, tbufr, ERR(goto done));

	if ( !token_file->open_ro(token_file, token) )
		ERR(goto done);
	if ( !token_file->slurp(token_file, tbufr) )
		ERR(goto done);
	einit_token = (struct SGX_einittoken *) tbufr->get(tbufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SGXenclave, Enclave, ERR(goto done));

	if ( !Enclave->open_enclave(Enclave, SGX_DEVICE, SGX_ENCLAVE, true) )
		ERR(goto done);

	if ( !Enclave->create_enclave(Enclave) )
		ERR(goto done);

	if ( !Enclave->load_enclave(Enclave) )
		ERR(goto done);

	if ( !Enclave->init_enclave(Enclave, einit_token) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(tbufr);
	WHACK(token_file);

	return retn;
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

	int rc;

	Buffer bf,
	       input = NULL;

	SHA256 sha256 = NULL;


	/* Convert the ASCII measurement into a binary buffer. */
	INIT(HurdLib, Buffer, input, ERR(goto done));
	if ( !input->add_hexstring(input, bufr) )
		ERR(goto done);


	/* Update the enclave measurement if we are running in SGX mode. */
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
			if ( discipline > 0 )
				fprintf(stderr, "PID is disciplined: %d\n", \
					pid);
			else {
				fprintf(stderr, "PID not disciplined: %d, " \
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

	if ( !Model->set_aggregate(Model, aggregate) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(aggregate);

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

		case exchange_event:
			retn = add_event(p);
			break;

		case aggregate_event:
			retn = add_aggregate(p);
			break;

		case seal_event:
			fputs("Sealed domain.\n", stderr);
			Model->seal(Model);
			retn   = true;
			Sealed = true;
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
 * This function is responsible for issueing an ECALL to obtain the
 * current canister measurement state maintained in the enclave.
 *
 * \param bufr		The object which the measurement will be
 *			loaded into.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the measurement was properly returned.
 *			A false value indicates an error was
 *			encountered while retrieving the measurement.
 */

static _Bool get_enclave_measurement(CO(Buffer, bufr))
{
	_Bool retn = false;

	unsigned char inbufr[32];

	int rc;


	memset(inbufr, '\0', sizeof(inbufr));
	ecall1_table.len    = sizeof(inbufr);
	ecall1_table.buffer = (uint8_t *) inbufr;
	if ( !Enclave->boot_slot(Enclave, 1, &ocall_table, \
				 &ecall1_table, &rc) ) {
		fprintf(stderr, "Enclave returned: %d\n", rc);
		goto done;
	}

	if ( !bufr->add(bufr, inbufr, sizeof(inbufr)) )
		ERR(goto done);
	retn = true;


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
	cnt = Model->size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	fprintf(stderr, "Sent trajectory size: %zu\n", cnt);


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
	cnt = Model->forensics_size(Model);

	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !mgmt->send_Buffer(mgmt, cmdbufr) )
		ERR(goto done);
	fprintf(stderr, "Sent forensics size: %zu\n", cnt);


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
			if ( Mode == sgx )
				get_enclave_measurement(cmdbufr);
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
	}


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
	fprintf(stderr, "Update file: %s\n", fname);

	if ( (fd = open(fname, O_RDONLY)) < 0 )
		ERR(goto done);
	retn = true;


 done:
	if ( retn )
		*fdptr = fd;
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool connected = false;

	char *token	    = NULL,
	     *bundle	    = NULL,
	     *canister_name = NULL,
	     bufr[1024],
	     sockname[UNIX_PATH_MAX];

	int opt,
	    fd	 = 0,
	    retn = 1;

	pid_t canister_pid;

	struct pollfd poll_data[2];

	struct sigaction signal_action;

	Buffer cmdbufr = NULL;

	LocalDuct mgmt = NULL;


	while ( (opt = getopt(argc, argv, "Sb:n:t:")) != EOF )
		switch ( opt ) {
			case 'S':
				Mode = sgx;
				break;

			case 'b':
				bundle = optarg;
				break;

			case 'n':
				canister_name = optarg;
				break;

			case 't':
				token = optarg;
				break;
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
		if ( token == NULL ) {
			fputs("SGX mode but no token specified.\n", stderr);
			goto done;
		}

		if ( !load_enclave(token) ) {
			fputs("SGX enclave initialization failure.\n", stderr);
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


	/* Initialize the event objects. */
	INIT(NAAAIM, ISOidentity, Model, ERR(goto done));


	/* Poll for measurement and/or management requests. */
	poll_data[0].fd = fd;
	poll_data[0].events = POLLPRI;

	if ( !mgmt->get_socket(mgmt, &poll_data[1].fd) ) {
		fputs("Error setting up polling data.\n", stderr);
		goto done;
	}
	poll_data[1].events = POLLIN;


	/* Dispatch loop. */
	fputs("Calling loop\n", stderr);
	fprintf(stderr, "descriptor 1: %d, descriptor 2: %d\n", \
		poll_data[0].fd, poll_data[1].fd);

	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	opt = 0;
	while ( 1 ) {
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
			fputs("Poll timeout.\n", stderr);
			continue;
		}

		fprintf(stderr, "Events: %d, Data poll=%0x, Mgmt poll=%0x\n", \
			retn, poll_data[0].revents, poll_data[1].revents);

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
				fputs("Have socket connection.\n", stderr);
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
	WHACK(cmdbufr);
	WHACK(mgmt);
	WHACK(Enclave);
	WHACK(Model);

	if ( fd > 0 )
		close(fd);

	return retn;
}
