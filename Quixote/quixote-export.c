/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in an independent security namespace domain with export of
 * the security state events to userspace.  The primary purpose
 * of this orchestrator is to provide a mechanism for driving machine
 * learning baed security models.
 *
 * As with the other userspace orchestrator the security events
 * are exported through the following pseudo-file:
 *
 * /sys/kernel/security/tsem/ExternalTMA/update-NNNNNNNNNN
 *
 * Where NNNNNNNNNN is the id number of the security event modeling
 * namespace.
 */

/**************************************************************************
 * Copyright (c) 2023, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#define READ_SIDE  0
#define WRITE_SIDE 1

#define TSEM_ROOT_EXPORT "/sys/kernel/security/tsem/external_tma/0"

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
#include <pwd.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <linux/un.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>
#include <Gaggle.h>
#include <Process.h>

#include "quixote.h"
#include "sancho-cmd.h"

#include "NAAAIM.h"
#include "TTYduct.h"
#include "LocalDuct.h"
#include "MQTTduct.h"
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
 * The process id of the cartridge monitor process.
 */
static pid_t Monitor_pid;

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

/**
 * The object that will be used for parsing the TSEM events.
 */
static TSEMevent Event = NULL;

/**
 * The alternate TSEM model that is to be used.
 */
static char *TSEM_model = NULL;

/**
 * The number of event descriptions that are queued.
 */
static size_t Queued = 0;

/**
 * The objects used to write the output.
 */
static File Output_File	    = NULL;
static MQTTduct MQTT	    = NULL;
static String Output_String = NULL;

/**
 * Object used to manage invocation of a specific command in execute mode.
 */
static Process Execute = NULL;


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
	 root_mode,
	 process_mode,
	 container_mode,
	 execute_mode
} Mode = container_mode;


/**
 * Private function.
 *
 * This function is responsible for outputting a single event description.
 *
 * \param event	The object containing the object that contains the event
 *		to be output.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		processing of the event ouput was successful.  A false
 *		value indicates a failure in output while a true value
 *		indicates that output was successful.
 */

static _Bool output_event(CO(TSEMevent, event))

{
	_Bool retn = false;


	Output_String->reset(Output_String);
	if ( !Output_String->add(Output_String, event->get_event(event)) )
		ERR(goto done);
	if ( !Output_String->add(Output_String, "\n") )
			ERR(goto done);

	if ( MQTT != NULL ) {
		if ( !MQTT->send_String(MQTT, Output_String) )
			ERR(goto done);
	}

	if ( Output_File != NULL ) {
		if ( !Output_File->write_String(Output_File, Output_String) )
			ERR(goto done);
	}

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


/** Private function.
 *
 * This function is responsible for opening an output file which the
 * security events will be written to.  The file is truncated so each
 * invocation of the utility results in a collection of events for
 * only that execution of the utility.
 *
 * \param outfile	A null-terminated buffer containing the name of
 *			the output file.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		opening of the file succeeded.  A false value indicates
 *		a failure while a true value indicates the open
 *		succeeded.
 */

static _Bool open_file(CO(char *, outfile))

{
	_Bool retn = false;

	if ( strcmp(outfile, "/dev/stdout") != 0 )
		truncate(outfile, 0);

	INIT(HurdLib, File, Output_File, ERR(goto done));
	if ( Output_File->open_rw(Output_File, outfile) )
		retn = true;


 done:
	return retn;
}


/** Private function.
 *
 * This function is responsible for opening a connection to an MQTT
 * broker that the security events will be forwarded to.
 *
 * \param broker	A null-terminated buffer containing the hostname
 *			of the broker.
 *
 * \param port		A null-terminated buffer containing the ASCII
 *			representation of the numeric port value that
 *			is to be used for the connection.
 *
 * \param user		A null-terminated buffer containing the name of
 *			the user to be used for authenticating to the
 *			broker.
 *
 * \param topic		A null-terminated buffer containing the name of
 *			topic that the connection is to be subscribed to.
 *
 * \return	A boolean value is used to indicate whether or establishing
 *		of the connection succeeded.  A false value indicates a
 *		failure while a true value indicates the connection has
 *		been established and is operational.
 */

static _Bool open_broker(CO(char *, broker), CO(char *, port), \
			 CO(char *, user), CO(char *, topic))

{
	_Bool retn = false;

	int port_num;


	port_num = strtol(port == NULL ? "1883" : port , NULL, 0);
	if ( errno == ERANGE )
		goto done;

	INIT(NAAAIM, MQTTduct, MQTT, ERR(goto done));
	if ( !MQTT->set_password(MQTT, NULL) )
		ERR(goto done);
	if ( !MQTT->init_publisher(MQTT, broker, port_num, topic, user, \
				   NULL) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for running a workload in a security
 * modeling namespace with output of the events into the file specified
 * as an argument to this function.
 *
 * \param workload	The object describing the workload environment
 *			that is to be executed.

 * \param outfile	A pointer to a null-terminated character buffer
 *			containing the name of the file that the security
 *			event descriptions are to be written to.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the workload launch.  A false value indicates an error was
 *		encountered while a true value indicates the workload
 *		was successfully run.
 */

static _Bool run_workload(CO(TSEMworkload, workload), CO(char *, outfile))

{
	_Bool retn = false;

	pid_t workload_pid;

	String cartridge_dir = NULL;


	/* Create the workload process process. */
	workload_pid = fork();
	if ( workload_pid == -1 )
		ERR(goto done);

	/* Parent process - Security Monitor. */
	if ( workload_pid > 0 ) {
		if ( !open_file(outfile) )
			ERR(goto done);

		if ( !workload->run_monitor(workload, workload_pid, NULL, \
					    output_event) )
			ERR(goto done);
		retn = true;
		goto done;
	}

	/* Child process - workload process. */
	if ( !workload->run_workload(workload) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(cartridge_dir);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for launching a workload in an
 * independent security modeling namespace that has the events exported
 * by that namespace through an MQTT broker.  The functionality of this
 * function is identical to the fire_cartridge() function with the
 * exception that this function initializes the MQTT client in the
 * context of the monitor process.
 *
 * \param cartridge	A pointer to the name of the runc based
 *			container to execute.
 *
 * \param argc		The number of command-line arguments specified
 *			for the execution of the security namespace.
 *
 * \param argv		A pointer to the array of strings describing
 *			the command-line arguements.  This variable and
 *			the argc value are used if the export utility
 *			has been running in execute mode.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the launch.  A false value indicates an error was
 *		encountered while a true value indicates the cartridge
 *		was successfully launched.
 */

static _Bool run_broker_workload(CO(TSEMworkload, workload),		\
				 CO(char *, broker), CO(char *, port),	\
				 CO(char *, tsem_user), CO(char *, topic))

{
	_Bool retn = false;

	pid_t workload_pid;


	workload_pid = fork();
	if ( workload_pid == -1 )
		ERR(goto done);

	/* Security monitor parent process. */
	if ( workload_pid > 0 ) {
		if ( Debug )
			fprintf(Debug, "SM process: %d\n", getpid());

		if ( !open_broker(broker, port, tsem_user, topic) )
			ERR(goto done);

		if ( !workload->run_monitor(workload, workload_pid, NULL, \
					    output_event) )
			ERR(goto done);

		retn = true;
		goto done;
	}

	/* Child process - run the workload and export events. */
	if ( !workload->run_workload(workload) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Private helper function.
 *
 * This function is a helper function for the export_root function.  This
 * function reads a single event description and loads it into the
 * supplied TSEMevent object.
 *
 * \param fd		The file descriptor of the pseudo-file from which
 *			the event description is to be read.
 *
 * \param output	The object that is used to queue the event
 *			descriptions that are to be output.
 *
 * \param nodata	A pointer to a boolean variable that will be
 *			used to indicate whether or not the end of the
 *			current events had been reached.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the read.  A false value indicates an error was
 *		encountered while a true value indicates the output
 *		structure was populated with an event.
 */

static _Bool _get_event(const int fd, CO(Gaggle, output), _Bool *nodata)

{
	_Bool retn = false;

	char bufr[PAGE_SIZE + 1];

	int rc;

	String str;


	memset(bufr, '\0', sizeof(bufr));

	rc = read(fd, bufr, sizeof(bufr));
	if ( Signals.stop || (rc == 0) ) {
		retn = true;
		goto done;
	}

	if ( rc > 0 ) {
		str = GGET(output, str);
		str->reset(str);
		if ( !str->add(str, bufr) )
			ERR(goto done);

		if ( Debug )
			fprintf(Debug, "Queuing %lu/%lu.\n", Queued, \
				output->size(output));
		++Queued;
		retn = true;
	} else {
		if ( errno == ENODATA ) {
			*nodata = true;
			retn = true;
		}
	}


 done:
	if ( lseek(fd, 0, SEEK_SET) < 0 )
		ERR(goto done);

	return retn;
}


/**
 * Private helper function.
 *
 * This function traverses the output object and sends each description
 * to the designated output.
 *
 * \param output	The object containing the set of events to
 *			be output.
 *
 * \return	A boolean value is used indicate whether or not the
 *		output succeeded.  A false value indicates an error
 *		occurred while a true value indicates that all of the
 *		events were sent.
 */

static _Bool _output_events(CO(Gaggle, output))

{
	_Bool retn = false;

	size_t lp;

	String str;


	output->rewind_cursor(output);
	if ( Debug )
		fputs("Flushing output queue.\n", Debug);

	if ( MQTT != NULL ) {
		Output_String->reset(Output_String);
		for (lp= 0; lp < Queued; ++lp) {
			str = GGET(output, str);
			if ( !Output_String->add(Output_String, \
						 str->get(str)) )
				ERR(goto done);
		}
		if ( !MQTT->send_String(MQTT, Output_String) )
			ERR(goto done);
	}

	if ( Output_File != NULL ) {
		for (lp= 0; lp < Queued; ++lp) {
			str = GGET(output, str);
			if ( !Output_File->write_String(Output_File, str) )
				ERR(goto done);
		}
	}

	Queued = 0;
	retn = true;
	output->rewind_cursor(output);


  done:
	return retn;
}


/**
 * Private helper function.
 *
 * This function is a helper function for the export_root function.  This
 * function reads and outputs all of the oustanding events that are
 * available.
 *
 * \param fd		The file descriptor of the pseudo-file from which
 *			the event descriptions are to be read.
 *
 * \param output	The object that is used to hold the event
 *			entries.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the exports.  A false value indicates an error was
 *		encountered while a true value indicates the currently
 *		available events have been exported.
 */

static _Bool _export_events(const int fd, CO(Gaggle, output))

{
	_Bool retn   = false,
	      nodata = false;


	/* Output events until the end of the event list is met. */
	while ( true ) {
		if ( !_get_event(fd, output, &nodata) )
			ERR(goto done);

		if ( nodata ) {
			retn = true;
			break;
		}

		if ( Queued == output->size(output) ) {
			if ( !_output_events(output) )
				ERR(goto done);
		}
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for driving the export of events from
 * the root security modeling namespace.
 *
 * \param follow	A boolean value used to indicate whether or
 *			not the the security events should be tracked
 *			after the current queue is read.
 *
 * \param queue_size	A pointer to a null-terminated buffer containing
 *			the string representation of the size of the
 *			queue of events to be implemented for output.
 *
 * \param outfile	A pointer to a null-terminated character buffer
 *			containing the name of the output file if file
 *			based output is requested.
 *
 * \param broker	A null-terminated buffer containing the hostname
 *			of the broker.
 *
 * \param port		A null-terminated buffer containing the ASCII
 *			representation of the numeric port value that
 *			is to be used for the connection.
 *
 * \param user		A null-terminated buffer containing the name of
 *			the user to be used for authenticating to the
 *			broker.
 *
 * \param topic		A null-terminated buffer containing the name of
 *			topic that the connection is to be subscribed to.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the the configuration and export of the root security
 *		modeling namespace.  A false value indicates it failed
 *		while a true value indicates that the export had
 *		concluded successfully.
 */

static _Bool export_root(const _Bool follow, CO(char *, queue_size),	\
			 CO(char *, outfile), CO(char *, broker),	\
			 CO(char *, port), CO(char *, user), CO(char*, topic))

{
	_Bool retn = false;

	int rc,
	    fd;

	unsigned int lp;

	long int queue_length;

	unsigned int cycle = 0;

	struct pollfd poll_data[1];

	String str;

	Gaggle output = NULL;


	/* Open the output file if file based output is requested. */
	if ( outfile != NULL ) {
		if ( Debug )
			fprintf(Debug, "Root export to file: %s\n", outfile);
		if ( !open_file(outfile) )
			ERR(goto done);
	}

	/* Open the broker if MQTT output is requested. */
	if ( broker != NULL ) {
		if ( Debug )
			fprintf(Debug, "Root export to broker: %s\n", broker);
		if ( !open_broker(broker, port, user, topic) )
			ERR(goto done);
	}

	/* Open the root export file. */
	if ( (fd = open(TSEM_ROOT_EXPORT, O_RDONLY)) < 0 )
		ERR(goto done);

	/* Establish the queue size. */
	queue_length = strtol(queue_size, NULL, 0);
	if ( errno == ERANGE )
		goto done;

	/* Initialize output queue. */
	INIT(HurdLib, Gaggle, output, ERR(goto done));
	for (lp= 0; lp < queue_length; ++lp) {
		INIT(HurdLib, String, str, ERR(goto done));
		if ( !GADD(output, str) )
			ERR(goto done);
	}

	/* Output entries that have been queued. */
	if ( !_export_events(fd, output) )
		ERR(goto done);

	if ( !_output_events(output) )
		ERR(goto done);

	if ( !follow ) {
		retn = true;
		goto done;
	}

	/* Output events as they are generated.. */
	if ( Debug )
		fprintf(Debug, "%d: Running root event loop.\n", getpid());

	poll_data[0].fd	    = fd;
	poll_data[0].events = POLLIN;

	while ( 1 ) {
		if ( Debug )
			fprintf(Debug, "\n%d: Poll cycle: %d\n", getpid(), \
				++cycle);

		rc = poll(poll_data, 1, -1);
		if ( rc < 0 ) {
			if ( Signals.stop ) {
				if ( Debug )
					fputs("Quixote terminated.\n", Debug);
				retn = true;
				goto done;
			}
			ERR(goto done);
		}

		if ( Debug )
			fprintf(Debug, "Poll retn=%d, Data poll=%0x\n", \
				rc, poll_data[0].revents);

		if ( poll_data[0].revents & POLLIN ) {
			if ( !_export_events(fd, output) )
				ERR(goto done);
		}
	}


 done:
	GWHACK(output, String);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool follow = false;

	char *debug	    = NULL,
	     *broker	    = NULL,
	     *topic	    = NULL,
	     *port	    = NULL,
	     *cartridge	    = NULL,
	     *magazine_size = NULL,
	     *outfile	    = NULL,
	     *queue_size    = "100",
	     *tsem_user	    = "tsem";

	int opt,
	    retn = 1;

	TSEMworkload workload = NULL;


	while ( (opt = getopt(argc, argv, "CPRSXfuM:b:c:d:h:n:o:p:q:s:t:")) \
		!= EOF )
		switch ( opt ) {
			case 'C':
				Mode = container_mode;
				break;
			case 'P':
				Mode = process_mode;
				break;
			case 'R':
				Mode = root_mode;
				break;
			case 'S':
				Mode = show_mode;
				break;
			case 'X':
				Mode = execute_mode;
				break;

			case 'f':
				follow = true;
				break;
			case 'u':
				Current_Namespace = true;
				break;

			case 'M':
				TSEM_model = optarg;
				break;

			case 'b':
				broker = optarg;
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
			case 'n':
				magazine_size = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'q':
				queue_size = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 't':
				topic = optarg;
				break;
		}


	/* We need an output file. */
	if ( (outfile == NULL) && (broker == NULL) ) {
		fputs("No output method specified.\n", stderr);
		goto done;
	}

	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( (Mode == container_mode) && (cartridge == NULL) ) {
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

	/* Handle output to a file. */

	/* Initialize the TSEM workload manager object. */
	INIT(NAAAIM, TSEMworkload, workload, ERR(goto done));
	INIT(HurdLib, String, Output_String, ERR(goto done));

	workload->set_debug(workload, Debug);
	if ( !workload->configure_export(workload, TSEM_model, Digest, \
					 magazine_size, Current_Namespace) )
		ERR(goto done);

	switch ( Mode ) {
		case container_mode:
			if ( !workload->set_container_mode(workload, 	     \
							   QUIXOTE_MAGAZINE, \
							   cartridge) )
				ERR(goto done);
			break;

		case execute_mode:
			workload->set_execute_mode(workload, argc, argv);
			break;

		case root_mode:
			if ( export_root(follow, queue_size, outfile, \
					 broker, port, tsem_user, topic) )
				retn = 0;
			goto done;
			break;

		default:
			break;
	}

	/* Initialize the process object if in execute mode. */
	if ( broker != NULL ) {
		if ( Debug )
			fprintf(Debug, "Broker output: host=%s, topic=%s\n", \
				broker, topic);
		/* Run a broker based workload. */
		if ( topic == NULL ) {
			fputs("No broker topic specified.\n", stderr);
			goto done;
		}

		if ( !run_broker_workload(workload, broker, port, tsem_user, \
					  topic) )
			ERR(goto done);

	} else {
		/* Run a file based workload. */
		if ( !run_workload(workload, outfile) )
			ERR(goto done);
	}

	waitpid(Monitor_pid, NULL, 0);


 done:
	WHACK(Output_String);
	WHACK(MQTT);
	WHACK(Output_File);

	WHACK(Event);
	WHACK(Execute);

	WHACK(workload);

	return retn;
}
