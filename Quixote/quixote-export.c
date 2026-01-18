/** \file
 *
 * This file implements a utility for running and managing software
 * stacks in an independent security namespace domain with export of
 * the security state events to userspace.  The primary purpose
 * of this orchestrator is to provide a mechanism for driving machine
 * learning based security models.
 *
 * As with the other userspace orchestrator the security events
 * are exported through the following control plane file:
 *
 * /sys/kernel/security/tsem/export
 *
 * Export can be directed to a file, an MQTT broker or directly into
 * a document indexing engine.
 *
 * In addition to running workloads in subordinate modeling namespaces,
 * this utility also provides support for exporting security events
 * from the root modeling namespace when the kernel is run in
 * root_export_only mode.
 */

/**************************************************************************
 * Copyright (c) 2023, Enjellic Systems Development, LLC. All rights reserved.
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
#include "ESclient.h"
#include "SHA256.h"

#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"
#include "TSEMevent.h"
#include "TSEMcontrol.h"
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
 * This boolean variable is set if a timestamp field is to be
 * added to the event description.
 */
static _Bool Timestamp = false;

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
 * The alternate TSEM model that is to be used.
 */
static char *TSEM_model = NULL;

/**
 * The number of event descriptions that are queued.
 */
static size_t Queued = 0;

/**
 * The object that holds the UUID based boot identifier.
 */
static String Boot_ID = NULL;

/**
 * The object used to hold events being exported from the root modeling
 * namespace.
 */
static Gaggle Output = NULL;

/**
 * The objects used to write the output.
 */
static File Output_File	    = NULL;
static MQTTduct MQTT	    = NULL;
static ESclient IDX	    = NULL;
static String Output_String = NULL;

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
 * Private helper function.
 *
 * This function is a helper function for the update_event() function that
 * adds a timestamp to the export description.
 *
 * \param str	A pointer to the object containing the export description
 *		that is being updated.
 *
 * \return	A boolean value is used to indicate if the addition of
 *		the timestamp was successfull.  A false value indicates
 *		that it failed while a true value indicates the object
 *		passed to the function has been updated with the timestamp.
 */

static _Bool _add_timestamp(CO(String, str))

{
	_Bool retn = false;

	char tb[sizeof("9999-12-31T23:59:59")];

	struct timespec now;


	clock_gettime(CLOCK_REALTIME, &now);
	if ( strftime(tb, sizeof(tb), "%FT%T", gmtime(&now.tv_sec)) \
	     >= sizeof(tb) )
		ERR(goto done);

	if ( !str->add_sprintf(str, "\"@timestamp\": \"%s.%lu\", ", tb, \
			       now.tv_nsec) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function updates the export description to include the boot
 * identifier, and if requested, an event timestamp.
 *
 * \param event		The object containing the event description.
 *
 * \param str		The object into which the updated event
 *			description will be written.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the update of the export description.  A false value
 *		indicates an error was encountered while a true value
 *		indicates the output structure has a valid event
 *		description in it.
 */

static _Bool update_event(CO(TSEMevent, event), CO(String, str))

{
	_Bool retn = false;

	char *p,
	     *type;

	enum TSEM_export_type tp;


	event->reset(event);
	if ( (tp = event->extract_export(event)) == TSEM_EVENT_UNKNOWN )
		ERR(goto done);

	switch ( tp ) {
		case TSEM_EVENT_EVENT:
			type = "event";
			break;
		case TSEM_EVENT_ASYNC_EVENT:
			type = "async_event";
			break;
		case TSEM_EVENT_LOG:
			type = "forensic_event";
			break;
		case TSEM_EVENT_AGGREGATE:
			type = "aggregate";
			break;
		default:
			type = NULL;
			break;
	}

	/* Re-create the export description with a boot identifier. */
	if ( !str->add_sprintf(str, "{\"export\": {\"boot_id\": \"%s\", ", \
			       Boot_ID->get(Boot_ID)) )
		ERR(goto done);

	/* Add the timestamp export description if requested. */
	if ( Timestamp ) {
		if ( !_add_timestamp(str) )
			ERR(goto done);
	}

	/* Add the type. */
	if ( !str->add_sprintf(str, "\"type\": \"%s\"}, ", type) )
		ERR(goto done);


	/* Append the remainder of the event. */
	if ( (p = strstr(event->get_event(event), "\"event\": {")) == NULL )
		ERR(goto done);
	if ( !str->add(str, p) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


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
	if ( !update_event(event, Output_String) )
			ERR(goto done);
	if ( !Output_String->add(Output_String, "\n") )
			ERR(goto done);

	if ( MQTT != NULL ) {
		if ( !MQTT->send_String(MQTT, Output_String) )
			ERR(goto done);
	}

	if ( IDX != NULL ) {
		if ( !IDX->inject(IDX, Output_String) )
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


	if ( !open_file(outfile) )
		ERR(goto done);

	if ( !workload->run_workload(workload, NULL, output_event, NULL) )
		ERR(goto done);
	retn = true;


 done:
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


	if ( !open_broker(broker, port, tsem_user, topic) )
		ERR(goto done);

	if ( !workload->run_workload(workload, NULL, output_event, NULL) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/** Private function.
 *
 * This function is responsible for opening a connection to an index
 * engine endpoint.
 *
 * \param endpoint	A null-terminated buffer containing the hostname
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
 * \param pwd		A pointer to a null-terminated buffer containing
 *			the password to be used to authenticate to
 *			the indexing engine.
 *
 * \param index		A pointer to a null-terminated buffer containing
 *			the name of the index that the security event
 *			descriptions are to be written to.
 *
 * \return	A boolean value is used to indicate whether or establishing
 *		of the connection succeeded.  A false value indicates a
 *		failure while a true value indicates the connection has
 *		been established and is operational.
 */

static _Bool _open_endpoint(CO(char *, endpoint), CO(char *, port),	\
			    CO(char *, user), CO(char *, pwd),		\
			    CO(char *, index))

{
	_Bool retn = false;


	INIT(NAAAIM, ESclient, IDX, ERR(goto done));
	if ( !IDX->init(IDX, endpoint, port, index, user, pwd, NULL) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for launching a workload in an
 * independent security modeling namespace that has the events exported
 * by that namespace to a document indexing engine.  The functionality of
 * this function is identical to the run_broker_workload() function with the
 * exception that this function initializes the index client in the
 * context of the monitor process.
 *
 * \param workload	The object controlling the workload that is to
 *			be executed.
 *
 * \param endpoint	A null-terminated character buffer containing
 *			the name of the host running the indexing
 *			engine.
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

static _Bool run_index_workload(CO(TSEMworkload, workload),		\
				CO(char *, endpoint), CO(char *, port), \
				CO(char *, user), CO(char *, pwd),	\
				CO(char *, index))

{
	_Bool retn = false;


	if ( !_open_endpoint(endpoint, port, user, pwd, index) )
		ERR(goto done);

	if ( !workload->run_workload(workload, NULL, output_event, NULL) )
		ERR(goto done);
	fputs("Exited index workload.\n", stderr);
	retn = true;


 done:
	return retn;
}


/**
 * Private helper function.
 *
 * This function is a helper function for the export_root function.  It
 * is responsible for queing a single event in the output Gaggle.
 *
 * \param event		The object containing the event description.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the queueing.  A false value indicates an error was
 *		encountered while a true value indicates the output
 *		structure was populated with an event.
 */

_Bool _queue_event(CO(TSEMevent, event))

{
	_Bool retn = false;

	String str;


	str = GGET(Output, str);
	str->reset(str);

	if ( !update_event(event, str) )
		ERR(goto done);

	if ( !str->add(str, "\n") )
		ERR(goto done);

	if ( Debug )
		fprintf(Debug, "Queuing %lu/%lu.\n", Queued, \
			Output->size(Output));
	++Queued;
	retn = true;

 done:
	return retn;
}


/**
 * Private helper function.
 *
 * This function traverses the output object and sends each description
 * to the designated output.
 *
 * \return	A boolean value is used indicate whether or not the
 *		output succeeded.  A false value indicates an error
 *		occurred while a true value indicates that all of the
 *		events were sent.
 */

static _Bool _output_events(void)

{
	_Bool retn = false;

	size_t lp;

	String str;


	Output->rewind_cursor(Output);
	if ( Debug )
		fputs("Flushing output queue.\n", Debug);

	if ( MQTT != NULL ) {
		Output_String->reset(Output_String);
		for (lp= 0; lp < Queued; ++lp) {
			str = GGET(Output, str);
			if ( !Output_String->add(Output_String, \
						 str->get(str)) )
				ERR(goto done);
		}
		if ( !MQTT->send_String(MQTT, Output_String) )
			ERR(goto done);
	}

	if ( Output_File != NULL ) {
		for (lp= 0; lp < Queued; ++lp) {
			str = GGET(Output, str);
			if ( !Output_File->write_String(Output_File, str) )
				ERR(goto done);
		}
	}

	Queued = 0;
	retn = true;
	Output->rewind_cursor(Output);


  done:
	return retn;
}


/**
 * Private helper function.
 *
 * This function is a helper function for the export_root function.  It
 * is called by the TSEMworkload->monitor method for each event that
 * is processed.
 *
 * \param event		The event processing structure that will be used
 *			to read the event stream.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the exports.  A false value indicates an error was
 *		encountered while a true value indicates the currently
 *		available events have been exported.
 */

static _Bool _process_event(CO(TSEMevent, event))

{
	_Bool retn = false;


	/* Output events until the end of the event list is met. */
	if ( !_queue_event(event) )
		ERR(goto done);

	if ( Queued == Output->size(Output) ) {
		if ( !_output_events() )
			ERR(goto done);
	}
	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for driving the export of events from
 * the root security modeling namespace.
 *
 * \param workload	The workload management object that will be
 *			used to monitor the root modeling namespace.
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

static _Bool export_root(CO(TSEMworkload, workload), const _Bool follow, \
			 CO(char *, queue_size), CO(char *, outfile),	 \
			 CO(char *, broker), CO(char *, port),		 \
			 CO(char *, user), CO(char*, topic))

{
	_Bool retn = false;

	unsigned int lp;

	long int queue_length;

	String str;

	TSEMevent event = NULL;


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

	/* Establish the queue size. */
	queue_length = strtol(queue_size, NULL, 0);
	if ( errno == ERANGE )
		goto done;

	/* Initialize output queue. */
	INIT(HurdLib, Gaggle, Output, ERR(goto done));
	for (lp= 0; lp < queue_length; ++lp) {
		INIT(HurdLib, String, str, ERR(goto done));
		if ( !GADD(Output, str) )
			ERR(goto done);
	}

	/* Output events as they are generated.. */
	if ( !workload->run_root_export(workload, _process_event, follow) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(event);
	GWHACK(Output, String);

	return retn;
}

/**
 * Private helper function.
 *
 * This is a private helper function for the main() function that
 * reads the system boot identifier from the following file:
 *
 * /proc/sys/kernel/random/boot_id
 *
 * This UUID will be added to each exported record in order to allow
 * namespaces to be differentiated between boots of the operating
 * system.  Within a given OS boot the security context identifier
 * will differentiate separate namespaces.
 *
 * This function loads the UUID into the statically scoped Boot_ID
 * String object.
 *
 * \return	A boolean value is returned to reflect the status of
 *		loading the boot identifier.  A false value indicates
 *		the read of the identifier failed while a true value
 *		indicates the Boot_ID object contains the current
 *		boot identifier.
 */

static _Bool _read_boot_identifier(void)

{
	_Bool retn = false;

	File boot_file = NULL;


	INIT(HurdLib, String, Boot_ID, ERR(goto done));

	INIT(HurdLib, File, boot_file, ERR(goto done));
	if ( !boot_file->open_ro(boot_file, \
				 "/proc/sys/kernel/random/boot_id") )
		ERR(goto done);

	if ( !boot_file->read_String(boot_file, Boot_ID) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(boot_file);

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
	     *endpoint	    = NULL,
	     *topic	    = NULL,
	     *port	    = NULL,
	     *name	    = NULL,
	     *magazine_size = NULL,
	     *outfile	    = NULL,
	     *queue_size    = "100",
	     *tsem_user	    = "tsem";

	int opt,
	    retn = 1;

	TSEMworkload workload = NULL;


	while ( (opt = getopt(argc, argv,
			      "CPRSXafuM:b:d:e:h:n:o:p:q:s:t:w:")) \
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

			case 'a':
				Timestamp = true;
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
			case 'd':
				debug = optarg;
				break;
			case 'e':
				endpoint = optarg;
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
			case 'w':
				name = optarg;
				break;
		}


	/* We need an output file. */
	if ( (outfile == NULL) && (broker == NULL) && (endpoint == NULL) ) {
		fputs("No output method specified.\n", stderr);
		goto done;
	}

	/* Execute cartridge display mode. */
	if ( Mode == show_mode )
		show_magazine(QUIXOTE_MAGAZINE);

	if ( name == NULL ) {
		fputs("No workload name specified.\n", stderr);
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

	/* Get the boot identifier. */
	if ( !_read_boot_identifier() )
		ERR(goto done);

	/* Initialize the TSEM workload manager object. */
	INIT(NAAAIM, TSEMworkload, workload, ERR(goto done));
	INIT(HurdLib, String, Output_String, ERR(goto done));

	workload->set_debug(workload, Debug);
	if ( !workload->configure_export(workload, name, TSEM_model, Digest, \
					 magazine_size, Current_Namespace) )
		ERR(goto done);

	switch ( Mode ) {
		case container_mode:
			if ( !workload->set_container_mode(workload, 	     \
							   QUIXOTE_MAGAZINE) )
				ERR(goto done);
			break;

		case execute_mode:
			workload->set_execute_mode(workload, argc, argv);
			break;

		case root_mode:
			if ( export_root(workload, follow, queue_size,	   \
					 outfile, broker, port, tsem_user, \
					 topic) )
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
	} else if ( endpoint != NULL ) {
		if ( topic == NULL ) {
			fputs("No index specified.\n", stderr);
			goto done;
		}
		if ( Debug )
			fprintf(Debug, "Index output: host=%s, index=%s\n", \
				endpoint, topic);
		if ( !run_index_workload(workload, endpoint, port, tsem_user, \
					 NULL, topic) )
			ERR(goto done);
	} else if ( outfile != NULL ) {
		/* Run a file based workload. */
		if ( !run_workload(workload, outfile) )
			ERR(goto done);
	}
	fputs("Exited workload.\n", stderr);


	waitpid(Monitor_pid, NULL, 0);


 done:
	WHACK(Boot_ID);
	WHACK(Output_String);
	WHACK(MQTT);
	WHACK(IDX);
	WHACK(Output_File);

	WHACK(workload);

	return retn;
}
