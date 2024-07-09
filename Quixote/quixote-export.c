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
 * The control object for the model.
 */
static TSEMcontrol Control = NULL;

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
 * The name of the runc workload.
 */
static const char *Runc_name = NULL;

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
 * This function is responsible for shutting down the workload.
 *
 * \param wait		A boolean flag used to indicate whether or
 *			not a runc based workload should wait for the
 *			termination of the run process.
 *
 * \return	No return value is defined.
 */

static void kill_cartridge(_Bool wait)

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
		execlp("runc", "runc", "kill", Runc_name, "SIGKILL", \
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
 * This function is responsible for outputting the security event
 * description or descriptions that have been encoded in the
 * Output_String object.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		processing of the event was successful.  A false value
 *		indicates a failure in event processing while a true
 *		value indicates that event processing has succeeded.
 */

static _Bool output_event_description()

{
	_Bool retn = false;


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
 * This function is responsible for outputting a single event description.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not processing of the event ouput was successful.
 *			A false value indicates a failure in output while
 *			a true value indicates that output was successful.
 */

static _Bool output_event()

{
	_Bool retn = false;


	Output_String->reset(Output_String);
	if ( !Output_String->add(Output_String, Event->get_event(Event)) )
		ERR(goto done);

	if ( Output_File != NULL ) {
		if ( !Output_String->add(Output_String, "\n") )
			ERR(goto done);
	}

	if ( !output_event_description() )
		ERR(goto done);

	retn = true;


 done:
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
 * \return		A boolean value is returned to indicate whether
 *			or not the the creation of the domain was
 *			successful.  A false value indicates setup of
 *			the domain was unsuccessful while a true
 *			value indicates the domains is setup and
 *			ready to be modeled.
 */

static _Bool setup_namespace(int *fdptr)

{
	_Bool retn = false;

	char fname[PATH_MAX];

	int fd;

	uint64_t id;

	enum TSEMcontrol_ns_config ns = 0;


	/* Create and configure a security model namespace. */
	if ( Current_Namespace )
		ns = TSEMcontrol_CURRENT_NS;

	if ( !Control->create_ns(Control, TSEMcontrol_TYPE_EXPORT, \
				 TSEM_model, Digest, ns, Magazine_Size) )
		ERR(goto done);
	if ( !Control->id(Control, &id) )
		ERR(goto done);


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

static _Bool child_monitor(CO(char *, cartridge), int fd)

{
	_Bool event,
	      retn = false;

	int rc;

	unsigned int cycle = 0;

	struct pollfd poll_data[2];

	Buffer cmdbufr = NULL;


	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	poll_data[0].fd	    = fd;
	poll_data[0].events = POLLIN;


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
				if ( !output_event() ) {
					if ( Debug )
						fprintf(Debug, "Event "	     \
							"processing error, " \
							"%u killing %u\n",   \
							getpid(), Monitor_pid);
					break;
				}
			}
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
 * \param cartridge	A pointer to the name of the runc based
 *			container to execute.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the launch.  A false value indicates an error was
 *		encountered while a true value indicates the cartridge
 *		was successfully launched.
 */

static _Bool fire_cartridge(CO(char *, cartridge))

{
	_Bool retn = false;

	char *bundle = NULL,
	     bufr[TSEM_READ_BUFFER];

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
		if ( !child_monitor(cartridge, event_pipe[READ_SIDE]) )
				ERR(goto done);
		retn = true;
		goto done;
	}

	/* Child process - create an independent namespace for this process. */
	if ( Monitor_pid == 0 ) {
		close(event_pipe[READ_SIDE]);
		if ( Debug )
			fprintf(Debug, "%s: Setting up namespace.\n", \
				__func__);
		if ( !setup_namespace(&event_fd) )
			_exit(1);
		if ( Debug )
			fprintf(Debug, "%s: Have namespace.\n", \
				__func__);

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
					fputs("Monitor process terminated.\n",\
					      Debug);
				kill_cartridge(false);
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

		if ( lseek(fd, 0, SEEK_SET) < 0 )
			ERR(goto done);
		retn = true;
	} else {
		if ( errno == ENODATA ) {
			*nodata = true;
			retn = true;
		}
	}


 done:
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
	output->rewind_cursor(output);

	while ( true ) {
		if ( !_get_event(fd, output, &nodata) )
			ERR(goto done);

		if ( nodata ) {
			retn = true;
			break;
		}

		if ( ++Queued == output->size(output) ) {
			if ( !_output_events(output) )
				ERR(goto done);
			Queued = 0;
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
 * \return	A boolean value is returned to reflect the status of
 *		the export.  A false value indicates an error was
 *		encountered while a true value indicates the export
 *		of events was successfully completed.
 */

static _Bool export_root(const _Bool follow, CO(char *, queue_size))

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

	if ( !follow ) {
		if ( !_output_events(output) )
			ERR(goto done);
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
	WHACK(output);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool follow = false;

	char *pwd,
	     *debug	    = NULL,
	     *broker	    = NULL,
	     *topic	    = NULL,
	     *cartridge	    = NULL,
	     *magazine_size = NULL,
	     *queue_size    = "100",
	     *user	    = "tsem",
	     *outfile	    = "/dev/stdout";

	int opt,
	    retn = 1;

	struct sigaction signal_action;


	while ( (opt = getopt(argc, argv, "CPRSfuM:U:b:c:d:h:n:o:p:q:t:")) != \
		EOF )
		switch ( opt ) {
			case 'C':
				Mode = cartridge_mode;
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

			case 'f':
				follow = true;
				break;
			case 'u':
				Current_Namespace = true;
				break;

			case 'M':
				TSEM_model = optarg;
				break;
			case 'U':
				user = optarg;
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

	/* Initialize the security model and its controller. */
	INIT(NAAAIM, TSEMevent, Event, ERR(goto done));
	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));

	/* Handle output to a file. */
	if ( (outfile != NULL) && (broker == NULL) ) {
		if ( strcmp(outfile, "/dev/stdout") != 0 )
			truncate(outfile, 0);

		INIT(HurdLib, File, Output_File, ERR(goto done));
		if ( !Output_File->open_rw(Output_File, outfile) )
			ERR(goto done);
	}

	if ( broker != NULL ) {
		pwd = getenv("TSEM_PASSWORD");

		if ( topic == NULL ) {
			fputs("No broker topic specified.\n", stderr);
			goto done;
		}

		INIT(NAAAIM, MQTTduct, MQTT, ERR(goto done));
		if ( !MQTT->init_publisher(MQTT, broker, 10902, topic, user, pwd) )
			ERR(goto done);
	}


	INIT(HurdLib, String, Output_String, ERR(goto done));

	/* Export the root security modeling domain. */
	if ( Mode == root_mode ) {
		if ( export_root(follow, queue_size) )
			retn = 0;
		goto done;
	}

	/* Fire the workload cartridge. */
	if ( Debug )
		fprintf(Debug, "Launch process: %d\n", getpid());
	if ( !fire_cartridge(cartridge) )
		ERR(goto done);

	waitpid(Monitor_pid, NULL, 0);


 done:
	WHACK(Output_String);
	WHACK(MQTT);
	WHACK(Output_File);

	WHACK(Control);
	WHACK(Event);

	return retn;
}
