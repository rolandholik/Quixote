/** \file
 * This file contains the implementation of an object that implements
 * the running of a workload in a security modeling namespace.
 */

/**************************************************************************
 * Copyright (c) 2024, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local definitions. */

/* Defines for which side of the event pipe to access. */
#define READ_SIDE  0
#define WRITE_SIDE 1

/* The size of the buffer to be used for reading TSEM events. */
#define TSEM_READ_BUFFER 1536

/* The printf specifier for the file exporting events for a namespace. */
#define TSEM_EVENT_FILE "/sys/kernel/security/tsem/external_tma/%lu"


/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/capability.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "LocalDuct.h"
#include "Process.h"
#include "TSEMcontrol.h"
#include "TSEMevent.h"
#include "TSEMworkload.h"


/* State extraction macro. */
#define STATE(var) CO(TSEMworkload_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TSEMworkload_OBJID)
#error Object identifier not defined.
#endif

/**
 * The following enumeration type is used to specify the execution mode
 * of the workload defined by an instance of a TSEMworkload object.
 */
enum workload_mode {
	NO_MODE,
	PROCESS_MODE,
	CONTAINER_MODE,
	EXECUTE_MODE
};

/**
 * Debug file.
 */
static FILE *Debug = NULL;

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

/** TSEMworkload private state information. */
struct NAAAIM_TSEMworkload_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object state. */
	_Bool poisoned;

	/* Process identifiers. */
	pid_t workload_pid;

	/* Workload parameters. */
	int fd;
	unsigned long int id;
	enum TSEMcontrol_ns_config type;
	enum TSEMcontrol_ns_config ns;
	unsigned int cache_size;
	_Bool enforce;
	String model;
	String digest;

	/* Execute mode parameters. */
	enum workload_mode mode;
	int argc;
	char **argv;
	const char *container;
	String bundle;

	/* Communication pipe for state events. */
	int event_pipe[2];

	/* Namespace control object. */
	TSEMcontrol control;

	/* Event processing object. */
	TSEMevent event;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TSEMworkload_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(TSEMworkload_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TSEMworkload_OBJID;

	S->poisoned = false;

	S->workload_pid = 0;

	S->fd = 0;
	S->id = 0;
	S->type = 0;
	S->ns = TSEMcontrol_INIT_NS;
	S->cache_size = 0;
	S->model = NULL;
	S->digest = NULL;
	S->control = NULL;

	S->mode = PROCESS_MODE;
	S->argc = 0;
	S->argv = NULL;
	S->container = NULL;
	S->bundle = NULL;

	return;
}


/**
 * Private function.
 *
 * This function implements the signal handler for the workload.  When
 * called it sets the signal type in the Signals structure for processing
 * by the event loops.
 *
 * \param signal	The number of the signal which caused the
 *			handler to execute.
 *
 * \param siginfo	A pointer to a structure providing information
 *			on the signal.
 *
 * \param private	The signal context information, unused by this
 *			handler.
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
			fprintf(stderr, "%d: Caught sigsegv.\n", getpid());
			exit(1);
			return;
	}

	return;
}


/**
 * Internal private method.
 *
 * This function is responsible for populating the object state
 * structure with the namespace creation parameters.
 *
 * \param S		The object state information that is to be
 *			updated.
 *
 * \param model		A pointer to a null-terminated character buffer
 *			containing the name of the security event processing
 *			model that is to be requested.  A null value
 *			indicates that no model is being specified.
 *
 * \param digest	A pointer to a null-terminated character buffer
 *			containing the name of the digest function that
 *			is to be used for event mapping.
 *
 * \param initial_ns	A boolean value indicating whether or not the
 *			initial user namespace should be used for the
 *			discretionary access controls or if operative
 *			user namespace should be used.
 *
 * \param cache_size	A pointer to a null-terminated character buffer
 *			containing the ASCII expresion of the asynchronous
 *			cache sizes to be used for the modeling namespace.
 *
 * \param enforce	A boolean value indicating whether or not the
 *			namespace should be placed in enforcing mode.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		security model namespace has been initialized.  A false
 *		value indicates the initialization failed while a true
 *		value indicates the state was successfully initialized.
 */

static _Bool _init_ns_config(CO(TSEMworkload_State, S), CO(char *, model), \
			     CO(char *, digest), const _Bool initial_ns,   \
			     CO(char *, cache_size), const _Bool enforce)

{
	_Bool retn = false;


	if ( model != NULL ) {
		INIT(HurdLib, String, S->model, ERR(goto done));
		if ( !S->model->add(S->model, model) )
			ERR(goto done);
	}

	if ( digest != NULL ) {
		INIT(HurdLib, String, S->digest, ERR(goto done));
		if ( !S->digest->add(S->digest, digest) )
			ERR(goto done);
	}

	if ( cache_size != NULL ) {
		S->cache_size = strtoll(cache_size, NULL, 0);
		if ( errno == ERANGE )
			ERR(goto done);
	}

	if ( !initial_ns )
		S->ns = TSEMcontrol_CURRENT_NS;

	S->enforce = enforce;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of a security modeling workload
 * that externally exports the events.
 *
 * \param this		A pointer to the object describing the workload.
 *
 * \param model		A pointer to a null-terminated character buffer
 *			containing the name of an alternate security
 *			model that is to be used for processing security
 *			events.
 *
 * \param digest	A pointer to a null-terminated character buffer
 *			containing the name of the cryptographic hash
 *			function that will be used to generate the
 *			security event coefficients.
 *
 * \param cache_size	A pointer to a null-terminated character buffer
 *			containing an integer expression of the size
 *			of the event magazines that are to be used
 *			for the security modeling namespace.
 *
 * \param initial_ns	A boolean value that indicates the origin for
 *			the characteristics of the context of execution.
 *			A true value indicates that the initial user
 *			namespace should be used, a false value indicates
 *			that the user namespace view of the characteristics
 *			should be used.
 */

static _Bool configure_export(CO(TSEMworkload, this), CO(char *, model),  \
			      CO(char *, digest), CO(char *, cache_size), \
			      const _Bool initial_ns)

{
	STATE(S);

	_Bool retn = false;


	if ( !_init_ns_config(S, model, digest, initial_ns, cache_size, \
			      false) )
		ERR(goto done);

	retn	= true;
	S->type = TSEMcontrol_TYPE_EXPORT;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of a security modeling workload
 * that externally models the events.
 *
 * \param this	A pointer to the object describing the workload.
 *
 * \param model		A pointer to a null-terminated character buffer
 *			containing the name of an alternate security
 *			model that is to be used for processing security
 *			events.
 *
 * \param digest	A pointer to a null-terminated character buffer
 *			containing the name of the cryptographic hash
 *			function that will be used to generate the
 *			security event coefficients.
 *
 * \param cache_size	A pointer to a null-terminated character buffer
 *			containing an integer expression of the size
 *			of the event magazines that are to be used
 *			for the security modeling namespace.
 *
 * \param initial_ns	A boolean value that indicates the origin for
 *			the characteristics of the context of execution.
 *			A true value indicates that the initial user
 *			namespace should be used, a false value indicates
 *			that the user namespace view of the characteristics
 *			should be used.
 *
 * \param enforce	A boolean value that indicates whether or not
 *			the security modeling namespace should be set to
 *			enforcing mode.  A true value indicates that
 *			enforcing mode should be selected.
 */

static _Bool configure_external(CO(TSEMworkload, this), CO(char *, model),  \
				CO(char *, digest), CO(char *, cache_size), \
				const _Bool initial_ns, const _Bool enforce)

{
	STATE(S);

	_Bool retn = false;


	if ( !_init_ns_config(S, model, digest, initial_ns, cache_size, \
			      enforce) )
		ERR(goto done);

	S->type = TSEMcontrol_TYPE_EXTERNAL;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implementations configuration of execution mode for the
 * workload.  Execution mode involves running a specific command that
 * is provided in the form of an argc count and an array of pointers
 * specifying the command.  The implementation is designed to execute
 * command line parameters that are delimited by a -- character sequence
 * on the command-line of the trust orchestrator.
 *
 * \param this		A pointer to the object whose workload type is
 *			being set.
 *
 * \param argc		The count of arguments in the argv array if
 *			non-null.
 *
 * \param argv		An argument list specifing a command to be
 *			executed.
 */

static void set_execute_mode(CO(TSEMworkload, this), int argc, char *argv[])

{
	STATE(S);


	S->argc = argc;
	S->argv = argv;
	S->mode = EXECUTE_MODE;

	return;
}


/**
 * External public method.
 *
 * This method implementations configuration of container mode for the
 * workload.  Containerna mode specifies that a runc instance is to be
 * used to run  OCI container instance as the security modeling workload.
 *
 * \param this		A pointer to the object whose workload type is
 *			being set.
 *
 * \param magazine	A pointer to a null-terminated character buffer
 *			containing the directory location where the
 *			container instance is located.
 *
 * \param container	A pointer to a null-terminated buffer containing
 *			the name of the runc container to execute.
 *
 * \return	A boolean value is used to indicate whether or not
 *		configuration of the mode has succeesed.  A false
 *		value indicates that configuration failed while a true
 *		value indicates the object execution mode was successfully
 *		configured.
 */

static _Bool set_container_mode(CO(TSEMworkload, this), \
				CO(char *, magazine), CO(char *, container))

{
	STATE(S);

	_Bool retn = false;


	/* Save the container name and create the bundle name. */
	INIT(HurdLib, String, S->bundle, ERR(goto done));
	if ( !S->bundle->add_sprintf(S->bundle, "%s/%s", magazine, container) )
		ERR(goto done);

	retn	     = true;
	S->mode	     = CONTAINER_MODE;
	S->container = container;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implementations the specification of a file descriptor
 * that is to be used for generating debug information on the status
 * of the workload.
 *
 * \param this	A pointer to the object whose debug status is
 *		to be set.
 *
 * \param file	A pointer to the file descriptor that is to be used
 *		for debug information.
 */

static void set_debug(CO(TSEMworkload, this), FILE *debug)

{
	Debug = debug;
	return;
}


/**
 * Private function.
 *
 * This function implements checking for whether or not a process has
 * terminated.
 *
 * \param child	The process id of a child that exited.
 *
 *
 * \return	A boolean value is used to indicate whether or not the
 *		designed process has exited.  A false value indicates it
 *		has not while a true value indicates it has.
 */

static _Bool child_exited(const pid_t child)

{
	int status;

	pid_t exited;


	exited = waitpid(child, &status, WNOHANG);
	if ( Debug )
		fprintf(Debug, "%d: %d exited.\n", getpid(), exited);

	if ( exited != child )
		return false;
	return true;
}


/**
 * External public method.
 *
 * This method implements running the security monitor process.  This
 * process receives and processes security events from the workload
 * monitor process.
 *
 * \param this		A pointer to the object whose security monitor
 *			process is to be run.
 *
 * \param workload_pid	The process id of the workload that will be
 *			monitored for security events.
 *
 * \param mgmt		If a workload manager is to be used a pointer
 *			to the object.  A NULL value will disable for
 *			polling for management commands.
 *
 * \parm event_handler	A pointer to a function that will be caused with
 *			the object that was used to read the security
 *			event.
 *
 * \return	A boolean value is used to indicate whether or not
 *		execution of the security monitor has succeeded.  A false
 *		value indicates that the monitor process failed while a
 *		true value indicates the object execution mode was
 *		successfully configured.
 */

static _Bool run_monitor(CO(TSEMworkload, this), pid_t workload_pid,	\
			 CO(LocalDuct, mgmt),				\
			 _Bool (*event_handler)(TSEMevent),		\
			 _Bool (*command_handler)(LocalDuct, Buffer))

{
	STATE(S);

	_Bool event,
	      retn	= false,
	      connected = false;

	int rc,
	    fd	  = S->event_pipe[READ_SIDE],
	    fdcnt = 1;

	unsigned int cycle = 0;

	struct pollfd poll_data[2];

	Buffer cmdbufr = NULL;


	if ( Debug )
		fprintf(Debug, "Security Monitor (SM) pid: %d\n", getpid());

	INIT(HurdLib, Buffer, cmdbufr, ERR(goto done));

	S->workload_pid = workload_pid;
	close(S->event_pipe[WRITE_SIDE]);

	poll_data[0].fd	    = fd;
	poll_data[0].events = POLLIN;

	if ( mgmt == NULL )
		poll_data[1].fd = 0;
	else {
		if ( !mgmt->get_socket(mgmt, &poll_data[1].fd) )
			ERR(goto done);
		++fdcnt;
		poll_data[1].events = POLLIN;
	}

	/* Dispatch loop. */
	if ( Debug ) {
		fprintf(Debug, "%d: Calling event loop\n", getpid());
		fprintf(Debug, "fdcnt: %d, descriptor 1: %d, " \
			"descriptor 2: %d\n", fdcnt, poll_data[0].fd, \
			poll_data[1].fd);
	}

	while ( 1 ) {
		if ( Debug )
			fprintf(Debug, "\n%d: Poll cycle: %d\n", getpid(), \
				++cycle);

		rc = poll(poll_data, fdcnt, -1);
		if ( rc < 0 ) {
			if ( Signals.stop ) {
				if ( Debug )
					fputs("Quixote terminated.\n", Debug);
				retn = true;
				Signals.stop = false;
				this->shutdown(this, SIGTERM, true);
				goto done;
			}
			if ( Signals.sigchild ) {
				Signals.sigchild = false;
				if ( !child_exited(S->workload_pid) )
					continue;
				retn = true;
				goto done;
			}

			fputs("Poll error.\n", stderr);
			this->shutdown(this, SIGTERM, true);
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
				Signals.stop = false;
				goto done;
			}
			if ( Signals.sigchild ) {
				Signals.sigchild = false;
				if ( !child_exited(S->workload_pid) )
					continue;
				retn = true;
				goto done;
			}
		}

		if ( poll_data[0].revents & POLLIN ) {
			if ( !S->event->read_event(S->event, fd) ) {
				this->shutdown(this, SIGTERM, false);
				break;
			}

			event = true;
			while ( event ) {
				if ( !S->event->fetch_event(S->event, \
							    &event) ) {
					this->shutdown(this, SIGTERM, false);
					break;
				}

				if ( !event_handler(S->event) ) {
					if ( Debug )
						fprintf(Debug, "Event "	     \
							"processing error, " \
							"%u killing %u\n",   \
							getpid(),	     \
							S->workload_pid);
					break;
				}
				if ( Signals.sigchild ) {
					Signals.sigchild = false;
					if ( child_exited(S->workload_pid) ) {
						retn = true;
						goto done;
					}
					continue;
				}
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
			if ( !mgmt->receive_Buffer(mgmt, cmdbufr) ) {
				fputs("Orchestrator manager error.\n", stderr);
				this->shutdown(this, SIGTERM, false);
			}
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

			if ( !command_handler(mgmt, cmdbufr) )
				this->shutdown(this, SIGTERM, false);
			cmdbufr->reset(cmdbufr);
		}
	}


 done:
	WHACK(cmdbufr);

	return retn;
}


/**
 * Private helper method
 *
 * This function is a helper function for the ->run_workload method.  It
 * is responsible for creating the security modeling namespace.  In the
 * case of an externally modeled or export namespace it captures the
 * security modeling namespace identifier value.
 *
 * \param S		A pointer to the structure containing the state
 *			information for the object running the workload.
 *
 * \return		A boolean value is used to indicated whether or
 *			not the setup of the namespace has succeeded.  A
 *			false value indicates failure while a true
 *			value indicates the namespace was successfully
 *			created.  In the event of a true value return
 *			and an external modeled or export domain the
 *			variable pointed to by the fdptr is updated
 *			with the file descriptor of the namespace
 *			export file.
 */

static _Bool _setup_namespace(CO(TSEMworkload_State, S))

{
	_Bool retn = false;

	char *model  = S->model == NULL ? NULL : S->model->get(S->model),
	     *digest = S->digest == NULL ? NULL : S->digest->get(S->digest),
	     fname[PATH_MAX];


	/* Create and configure a security model namespace. */
	if ( !S->control->create_ns(S->control, S->type, model, digest, \
				    S->ns, S->cache_size) )
		ERR(goto done);
	if ( !S->control->id(S->control, &S->id) )
		ERR(goto done);
	if ( S->enforce ) {
		if ( !S->control->enforce(S->control) )
			ERR(goto done);
	}


	/* Create the pathname to the event update file. */
	memset(fname, '\0', sizeof(fname));
	if ( snprintf(fname, sizeof(fname), TSEM_EVENT_FILE, \
		      S->id) >= sizeof(fname) )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "Update file: %s\n", fname);

	if ( (S->fd = open(fname, O_RDONLY)) < 0 )
		ERR(goto done);
	retn = true;


 done:
	return retn;

}


/**
 * Private helper function.
 *
 * This function is a helper function for the run_workload() function.
 * The purpose of this function is to set the process permissions to, by
 * default, to the 'nobody' value, ie. with no privileges.
 *
 * \param user	A character pointer to the name of the uid that the
 *		process will be changed to.  Passing a NULL value to this
 *		function will cause the 'nobody' user to be attempted.
 *
 * \return	A boolean value is returned to reflect the status of
 *		the permissions change.  A false value indicates an error
 *		was encountered while a true value indicates the permissions
 *		were successfully changed.
 */

static _Bool _set_user(CO(char *, user))

{
	_Bool retn = false;

	const char *u = user == NULL ? "nobody" : user;

	struct passwd *pw;


	if ( (pw = getpwnam(u)) == NULL )
		ERR(goto done);
	if ( Debug )
		fprintf(Debug, "%d: Setting credentials to %s\n", getpid(), \
			pw->pw_name);

	if ( setgid(pw->pw_gid) != 0 )
		ERR(goto done);
	if ( setuid(pw->pw_uid) != 0 )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements running a workload process in a security
 * modeling namespace.  The function forks to create a process from
 * which the target workload will be executed.  The parent process
 * then reads the TSEM event file that was created for the security
 * modeling namespace and writes the events as they occur to the
 * event pipe that is connected to the security workload monitor.
 *
 * \param this		A pointer to the object whose workload is
 *			to be executed.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the workload was successfully run.  A
 *			false value indicates the execution of the
 *			workload failed or if there was an error
 *			encountered during the monitoring of the
 *			workload.
 */

static _Bool run_workload(CO(TSEMworkload, this))

{
	STATE(S);

	_Bool retn = false;

	char bufr[TSEM_READ_BUFFER];

	int rc;

	struct pollfd poll_data[1];

	Process execute = NULL;


	if ( Debug )
		fprintf(Debug, "%s: Setting up namespace.\n", __func__);
	if ( !_setup_namespace(S) )
		_exit(1);

	/* Fork again to run the cartridge. */
	close(S->event_pipe[READ_SIDE]);

	S->workload_pid = fork();
	if ( S->workload_pid == -1 )
		exit(1);

	/* Child process - Workload. */
	if ( S->workload_pid == 0 ) {
		if ( Debug ) {
			fprintf(Debug, "Workload process: %d\n", getpid());
		}
		close(S->fd);
		close(S->event_pipe[WRITE_SIDE]);
		WHACK(S->control);

		/* Drop the ability to modify the trust state. */
		if ( cap_drop_bound(CAP_MAC_ADMIN) != 0 )
			ERR(goto done);

		if ( S->mode == CONTAINER_MODE ) {
			if ( Debug ) {
				fprintf(Debug, "Workload: container=%s, "  \
					"bundle=%s\n", S->container,	   \
					S->bundle->get(S->bundle));
				fclose(Debug);
			}

			execlp("runc", "runc", "run", "-b", \
			       S->bundle->get(S->bundle), S->container, NULL);
			fputs("Workload execution failed.\n", stderr);
			exit(1);
		}

		if ( S->mode == PROCESS_MODE ) {
			if ( geteuid() != getuid() ) {
				if ( Debug )
					fprintf(Debug, "Changing to real " \
						"id: %u\n", getuid());
				if ( setuid(getuid()) != 0 ) {
					fputs("Cannot change uid.\n", stderr);
					exit(1);
				}
			}

			if ( Debug ) {
				fputs("Executing workload shell.\n", Debug);
				fclose(Debug);
			}

			execlp("bash", "bash", "-i", NULL);
			fputs("Cartridge process execution failed.\n", stderr);
			exit(1);
		}

		if ( S->mode == EXECUTE_MODE ) {
			INIT(HurdLib, Process, execute, exit(1));
			if ( geteuid() != getuid() ) {
				if ( Debug )
					fprintf(Debug, "Changing to real " \
						"id: \%u\n",  getuid());
				if ( setuid(getuid()) != 0 ) {
					fputs("Cannot change uid.\n", stderr);
					exit(1);
				}
			}

			if ( Debug ) {
				fputs("Executing workload command.\n", Debug);
				fclose(Debug);
			}

			execute->run_command_line(execute, S->argc, S->argv);
			fputs("Command line execution failed.\n", stderr);
			exit(1);
		}
	}

	/* Parent process - Namespace Monitor. */
	if ( Debug ) {
		fprintf(Debug, "Namespace Monitor (NM) pid: %d\n", getpid());
		fprintf(Debug, "%d: Calling event loop\n", getpid());
		fprintf(Debug, "%d: fd descriptor: %d\n", getpid(), S->fd);
	}

	poll_data[0].fd	    = S->fd;
	poll_data[0].events = POLLIN;

	if ( S->type == TSEMcontrol_TYPE_EXPORT ) {
		if ( !_set_user(NULL) )
			ERR(goto done);
	}

	while ( true ) {
		if ( Signals.stop ) {
			if ( Debug )
				fputs("Monitor process stopped\n", Debug);
			retn = true;
			Signals.stop = false;
			goto done;
		}

		if ( Signals.sigterm ) {
			if ( Debug )
				fputs("Monitor process terminated.\n", Debug);
			Signals.sigterm = 0;
			this->shutdown(this, SIGKILL, false);
		}

		if ( Signals.sigchild ) {
			if ( child_exited(S->workload_pid) ) {
				close(S->fd);
				close(S->event_pipe[WRITE_SIDE]);
				_exit(0);
			}
			Signals.sigchild = false;
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
			rc = read(S->fd, bufr, sizeof(bufr));
			if ( rc == 0 )
				break;
			if ( rc < 0 ) {
				if ( errno != ENODATA ) {
					fputs("Fatal event read.\n", stderr);
					exit(1);
				}
				break;
			}
			if ( rc > 0 ) {
				write(S->event_pipe[WRITE_SIDE], bufr, rc);
				lseek(S->fd, 0, SEEK_SET);
			}
		}

		if ( lseek(S->fd, 0, SEEK_SET) < 0 ) {
			fputs("Seek error.\n", stderr);
			break;
		}
	}


 done:
	return retn;

}


/**
 * External public method.
 *
 * This method releases a process to run as a trusted process.  It serves
 * as an inheritance wrapper around a the TSEMcontrol->release method.
 *
 * \param this	The object describing the workload whose process is to
 *		be released.
 *
 * \param pid	The process identifier of the process to be released.
 *
 * \param tnum	The task number of the process to be released.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the workload was successfully released.
 *			A false value indicates that a failure had
 *			occurred int he process release.  A true value
 *			indicates the process was successfully released.
 */

static _Bool release(CO(TSEMworkload, this), const pid_t pid, \
		     const uint64_t tnum)

{
	STATE(S);

	return S->control->release(S->control, pid, tnum);
}


/**
 * External public method.
 *
 * This method releases a process to run as an untrusted process.  It
 * serves as an inheritance wrapper around a the TSEMcontrol->release
 * method.
 *
 * \param this	The object describing the workload whose process is to
 *		be released.
 *
 * \param pid	The process identifier of the process to be released
 *		as untrusted.
 *
 * \parm tnum	The task number of the process to be released as
 *		untrusted.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the workload was successfully released.
 *			A false value indicates that a failure had
 *			occurred int he process release.  A true value
 *			indicates the process was successfully released.
 */

static _Bool discipline(CO(TSEMworkload, this), const pid_t pid, \
			const uint64_t tnum)

{
	STATE(S);

	return S->control->discipline(S->control, pid, tnum);
}


/**
 * External public method.
 *
 * This method shuts down the workload being managed by this object.
 * If the workload is process based a termination signal is issued.  If
 * the workload is runc based a kill signal is transmitted to the
 * runc instance that is managing the workload.
 *
 * \param signal	The signal that is to sent to the child process.
 *
 * \param wait		A boolean flag used to indicate whether or not
 *			a runc based workload should wait for the
 *			termination of the run process.
 */

static void shutdown(CO(TSEMworkload, this), const int signal, \
		     const _Bool wait)

{
	STATE(S);

	int status;

	static pid_t kill_process = 0;


	/* Signal the monitor process to shutdown the cartridge process. */
	if ( S->mode != CONTAINER_MODE ) {
		kill(S->workload_pid, signal);
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
			fprintf(Debug, "Killing runc container: %s.\n",
				S->container);
		execlp("runc", "runc", "kill", S->container, "SIGKILL", NULL);
		exit(1);
	}

	/* Parent process - wait for the kill process to complete. */
	if ( wait )
		waitpid(kill_process, &status, 0);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TSEMworkload object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TSEMworkload, this))

{
	STATE(S);


	WHACK(S->model);
	WHACK(S->digest);

	WHACK(S->bundle);

	WHACK(S->event);
	WHACK(S->control);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * Internal private function.
 *
 * This method is called by the object constructor to establish the
 * signal handlers.
 *
 * \return	A boolean value is used to indicate the status of the
 *		setup of the signals.  A false value indicates the
 *		setup failed while a true value indicates the signal
 *		handlers were successfully established.
 */

static _Bool _init_signals(void)

{
	_Bool retn = false;

	struct sigaction signal_action;


	if ( sigemptyset(&signal_action.sa_mask) == -1 )
		ERR(goto done);

	signal_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	signal_action.sa_sigaction = signal_handler;

	if ( sigaction(SIGINT, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGTERM, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGHUP, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGQUIT, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGFPE, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGILL, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGBUS, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGTRAP, &signal_action, NULL) == -1 )
		ERR(goto done);
	if ( sigaction(SIGCHLD, &signal_action, NULL) == -1 )
		ERR(goto done);

	if ( sigaction(SIGSEGV, &signal_action, NULL) == -1 )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a TSEMworkload object.
 *
 * \return	A pointer to the initialized TSEMworkload.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TSEMworkload NAAAIM_TSEMworkload_Init(void)

{
	Origin root;

	TSEMworkload this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TSEMworkload);
	retn.state_size   = sizeof(struct NAAAIM_TSEMworkload_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TSEMworkload_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	if ( !_init_signals() )
		goto fail;

	if ( pipe(this->state->event_pipe) == -1 )
		goto fail;

	/* Initialize aggregate objects. */
	INIT(NAAAIM, TSEMevent, this->state->event, goto fail);
	INIT(NAAAIM, TSEMcontrol, this->state->control, goto fail);

	/* Method initialization. */
	this->configure_export	 = configure_export;
	this->configure_external = configure_external;

	this->set_debug		 = set_debug;
	this->set_execute_mode	 = set_execute_mode;
	this->set_container_mode = set_container_mode;

	this->run_monitor  = run_monitor;
	this->run_workload = run_workload;

	this->release	 = release;
	this->discipline = discipline;
	this->shutdown	 = shutdown;

	this->whack = whack;

	return this;


 fail:
	root->whack(root, this, this->state);
	return NULL;
}
