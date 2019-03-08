/** \file
 * This file contains the implementation of an object which manages a
 * software TPM implementation.  The primary purpose of this object
 * encapsulation is to confine the start/stop of all necessary system
 * daemons into a single container.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SoftwareTPM.h"

/* Object state extraction macro. */
#define STATE(var) CO(SoftwareTPM_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SoftwareTPM_OBJID)
#error Object identifier not defined.
#endif


/** SoftwareTPM private state information. */
struct NAAAIM_SoftwareTPM_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Process ID of the TPM server. */
	pid_t tpm_pid;

	/* Process ID of the TCSD server. */
	pid_t tcsd_pid;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SoftwareTPM_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const SoftwareTPM_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SoftwareTPM_OBJID;

	S->poisoned = false;

	S->tpm_pid  = 0;
	S->tcsd_pid = 0;

	return;
}


/**
 * External public method.
 *
 * This method starts the software TPM stack.  The stack consistes of
 * two daemons.  The tpm_server daemon which implements the software
 * TPM and the standard tcsd TPM management daemon.  After the
 * tpm_server is called the tpmbios binary is called to initialize the
 * TPM state for use.
 *
 * \param this	A pointer to the TPM object which is to be started.
 * 
 * \param uid	The uid of the user which the software TPM will
 *		run under.  This is provided to allow the files which the
 *		software TPM simulator uses/creates to not come under
 *		measurement.
 * 
 * \return	If any type of failure occurs when the software TPM
 *		stack is started a false value is returned.  A true
 *		value indicates the stack was successfully started.
 */

static _Bool start(CO(SoftwareTPM, this), const uid_t uid)

{
	STATE(S);

	_Bool retn	 = false,
	      changed_id = false;

	int fd,
	    status;

	pid_t tpmbios;


	if ( getuid() != uid ) {
		if ( setreuid(uid, -1) == -1 )
			goto done;
		changed_id = true;
	}

	if ( setenv("TPM_PORT", "1590", 1) != 0 )
		goto done;
	if ( setenv("TPM_SERVER_PORT", "1590", 1) != 0 )
		goto done;
	if ( setenv("TPM_SERVER_NAME", "127.0.0.1", 1) != 0 )
		goto done;
	if ( setenv("TCSD_TCP_DEVICE_PORT", "1590", 1) != 0 )
		goto done;
	if ( setenv("TCSD_TCP_DEVICE_HOSTNAME", "127.0.0.1", 1) != 0 )
		goto done;
	if ( setenv("TPM_PATH", "/var/lib/swtpm", 1) != 0 )
		goto done;

	S->tpm_pid = fork();
	if ( S->tpm_pid == -1 )
		goto done;
	/* Child. */
	if ( S->tpm_pid == 0 ) {
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			_exit(1);
		if ( dup2(fd, STDIN_FILENO) == -1 )
			_exit(1);
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			_exit(1);
		if ( dup2(fd, STDOUT_FILENO) == -1 )
			_exit(1);

		execl("/usr/local/sbin/tpm_server", \
		      "/usr/local/sbin/tpm_server", NULL);
		_exit(1);
	}
	/* Parent - verify DAEMON is running. */
	sleep(2);
	if ( kill(S->tpm_pid, 0) == -1 )
		goto done;

	tpmbios = fork();
	if ( tpmbios == -1 )
		goto done;
	/* Child. */
	if ( tpmbios == 0 ) {
		execl("/usr/local/sbin/tpmbios", "/usr/local/sbin/tpmbios", \
		      NULL);
		_exit(1);
	}
	if ( waitpid(tpmbios, &status, 0) != tpmbios )
		goto done;
	/* Parent - give effects of tpmbios some time. */
	sleep(2);
	

	/* Start the TCSD daemon. */
	S->tcsd_pid = fork();
	if ( S->tcsd_pid == -1 )
		goto done;
	/* Child. */
	if ( S->tcsd_pid == 0 ) {
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			_exit(1);
	 	if ( dup2(fd, STDIN_FILENO) == -1 )
			_exit(1);
		if ( (fd = open("/dev/null", O_RDWR)) == -1 )
			_exit(1);
		if ( dup2(fd, STDOUT_FILENO) == -1 )
			_exit(1);

		execl("/usr/local/sbin/tcsd", \
		      "/usr/local/sbin/tcsd", "-e", "-f", "-n", NULL);

		_exit(1);
	}
	/* Parent - verify DAEMON is running. */
	sleep(2);
	if ( kill(S->tcsd_pid, 0) == -1 )
		goto done;

	retn = true;
	if ( changed_id ) {
		if ( setreuid(geteuid(), -1) == -1 )
			retn = false;
	}

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a SoftwareTPM object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const SoftwareTPM const this)

{
	STATE(S);


	if ( S->tpm_pid > 0 ) {
		kill(S->tpm_pid, SIGTERM);
		sleep(2);
	}
	if ( S->tcsd_pid > 0 ) {
		kill(S->tcsd_pid, SIGTERM);
		sleep(2);
	}

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a SoftwareTPM object.
 *
 * \return	A pointer to the initialized SoftwareTPM.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SoftwareTPM NAAAIM_SoftwareTPM_Init(void)

{
	auto Origin root;

	auto SoftwareTPM this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SoftwareTPM);
	retn.state_size   = sizeof(struct NAAAIM_SoftwareTPM_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SoftwareTPM_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->start = start;

	this->whack = whack;

	return this;
}
