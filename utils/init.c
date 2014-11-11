/** \file
 * This file implements a system manager daemon.  It is designed to
 * play a very similar role to the classic 'init' daemon in multi-user
 * systems.
 *
 * In the context of the secure platform model this daemon is invoked
 * by being exec'ed by the boot daemon from the decrypted master
 * filesystem image.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
/* Measurement UID. */
#define MEASUREMENT_UID 1

/* UID of which identity manager is to run under. */
#define IDMGR_UID 1

/* TPM daemon location. */
#define TCSD_PATH "/usr/local/sbin/tcsd"

/* System initialization file. */
#define SYSINIT "/etc/conf/rc.sysinit"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Config.h>
#include <Buffer.h>
#include <String.h>

#include <SHA256.h>

#include "Netconfig.h"
#include "SoftwareTPM.h"
#include "SoftwareStatus.h"
#include "TPMcmd.h"


/* Definitions static to this module. */
static Config Cfg = NULL;

static SoftwareTPM SWtpm = NULL;


/**
 * Internal private function.
 *
 * This function is used to read a single line from the specified
 * input stream.  The input stream is read until a linefeed is
 * encountered.
 *
 * \param input		A pointer to the input stream to be read.
 *
 * \param line		The String object which the input is loaded
 *			into.
 *
 * \return		A boolean value is used to indicate the status
 *			of the read.  A true value indicates the
 *			supplied String object contains valid data.  A
 *			false value indicates an error or an end of
 *			file condition.
 */

static _Bool _getline(FILE *input, CO(String, line))

{
	char inbufr[2] = {0, 0};

	int inchar;


	while ( (inchar = fgetc(input)) != EOF ) {
		inbufr[0] = (char) inchar;
		if ( inbufr[0] == '\n' )
			return true;
		if ( !line->add(line, inbufr) )
			return false;
	}

	return false;
}


/**
 * Private function.
 *
 * This function is responsible for terminating the init process.  By
 * default the system will reboot on exit of init.  This can be selected
 * by the 'on_exit' variable in the init configuration file.  Setting the
 * value to 'halt' will cause the system to halt.
 *
 * No arguements are expected by this function.
 *
 * This function does not return.
 */

static void do_exit(void)

{
	_Bool do_reboot = true,
	      do_halt	= false;

	char *option;


	if ( (option = Cfg->get(Cfg, "on_exit")) != NULL )
		do_halt = (strcmp(option, "halt") == 0);

	WHACK(Cfg);
	WHACK(SWtpm);

	if ( do_halt ) {
		fputs("Halting system.\n", stderr);
		reboot(RB_HALT_SYSTEM);
	}

	if ( do_reboot ) {
		fputs("Rebooting system.\n", stderr);
		reboot(RB_AUTOBOOT);
	}

	return;
}


/**
 * Private function.
 *
 * This function is responsible for starting the Trusted Platform Module
 * system.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while loading the configuration
 *		a false value is returned.  A true value indicates the
 *		platform was successfully started.
 */

static _Bool start_tpm(void)

{
	_Bool retn	   = false,
	      software_tpm = false;

	pid_t tpm_pid;

	Buffer b;

	TPMcmd tpm = NULL;

	SoftwareStatus software = NULL;


	/* Start either the software TPM stack or just the hardware stack. */
	software_tpm = (Cfg->get(Cfg, "tpm") != NULL);
	if ( software_tpm )
		software_tpm = (strcmp(Cfg->get(Cfg, "tpm"), "software") == 0);

	if ( software_tpm ) {
		INIT(NAAAIM, SoftwareTPM, SWtpm, goto done);
		if ( !SWtpm->start(SWtpm, 1) )
			goto done;
	} else {
		tpm_pid = fork();
		if ( tpm_pid == -1 )
			goto done;
		/* Child. */
		if ( tpm_pid == 0 ) {
			execl(TCSD_PATH, TCSD_PATH, "-f", "-n", NULL);
			goto done;
		}

		/* Parent - verify DAEMON is running. */
		fputs("Checking for daemon presence.\n", stderr);
		sleep(5);
		if ( kill(tpm_pid, 0) == -1 )
			goto done;
	}


	/*
	 * Generate a system software measurement if software TPM is
	 * being used.  This is done by default for a hardware TPM
	 * by the kernel.
	 */
	if ( software_tpm ) {
		INIT(NAAAIM, TPMcmd, tpm, goto done);
		INIT(NAAAIM, SoftwareStatus, software, goto done);

		if ( !software->open(software) )
			goto done;
		if ( !software->measure(software) )
			goto done;

		b = software->get_template_hash(software);
		tpm->pcr_extend(tpm, 10, b);
		fputs("software tpm: Extended software status: ", stdout);
		b->print(b);
	}

	retn = true;

 done:
	WHACK(tpm);
	WHACK(software);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for loading the init configuration into
 * the statically scoped Cfg variable.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while loading the configuration
 *		a false value is returned.  A true value indicates the
 *		configuration was successfully loaded.
 */

static _Bool load_config(void)

{
	_Bool retn = false;


	INIT(HurdLib, Config, Cfg, goto done);
	
	if ( setreuid(1, -1) == -1 )
		goto done;
	if ( !Cfg->parse(Cfg, "/etc/conf/init.conf") )
		goto done;
	if ( setreuid(geteuid(), -1) == -1 )
		goto done;

	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for setting up the loopback interface
 * for the device.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while configuring the
 *		loopback address a false value is returned.  A true
 *		value indicates the network was successfully configured.
 */

static _Bool configure_network(void)

{
	_Bool retn = false;

	Netconfig netconfig = NULL;


	INIT(NAAAIM, Netconfig, netconfig, goto done);
	if ( !netconfig->set_address(netconfig, "lo", "127.0.0.1", \
				     "255.0.0.0") )
		goto done;
	retn = true;


 done:
	WHACK(netconfig);
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for starting the identity manager daemon.
 * The identity manager is run at reduced privilege levels and is
 * assumed to start, an error is returned if the identity manager
 * terminates prematurely.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while executing the tunnel
 *		configuration a false value is returned.  A true value
 *		indicates the tunnel was successfully configured.
 */

static _Bool start_identity_manager(void)

{
	_Bool waiting = true,
	      retn    = false;

	int status,
	    tries = 0;

	pid_t idmgr;

	struct stat idmgr_stat;


	if ( (idmgr = fork()) == -1 )
		goto done;

	/* Child. */
	if ( idmgr == 0 ) {
		if ( setuid(IDMGR_UID) == -1 )
			_exit(1);
		execl("/sbin/idmgr", "idmgr", NULL);
		_exit(1);
	}

	/* Parent, set return status if identity manager is running. */
	while ( waiting && (tries++ < 30) ) {
		if ( stat("/dev/shm/IDmgr", &idmgr_stat) == 0 )
			waiting = false;
		else if ( errno == ENOENT )
			sleep(2);
	}

	switch ( waitpid(idmgr, &status, WNOHANG) ) {
		case -1:
			goto done;
		case 0:
			retn = true;
			break;
		default:
			if ( WIFEXITED(status) )
				fprintf(stdout, "idmgr exit: %d\n", \
					WEXITSTATUS(status));
			break;
	}


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for checking whether or not a system
 * measurement should be executed.  A system measurement is requested by
 * placing a signed measurement request in the system boot directory.
 *
 * No arguements are expected by this function.
 *
 * \return	The return value of this system is used to indicate
 *		whether or not the system should proceed forward.  If
 *		a measurement is requested and/or succeeds a false value
 *		is returned.   true value is used to indicate the system
 *		should proceed forward with initialization.
 */

static _Bool measure_system(void)

{
	_Bool retn = true;

	int status;

	const char * const measurement = "/mnt/boot/measurement";
	const char * const verifier    = "/usr/local/sbin/gen-id-verifier";

	pid_t pid;

	struct stat measurement_stat;


	/* Check for presence of measurement request. */
	if ( stat(measurement, &measurement_stat) != 0 ) 
		goto done;

	/* Generate the system measurement. */
	if ( (pid = fork()) == -1 )
		goto done;

	/* Child. */
	if ( pid == 0 ) {
		if ( chdir(measurement) != 0 )
			goto done;
		execl(verifier, verifier, "-m", "-f", "-u", "/etc/conf/aik", \
		      (char *) NULL);
		goto done;
	}

	/* Parent - wait for verification to complete. */
	if ( waitpid(pid, &status, 0) == -1 )
		goto done;
	fputs("System measurement generated - rebooting.\n", stderr);
	sync();
	sleep(2);
	retn = false;


 done:
	chdir("/");
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for running the set of commands needed
 * to configure the system.  These commands are stored in the
 * /etc/conf/rc.sysinit file.  A non-zero return code from any command
 * in this file is considered an error.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while executing on of the
 *		commands needed for system configuration a false value
 *		is returned.  A true value indicates the system was
 *		successfully configured.
 */

static _Bool run_sysinit(void)

{
	_Bool retn = false;

	FILE *infile;

	String line = NULL;


	INIT(HurdLib, String, line, goto done);

	if ( (infile = fopen(SYSINIT, "r")) == NULL )
		goto done;

	while ( !feof(infile) ) {
		if ( !_getline(infile, line) )
			goto done;
		fprintf(stderr, "\t%s\n", line->get(line));
		if ( system(line->get(line)) != 0 )
			goto done;
		line->reset(line);
	}
	if ( feof(infile) )
		retn = true;


 done:
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	fputs("Loading configuration.\n", stderr);
	if ( !load_config() )
		goto done;

	fputs("Configuring network.\n", stderr);
	if ( !configure_network() )
		goto done;

	fputs("Starting TPM.\n", stderr);
	if ( !start_tpm() )
		goto done;

	fputs("Starting identity manager.\n", stderr);
	if ( !start_identity_manager() )
		goto done;

	fputs("Checking system measurement request.\n", stderr);
	if ( !measure_system() )
		goto done;

	fputs("Running system initialization.\n", stderr);
	if ( !run_sysinit() )
		goto done;


 done:
	do_exit();
	return retn;
}
