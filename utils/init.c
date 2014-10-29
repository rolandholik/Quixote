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

#include <SHA256.h>

#include "Netconfig.h"
#include "SoftwareTPM.h"
#include "SoftwareStatus.h"
#include "TPMcmd.h"


/* Definitions static to this module. */
static Config Cfg = NULL;

static char *Mode = NULL;

static SoftwareTPM SWtpm = NULL;


/**
 * Private function.
 *
 * This function is responsible for terminating the boot process.  It
 * requests a reboot of the system.
 *
 * No arguements are expected by this function.
 *
 * This function does not return.
 */

static void do_reboot(void)

{
	fputs("Reboot requested.\n", stderr);
	reboot(RB_HALT_SYSTEM);
	return;

#if 0
	fputs("Rebooting.\n", stderr);
	reboot(RB_AUTOBOOT);
#endif
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
			execl(TCSD_PATH, TCSD_PATH, "-f", NULL);
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

	if ( (Mode = Cfg->get(Cfg, "mode")) == NULL )
		goto done;
	retn = true;

 done:
	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for setting up the base network
 * configuration for the platform.  The network configuration is
 * obtained from the global Cfg variable.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while configuring the
 *		network a false value is returned.  A true value indicates
 *		the network was successfully configured.
 */

static _Bool configure_network(void)

{
	_Bool retn = false;

	char *iface,
	     *address,
	     *mask;

	Netconfig netconfig = NULL;


	INIT(NAAAIM, Netconfig, netconfig, goto done);
	if ( !netconfig->set_address(netconfig, "lo", "127.0.0.1", \
				     "255.0.0.0") )
		goto done;
	WHACK(netconfig);

	iface   = Cfg->get(Cfg, "interface");
	address = Cfg->get(Cfg, "address");
	mask	= Cfg->get(Cfg, "mask");
	if ( (iface == NULL) || (address == NULL) || (mask == NULL) )
		goto done;

	INIT(NAAAIM, Netconfig, netconfig, goto done);
	if ( !netconfig->set_address(netconfig, iface, address, mask) )
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
	while ( waiting && (tries++ < 10) ) {
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
		execl(verifier, verifier, "-m", "-f", "-k",	 \
		      "/etc/conf/pubkey", "-u", "/etc/conf/aik", \
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
 * This function is responsible for configuring the internal IPsec tunnel
 * used to transport commands between the two nodes.  The static Mode
 * variable is used to specify the personality type for the connection.
 *
 * No arguements are expected by this function.
 *
 * \return	If an error is encountered while executing the tunnel
 *		configuration a false value is returned.  A true value
 *		indicates the tunnel was successfully configured.
 */

static _Bool configure_internal_tunnel(void)

{
	_Bool changed_uid = false,
	      retn	  = false;

	char *cmd = NULL;


	if ( setreuid(1, -1) == -1 )
		goto done;
	changed_uid = true;
	
	if ( strcmp(Mode, "liu") == 0 ) {
		sleep(5);
		cmd = "possum -C -p liu";
	}
	if ( strcmp(Mode, "hui") == 0 )
		cmd = "possum -H -p hui";
	if ( cmd == NULL )
		goto done;

	if ( system(cmd) != 0 )
		goto done;
	retn = true;
	
 done:
	if ( changed_uid && (setreuid(geteuid(), -1) == -1) )
		retn = false;
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

	fputs("Starting internal tunnel.\n", stderr);
	if ( !configure_internal_tunnel() )
		goto done;

	if ( strcmp(Mode, "hui") == 0 ) {
		fputs("Starting identity engine.\n", stderr);
		system("/usr/local/sbin/idgine &");
		sleep(5);
		fputs("Starting identity server.\n", stderr);
		execl("/usr/local/sbin/idsvr", "/usr/local/sbin/idsvr", \
		      "-h", "10.0.2.1", NULL);
	} else {
		fprintf(stdout, "%s: OK\n", Mode);
		execl("/bin/sh", "/bin/sh", NULL);
	}


 done:
	WHACK(Cfg);
	WHACK(SWtpm);

	do_reboot();
	return retn;
}
