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
/* UID of which identity manager is to run under. */
#define IDMGR_UID 1


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
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
	_Bool retn = false;

	Buffer b;

	TPMcmd tpm = NULL;

	SoftwareStatus software = NULL;


	INIT(NAAAIM, SoftwareTPM, SWtpm, goto done);
	if ( !SWtpm->start(SWtpm, 1) )
	     goto done;

	INIT(NAAAIM, TPMcmd, tpm, goto done);
	INIT(NAAAIM, SoftwareStatus, software, goto done);
	if ( !software->open(software) )
		goto done;
	if ( !software->measure(software) )
		goto done;

	b = software->get_template_hash(software);
	tpm->pcr_extend(tpm, 10, b);
	fputs("Extended software status: ", stdout);
	b->print(b);

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
	_Bool retn = false;

	int status;

	pid_t idmgr;


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
	sleep(10);
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

	fputs("Starting internal tunnel.\n", stderr);
	configure_internal_tunnel();
#if 0
	if ( !configure_internal_tunnel() )
		goto done;
#endif

	fprintf(stdout, "%s: OK\n", Mode);
	execl("/bin/sh", "/bin/sh", NULL);


 done:
	WHACK(Cfg);
	WHACK(SWtpm);
	do_reboot();
	return retn;
}
