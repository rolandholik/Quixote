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


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Config.h>

#include "Netconfig.h"


/* Definitions static to this module. */
static Config Cfg = NULL;

static char *Mode = NULL;


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
	

/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;


	if ( !load_config() )
		goto done;

	if ( !configure_network() )
		goto done;

	fprintf(stdout, "%s: OK\n", Mode);
	execl("/bin/sh", "/bin/sh", NULL);


 done:
	WHACK(Cfg);
	do_reboot();
	return retn;
}
