/** \file
 * This file contains the implementation of the hardware attested IPsec
 * tunnel configuration utility.
 *
 * This utility is responsible for using One Time Identification (OTI)
 * in combination with hardware attestation to authenticate and configure
 * a tunnel mode (ESP) connection to a host device.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
/* Macro to clear object pointer if not NULL. */
#define WHACK(obj) if (obj != NULL) {obj->whack(obj); obj = NULL;}

/* Macro for defining a pointer to a constance object. */
#define CO(obj, var) const obj const var

/* Setkey utility location. */
#define SETKEY_PATH "/usr/local/sbin/setkey"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <Config.h>

#include "Netconfig.h"
#include "IPsec.h"


/* Variable static to this file. */


/**
 * Private function.
 *
 * This function is responsible for configuring a physical interface
 * over which the IPsec tunnel will be constructed.
 *
 * \param ip	The IP address to be assigned to the interface.
 *
 * \param mask	The netmask to be applied to the interface address.
 *
 * \param gw	The gateway address, this may be NULL in which case
 *		a default route will not be set.
 *
 * \return	A boolean value is used to indicate the status of the
 *		interface configuration.  Failure is denoted by returning
 *		a false value while success is indicated by a true value.
 */

static _Bool setup_tunnel_interface(CO(char *, iface), CO(char *, ip), \
				    CO(char *, ip_mask),	       \
				    CO(char *, net_remote),	       \
				    CO(char *, net_mask))

{
	_Bool retn = false;

	Netconfig netconfig = NULL;


	fprintf(stderr, "iface: %s\n", iface);
	fprintf(stderr, "ip: %s/%s\n", ip, ip_mask);
	fprintf(stderr, "remote: %s/%s\n", net_remote, net_mask);

	if ( (netconfig = NAAAIM_Netconfig_Init()) == NULL )
		goto done;
	if ( !netconfig->set_address(netconfig, iface, ip, ip_mask) )
		goto done;
	if ( !netconfig->set_route(netconfig, net_remote, ip, net_mask) )
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

	char *p,
	     *personality,
	     *interface,
	     *local_ip,
	     *local_mask,
	     *remote_ip,
	     *local_net,
	     *remote_net,
	     *net_mask;

	int opt;

	enum {initialize, accept} mode;

	Config config = NULL;

	Buffer key     = NULL,
	       mac_key = NULL;

	IPsec ipsec = NULL;


	/* Get the root image and passwd file name. */
	while ( (opt = getopt(argc, argv, "ACp:")) != EOF )
		switch ( opt ) {
			case 'A':
				mode = initialize;
				break;
			case 'I':
				mode = accept;
				break;

			case 'p':
				personality = optarg;
				break;
		}


	/* Verify parameters. */
	if ( personality == NULL ) {
		fputs("No personality specified.\n", stderr);
		return 1;
	}

        if ( (config = HurdLib_Config_Init()) == NULL ) {
		fputs("Error initializing configuration.", stderr);;
                goto done;
        }
        if ( !config->parse(config, "possum.conf") ) {
                fputs("Error parsing configuration file.", stderr);
                goto done;
        }
	if ( !config->set_section(config, personality) ) {
		fputs("Personality section not found.\n", stderr);
		goto done;
	}

	/* Setup physical link. */
	local_ip   = config->get(config, "local_ip");
	local_mask = config->get(config, "local_mask");
	remote_ip  = config->get(config, "remote_ip");
	interface  = config->get(config, "interface");
	if ( (local_ip == NULL) || (local_mask == NULL) || \
	     (remote_ip == NULL) ) {
		fputs("Client/host IP specification error.\n", stderr);
		goto done;
	}

	/* Setup security association. */
	if ( (ipsec = NAAAIM_IPsec_Init()) == NULL )
		goto done;

	if ( (key = HurdLib_Buffer_Init()) == NULL )
		goto done;

	if ( (p = config->get(config, "enc_key")) == NULL ) {
		fputs("Error loading encryption key.\n", stderr);
		goto done;
	}
	key->add_hexstring(key, p);

	if ( (mac_key = HurdLib_Buffer_Init()) == NULL )
		goto done;

	if ( (p = config->get(config, "mac_key")) == NULL ) {
		fputs("Error load mac key.\n", stderr);
		goto done;
	}
	mac_key->add_hexstring(mac_key, p);

	if ( !ipsec->setup_sa(ipsec, local_ip, remote_ip, 0x201, \
			      "3des-cbc", key, "hmac-md5", mac_key) ) {
		fputs("Error setting security association 1.\n", stderr);
		goto done;
	}


	local_net = config->get(config, "secure_local_net");
	remote_net = config->get(config, "secure_remote_net");
	net_mask = config->get(config, "secure_net_mask");
	if ( (local_net == NULL) || (remote_net == NULL) || \
	     (net_mask == NULL) ) {
		fputs("Error in network parameter specifications.\n", stderr);
		goto done;
	}

	if ( !ipsec->setup_spd(ipsec, local_ip, remote_ip, \
			       local_net, remote_net, net_mask) ) {
		fputs("Error setting security policy 1.\n", stderr);
		goto done;
	}

	/* Configure secure network interface and route. */
#if 0
	local_ip = config->get(config, "secure_local_ip");
	
	if ( !setup_tunnel_interface(interface, local_ip, local_mask, \
				     remote_net, net_mask) ) {
		fputs("Error setting up tunnel interface.\n", stderr);
		return 1;
	}
#endif


 done:
	WHACK(config);
	WHACK(key);
	WHACK(mac_key);
	WHACK(ipsec);

	return retn;
}
