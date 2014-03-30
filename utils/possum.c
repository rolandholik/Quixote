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
#define POSSUM_PORT 575


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
#include <Duct.h>

#include "Netconfig.h"
#include "IPsec.h"


/* Variable static to this file. */


/**
 * Private function.
 *
 * This function implements POSSUM host mode.  In this mode a
 * connection is listened for on the default POSSUM port for a tunnel
 * request.  Upon receipt of a connection the authentication challenge
 * is received from the client and interpreted for validity.
 *
 * If the challenge packet is from a known client it is decrypted and
 * the hardware attestation quote is verified.  The DH public key is
 * used in combination with an ephemeral key to encode a nonce to
 * be used as the shared secret.  The shared secret is encrypted
 * against the public key supplied by the guest.
 *
 * The NONCE supplied by the guest is used as an HMAC key to hash the
 * shared secret key with an expectation the client will perform the
 * same transormation.
 *
 * A listening socket is then opened and a tunnel based verification
 * connection is listened for.
 *
 * \param cfg	The configuration parameter which is used for
 *		master mode.
 *
 * \return	A boolean value is used to indicate whether or not a
 *		POSSUM connection was successfully processed.  A false
 *		value indicates a connection failure was experienced
 *		while a true value indicates succss.
 */

static _Bool host_mode(CO(Config, cfg))

{
	_Bool retn = false;

	Duct duct = NULL;

	Buffer bufr = NULL;


	duct = NAAAIM_Duct_Init();
	bufr = HurdLib_Buffer_Init();
	if ( (duct == NULL) || (bufr == NULL) )
		goto done;

	duct->init_server(duct);
	duct->init_port(duct, NULL, POSSUM_PORT);
	duct->accept_connection(duct);

	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}
	fputs("Identifier challenge: \n", stderr);
	bufr->print(bufr);

	retn = true;

 done:
	WHACK(duct);
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function implements POSSUM client mode.  In this mode a
 * connection is established to the system which is running in host
 * POSSUM hhost mode.
 *
 * When a connection is restablished the identification challenge is
 * composed and sent to the host.  The identification challenges
 * consists of the following elements encoded in an ASN1 block.
 *
 *	SCRYPT salt and identity challenge.
 *	Requested authentication time.
 *	Encrypted authentication block encrypted under OTEDKS
 *		DH public key
 *		Random NONCE
 *		Hardware quote
 *	HMAC checksum over all elements under SHA256(OTEDKS || PCR19)
 *
 * The client then waits for a host response.  The host response is
 * encoded in the above format.
 *
 * The host response is authenticated and decrypted.  The IPsec
 * encryption and authentication keys are extracted from the NONCE and
 * used to configure the IPsec tunnel.
 *
 * A tunnel connection is then established and authenticated with the
 * remote host.
 *
 * \param cfg	The configuration parameter which is used for
 *		master mode.
 *
 * \return	A boolean value is used to indicate whether or not a
 *		POSSUM connection was successfully processed.  A false
 *		value indicates a connection failure was experienced
 *		while a true value indicates succss.
 */

static _Bool client_mode(CO(Config, cfg))

{
	_Bool retn = false;

	const char * remote_ip;

	Duct duct = NULL;

	Buffer bufr = NULL;

	
	duct = NAAAIM_Duct_Init();
	bufr = HurdLib_Buffer_Init();
	if ( (duct == NULL) || (bufr == NULL) )
		goto done;

	if ( (remote_ip = cfg->get(cfg, "remote_ip")) == NULL )
		goto done;

	duct->init_client(duct);
	if ( !duct->init_port(duct, remote_ip, POSSUM_PORT) )
		goto done;

	bufr->add_hexstring(bufr, "feadbeaf");
	if ( !duct->send_Buffer(duct, bufr) ) {
		fputs("Error sending identifier.\n", stderr);
		goto done;
	}

	retn = true;

 done:
	WHACK(duct);
	WHACK(bufr);

	return retn;
}


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

	enum {host, client} mode;

	Config config = NULL;

	Buffer key     = NULL,
	       mac_key = NULL;

	IPsec ipsec = NULL;


	/* Get the root image and passwd file name. */
	while ( (opt = getopt(argc, argv, "CHp:")) != EOF )
		switch ( opt ) {
			case 'C':
				mode = client;
				break;
			case 'H':
				mode = host;
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


	/* Select execution mode. */
	switch ( mode ) {
		case host:
			host_mode(config);
			break;
		case client:
			client_mode(config);
			break;
	}
	goto done;

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
