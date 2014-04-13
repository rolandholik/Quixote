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
#if 0
#define POSSUM_PORT 575
#else
#define POSSUM_PORT 10902
#endif
#define CLIENT_SOFTWARE_STATUS "7398070fb095323464af0e9e961d5bf0e024d291faaf994bc5968293b65c33e6"
#define HOST_SOFTWARE_STATUS "e0fa54a0ba2832e4cb5bd2304956c753c16d66f300f8b46cb3a4e69af2efa73c"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <Config.h>

#include <NAAAIM.h>
#include <Duct.h>
#include <IDtoken.h>
#include <SHA256_hmac.h>
#include <Curve25519.h>

#include "Netconfig.h"
#include "IPsec.h"
#include "PossumPacket.h"


/* Variable static to this file. */


/**
 * Private function.
 *
 * This function is responsible for generating the shared key which
 * will be used between the client and host.
 *
 * The shared key is based on the following:
 *
 *	HMAC_dhkey(client_nonce ^ host_nonce)
 *
 *	Where dhkey is the shared secret generated from the Diffie-Hellman
 *	key exchange.
 *
 * \param nonce1	The first nonce to be used in key generation.
 *
 * \param nonce2	The second nonce to be used in key generation.
 *
 * \param dhkey		The Diffie-Hellman key to be used in computing
 *			the shared secret.

 * \param public	The public key to be used in combination with
 *			the public key in the dhkey parameter to generate
 *			shared secret.
 *
 * \param shared	The object which the generated key is to be
 *			loaded into.
 *
 * \return		A true value is used to indicate the key was
 *			successfully generated.  A false value indicates
 *			the key parameter does not contain a valid
 *			value.
 */

static _Bool generate_shared_key(CO(Buffer, nonce1), CO(Buffer, nonce2),    \
				 CO(Curve25519, dhkey), CO(Buffer, public), \
				 CO(Buffer, shared))

{
	_Bool retn = false;

	unsigned char *p,
		      *p1;

	unsigned int lp;

	Buffer xor = NULL,
	       key = NULL;

	SHA256_hmac hmac;


	/* XOR the supplied nonces. */
	INIT(HurdLib, Buffer, xor, goto done);
	if ( nonce1->size(nonce1) != nonce2->size(nonce2) )
		goto done;
	if ( !xor->add_Buffer(xor, nonce1) )
		goto done;

	p  = xor->get(xor);
	p1 = nonce2->get(nonce2);
	for (lp= 0; lp < xor->size(xor); ++lp) {
		*p ^= *p1;
		++p;
		++p1;
	}

	/*
	 * Generate the HMAC_SHA256 hash of the XOR'ed buffer under the
	 * computered shared key.
	 */
	INIT(HurdLib, Buffer, key, goto done);
	dhkey->compute(dhkey, public, key);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, key);
	hmac->compute(hmac);
	if ( shared->add_Buffer(shared, hmac->get_Buffer(hmac)) )
		retn = true;

 done:
	WHACK(xor);
	WHACK(key);
	WHACK(hmac);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for searching the list of attestable
 * clients based on the identification challenge.
 *
 * \param clients	A character string containing the name of
 *			the file which holds the list of clients.
 *
 * \param packet	The Buffer object containing the type 1 POSSUM
 *			packet which was received.
 *
 * \param token		An identity token populated with the identity
 *			of the client.
 *
 * \return		A true value is used to indicate the search
 *			for the client was successful.  A false value
 *			is returned if the search was unsuccessful.
 */

static _Bool find_client(CO(char *, clients), CO(Buffer, packet), \
			 CO(IDtoken, token))

{
	_Bool retn = false;

	FILE *client_file = NULL;

	Buffer b,
	       idkey	= NULL,
	       identity = NULL;

	SHA256_hmac idf;


	if ( (client_file = fopen(clients, "r")) == NULL )
		goto done;

	/* Load the identity key/salt and the asserted client identity. */
	INIT(HurdLib, Buffer, idkey, goto done);
	if ( !idkey->add(idkey, packet->get(packet), NAAAIM_IDSIZE) )
		goto done;

	INIT(HurdLib, Buffer, identity, goto done);
	if ( !identity->add(identity, packet->get(packet) + NAAAIM_IDSIZE, \
			    NAAAIM_IDSIZE) )
		goto done;

	if ( (idf = NAAAIM_SHA256_hmac_Init(idkey)) == NULL )
		goto done;

	/*
	 * Extract each available identity and compute its identity
	 * assertion against the value provided by the caller.
	 */
	while ( token->parse(token, client_file) ) {
		if ( (b = token->get_element(token, IDtoken_orgkey)) == NULL )
			goto done;
		idf->add_Buffer(idf, b);

		if ( (b = token->get_element(token, IDtoken_orgid)) == NULL )
			goto done;
		idf->add_Buffer(idf, b);

		if ( !idf->compute(idf) )
			goto done;

		if ( identity->equal(identity, idf->get_Buffer(idf)) ) {
			retn = true;
			goto done;
		}

		idf->reset(idf);
	}

 done:
	WHACK(idkey);
	WHACK(identity);
	WHACK(idf);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for composing the reply packet to
 * the initial packet1 request from the initiator.
 *
 * \param duct		The network connection which the response is
 *			to be transmitted over.
 *
 * \param packet	The packet to be used for sending the
 *			response.
 *
 * \param dhkey		The Diffie-Hellman key to be used for the
 *			exchange.
 *
 * \return		A true value is used to indicate composition
 *			and transmission of the packet was
 *			successful.  A false value indicates the
 *			process was unsuccessful.
 */

#if 0
static _Bool send_host_response(CO(Duct, duct), CO(PossumPacket, packet), \
				CO(Curve25519, dhkey))

{
	return false;
}
#endif


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

	char *cfg_item;

	FILE *token_file = NULL;

	Duct duct = NULL;

	Buffer b,
	       netbufr		= NULL,
	       nonce		= NULL,
	       software		= NULL,
	       public		= NULL,
	       shared_key	= NULL;

	IDtoken token = NULL;
	
	PossumPacket packet = NULL;

	Curve25519 dhkey = NULL;


	/* Setup the network port. */
	INIT(HurdLib, Buffer, netbufr, goto done);
	INIT(HurdLib, Buffer, software, goto done);

	INIT(NAAAIM, Duct, duct, goto done);
	duct->init_server(duct);
	duct->init_port(duct, NULL, POSSUM_PORT);
	duct->accept_connection(duct);

	/* Wait for a packet to arrive. */
	if ( !duct->receive_Buffer(duct, netbufr) )
		goto done;

	/* Find the client identity. */
	if ( (cfg_item = cfg->get(cfg, "client_list")) == NULL )
		goto done;

	INIT(NAAAIM, IDtoken, token, goto done);
	if ( !find_client(cfg_item, netbufr, token) )
		goto done;

	/* Locate and load the client file. */

	/* Verify and decode packet. */
	INIT(NAAAIM, PossumPacket, packet, goto done);
	software->add_hexstring(software, CLIENT_SOFTWARE_STATUS);
	if ( !packet->decode_packet1(packet, token, software, netbufr) )
		goto done;
	fputs("Incoming client packet 1.\n", stdout);
	packet->print(packet);

	/* Verify hardware quote. */

	/* Verify protocol. */

	/* Save the client provided nonce and public key. */
	fputs("Saving nonce and public key.\n", stdout);
	INIT(HurdLib, Buffer, nonce, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;
	if ( !nonce->add_Buffer(nonce, b) )
		goto done;

	INIT(HurdLib, Buffer, public, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_public)) == NULL )
		goto done;
	if ( !public->add_Buffer(public, b) )
		goto done;

	/* Generate DH public key for shared secret. */
	fputs("Generting DH key.\n", stdout);
	INIT(NAAAIM, Curve25519, dhkey, goto done);
	dhkey->generate(dhkey);

	/* Compose and send a reply packet. */
	fputs("Getting identity.\n", stdout);
	if ( (cfg_item = cfg->get(cfg, "identity")) == NULL )
		goto done;
	if ( (token_file = fopen(cfg_item, "r")) == NULL )
		goto done;
	token->reset(token);
	if ( !token->parse(token, token_file) )
		goto done;
	
	fputs("Composing packet.\n", stdout);
	packet->reset(packet);
	netbufr->reset(netbufr);

	packet->set_schedule(packet, token, time(NULL));
	packet->create_packet1(packet, token, dhkey);

	software->reset(software);
	software->add_hexstring(software, HOST_SOFTWARE_STATUS);
	if ( !packet->encode_packet1(packet, software, netbufr) )
		goto done;
	if ( !duct->send_Buffer(duct, netbufr) )
		goto done;
	fputs("Sent host packet 1:\n", stdout);
	packet->print(packet);

	INIT(HurdLib, Buffer, shared_key, goto done;);
	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;

	if ( !generate_shared_key(b, nonce, dhkey, public, shared_key) )
		goto done;
	fputs("\nShared key:\n", stdout);
	shared_key->hprint(shared_key);


	retn = true;

 done:
	sleep(5);

	if ( token_file != NULL )
		fclose(token_file);

	WHACK(duct);
	WHACK(netbufr);
	WHACK(nonce);
	WHACK(software);
	WHACK(public);
	WHACK(shared_key);
	WHACK(token);
	WHACK(packet);
	WHACK(dhkey);

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

	const char *cfg_item;

	FILE *token_file = NULL;

	Duct duct = NULL;

	Buffer b,
	       public,
	       nonce	  = NULL,
	       software	  = NULL,
	       bufr	  = NULL,
	       shared_key = NULL;

	IDtoken token = NULL;

	Curve25519 dhkey = NULL;

	PossumPacket packet = NULL;

	
	/* Load identity token. */
	INIT(NAAAIM, IDtoken, token, goto done);
	if ( (cfg_item = cfg->get(cfg, "identity")) == NULL )
		goto done;
	if ( (token_file = fopen(cfg_item, "r")) == NULL )
		goto done;
	if ( !token->parse(token, token_file) )
		goto done;

	/* Setup a connection to the remote host. */
	if ( (cfg_item = cfg->get(cfg, "remote_ip")) == NULL )
		goto done;

	INIT(NAAAIM, Duct, duct, goto done);
	duct->init_client(duct);
	if ( !duct->init_port(duct, cfg_item, POSSUM_PORT) )
		goto done;

	/* Send a session initiation packet. */
	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, software, goto done);
	INIT(NAAAIM, Curve25519, dhkey, goto done);

	INIT(NAAAIM, PossumPacket, packet, goto done);
	packet->set_schedule(packet, token, time(NULL));

	dhkey->generate(dhkey);
	packet->create_packet1(packet, token, dhkey);

	software->add_hexstring(software, CLIENT_SOFTWARE_STATUS);
	if ( !packet->encode_packet1(packet, software, bufr) )
		goto done;
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;

	fputs("Sent client packet 1:\n", stdout);
	packet->print(packet);

	/* Extract nonce and public key. */
	INIT(HurdLib, Buffer, nonce, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;
	nonce->add_Buffer(nonce, b);

	/* Wait for a packet to arrive. */
	packet->reset(packet);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;

	/* Find the host identity. */
	if ( (cfg_item = cfg->get(cfg, "client_list")) == NULL )
		goto done;

	token->reset(token);
	if ( !find_client(cfg_item, bufr, token) )
		goto done;

	software->reset(software);
	software->add_hexstring(software, HOST_SOFTWARE_STATUS);
	if ( !packet->decode_packet1(packet, token, software, bufr) ) {
		fprintf(stdout, "%s: Failed decode packet.\n", __func__);
		goto done;
	}

	fputs("\nReceived host packet 1.\n", stdout);
	packet->print(packet);

	INIT(HurdLib, Buffer, shared_key, goto done;);
	if ( (b = packet->get_element(packet, PossumPacket_public)) == NULL )
		goto done;
	public = b;

	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;

	if ( !generate_shared_key(b, nonce, dhkey, public, shared_key) )
		goto done;
	fputs("\nShared key:\n", stdout);
	shared_key->hprint(shared_key);
	
	retn = true;

 done:
	if ( token_file != NULL )
		fclose(token_file);

	WHACK(duct);
	WHACK(nonce);
	WHACK(software);
	WHACK(bufr);
	WHACK(shared_key);
	WHACK(token);
	WHACK(dhkey);
	WHACK(packet);

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

	goto done;
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
			if ( !host_mode(config) ) {
				fputs("Error initiating host mode.\n", \
				      stderr);
				goto done;
			}
			break;
		case client:
			if ( !client_mode(config) ) {
				fputs("Error initiating client mode.\n", \
				      stderr);
				goto done;
			}
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
	local_ip = config->get(config, "secure_local_ip");
	
	if ( !setup_tunnel_interface(interface, local_ip, local_mask, \
				     remote_net, net_mask) ) {
		fputs("Error setting up tunnel interface.\n", stderr);
		return 1;
	}


 done:
	WHACK(config);
	WHACK(key);
	WHACK(mac_key);
	WHACK(ipsec);

	return retn;
}
