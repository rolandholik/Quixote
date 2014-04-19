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

#define CLIENT_SPI_ARENA	0x10000
#define HOST_SPI_ARENA		0x20000
#define RESERVE_SPI_ARENA	0x30000


/* Include files. */
#include <stdint.h>
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
#include <SHA256.h>
#include <SHA256_hmac.h>
#include <Curve25519.h>
#include <RandomBuffer.h>

#include "Netconfig.h"
#include "IPsec.h"
#include "PossumPacket.h"


/* Variable static to this file. */
struct ipsec_parameters {
	uint32_t enc_key_length;
	uint32_t mac_key_length;
	const char *enc_type;
	const char *mac_type;
};


/**
 * Private function.
 *
 * This function is responsible for decoding the POSSUM protocol parameter
 * code into an encryption and authentication type as well as the
 * key lengths needed to support these protocols.
 *
 * \param protocol	The numeric protocol number defined which is
 *			requested.
 *
 * \param params	A pointer to a structure which encapsulates
 *			the protocol parameters.
 *
 * \return		A true value indicates the protocol parameter
 *			was successfully decoded, a false value indicate
 *			an element of the protocol was unknown.
 */

static _Bool setup_sa_parameters(const uint32_t protocol, \
				 struct ipsec_parameters *params)

{
	uint32_t encryption	= protocol >> 24,
		 authentication = (protocol >> 16) & UINT8_MAX;

	static const char *tripledes = "3des-cbc",
			  *hmac_md5  = "hmac-md5";


	memset(params, '\0', sizeof(struct ipsec_parameters));

	switch ( encryption ) {
		case POSSUM_PACKET_TRIPLEDES_CBC:
			params->enc_type       = tripledes;
			params->enc_key_length = 192 / 8;
			break;
	}

	switch ( authentication ) {
		case POSSUM_PACKET_HMAC_MD5:
			params->mac_type       = hmac_md5;
			params->mac_key_length = 128 / 8;
			break;
	}


	if ( (params->enc_type != NULL) && (params->mac_type != NULL) && \
	     (params->enc_key_length != 0) && (params->mac_key_length != 0) )
		return true;
	return false;
}


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


/**
 * Private function.
 *
 * This function is responsible for starting an IPsec tunnel based on
 * the specified configuration and parameters.
 *
 * \param cfg		The configuration object which specifies the
 *			parameters for the connection.
 *
 * \param protocol	The numeric description of the protocol.
 *
 * \param spi		The security parameter index to be used.
 *
 * \param shared_key	The object containing the shared key to be
 *			used in establishing the connection.
 *
 * \return	A boolean value is used to indicate the status of the
 *		connection being started.  Failure is denoted by
 *		returning a false value while success is indicated by
 *		a true value.
 */

static _Bool setup_ipsec(CO(Config, cfg), const uint32_t protocol, \
			 const uint32_t spi, CO(Buffer, shared_key))

{
	_Bool retn = false;

	unsigned char *k;

	char *interface,
	     *local_ip,
	     *local_mask,
	     *remote_ip,
	     *local_net,
	     *remote_net,
	     *net_mask;

	struct ipsec_parameters ipsec_params;

	Buffer enc_key = NULL,
	       mac_key = NULL;

	SHA256 sha256 = NULL;

	IPsec ipsec = NULL;


	/* Initialize IPsec configuration object. */
	INIT(NAAAIM, IPsec, ipsec, goto done);

	/* Extract IPsec parameters. */
	local_ip   = cfg->get(cfg, "local_ip");
	local_mask = cfg->get(cfg, "local_mask");
	remote_ip  = cfg->get(cfg, "remote_ip");
	if ( (local_ip == NULL) || (local_mask == NULL) || \
	     (remote_ip == NULL) )
		goto done;

	/*
	 * Resolve the security association parameters from the
	 * protocol specification.
	 */
	if ( !setup_sa_parameters(protocol, &ipsec_params) )
		goto done;

	/* Setup the encryption key. */
	INIT(HurdLib, Buffer, enc_key, goto done);
	k = shared_key->get(shared_key);
	if ( !enc_key->add(enc_key, k, ipsec_params.enc_key_length) )
		goto done;
	fprintf(stdout, "%s: IPSEC encryption key:\n", __func__);
	enc_key->hprint(enc_key);
	fputc('\n', stdout);

	/* Setup the authentication key. */
	INIT(HurdLib, Buffer, mac_key, goto done);
	INIT(NAAAIM, SHA256, sha256, goto done);

	sha256->add(sha256, shared_key);
	sha256->compute(sha256);
	if ( (k = sha256->get(sha256)) == NULL )
		goto done;
	if ( !mac_key->add(mac_key, k, ipsec_params.mac_key_length) )
		goto done;
	fprintf(stdout, "%s: IPSEC authentication key:\n", __func__);
	mac_key->hprint(mac_key);
	fputc('\n', stdout);

	/* Setup the security association. */
	if ( !ipsec->setup_sa(ipsec, local_ip, remote_ip, spi,	\
			      ipsec_params.enc_type, enc_key,	\
			      ipsec_params.mac_type, mac_key) ) {
		fputs("Error setting security association 1.\n", stderr);
		goto done;
	}

	/* Setup the security policy database. */
	local_net  = cfg->get(cfg, "secure_local_net");
	remote_net = cfg->get(cfg, "secure_remote_net");
	net_mask   = cfg->get(cfg, "secure_net_mask");
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
	interface = cfg->get(cfg, "interface");
	local_ip  = cfg->get(cfg, "secure_local_ip");
	if ( (interface == NULL) || (local_ip == NULL) )
		goto done;
	
	if ( !setup_tunnel_interface(interface, local_ip, local_mask, \
				     remote_net, net_mask) ) {
		fputs("Error setting up tunnel interface.\n", stderr);
		return 1;
	}

	retn = true;

 done:
	WHACK(enc_key);
	WHACK(mac_key);
	WHACK(sha256);
	WHACK(ipsec);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for two forms of functionality.  The
 * first form, if the spi value is set to zero, checks to see if the
 * SPI is in use in the specified arena.
 *
 * In the second form an unused SPI is nominated from the specified
 * allocation arena.
 *
 * \param base	The SPI arena from which the proposal is to be taken.
 *
 * \param spi	The SPI which is to be checked.  A zero value is used
 *		to indicate that a proposal should be made.
 *
 * \return	If a proposal values a value of zero is returned to
 *		the caller.
 */

static uint32_t propose_spi(CO(uint32_t, base), uint32_t use_spi)

{
        uint16_t cnt;

	uint32_t spi = 0;

	Buffer b;

	IPsec ipsec = NULL;

	RandomBuffer rnd = NULL;


	/* Check to see if an SPI has been proposed and is in use. */
	INIT(NAAAIM, IPsec, ipsec, goto done);
	if ( use_spi != 0 ) {
		use_spi += base;
		if ( !ipsec->have_spi(ipsec, use_spi) )
			spi = use_spi;
		goto done;
	}

	/* Propose an SPI based on the supplied base. */
	INIT(NAAAIM, RandomBuffer, rnd, goto done);
	cnt = 0;
	spi = 0;
	while ( (spi == 0) && (cnt < UINT16_MAX) ) {
		rnd->generate(rnd, 2);
		b = rnd->get_Buffer(rnd);
		spi = *((uint16_t *) b->get(b));
		if ( ipsec->have_spi(ipsec, spi) )
			spi = 0;
	}
	if ( spi == 0 )
		goto done;
	if ( base == RESERVE_SPI_ARENA )
		spi += base;

 done:
	WHACK(ipsec);
	WHACK(rnd);

	return spi;
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
 * \param cfg		The configuration parameter which is used for
 *			master mode.
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

	uint32_t tspi,
		 spi,
		 protocol;

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
	fprintf(stdout, "%s: Raw receive packet:\n", __func__);
	netbufr->hprint(netbufr);
	fputc('\n', stdout);

	/* Find the client identity. */
	if ( (cfg_item = cfg->get(cfg, "client_list")) == NULL )
		goto done;

	INIT(NAAAIM, IDtoken, token, goto done);
	if ( !find_client(cfg_item, netbufr, token) )
		goto done;

	/* Locate and load the client file. */

	/* Verify and decode packet. */
	INIT(NAAAIM, PossumPacket, packet, goto done);
	if ( (cfg_item = cfg->get(cfg, "remote_software")) == NULL )
		goto done;
	software->add_hexstring(software, cfg_item);
	if ( !packet->decode_packet1(packet, token, software, netbufr) )
		goto done;
	fprintf(stdout, "%s: Incoming client packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	/* Verify hardware quote. */

	/* Verify protocol. */

	/* Save the client provided nonce and public key. */
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
	INIT(NAAAIM, Curve25519, dhkey, goto done);
	dhkey->generate(dhkey);

	/* Compose and send a reply packet. */
	if ( (cfg_item = cfg->get(cfg, "identity")) == NULL )
		goto done;
	if ( (token_file = fopen(cfg_item, "r")) == NULL )
		goto done;
	token->reset(token);
	if ( !token->parse(token, token_file) )
		goto done;
	
	packet->reset(packet);
	netbufr->reset(netbufr);

	/*
	 * Check both SPI's proposed by the caller.  If neither are
	 * available allocate an SPI from the reserve arena.
	 */
	if ( (tspi = packet->get_value(packet, PossumPacket_spi)) == 0 )
		goto done;
	spi = propose_spi(HOST_SPI_ARENA, tspi & UINT16_MAX);
	if ( spi == 0 )
		spi = propose_spi(CLIENT_SPI_ARENA, tspi >> 16);
	if ( spi == 0 )
		spi = propose_spi(RESERVE_SPI_ARENA, 0);
	if ( spi == 0 )
		goto done;

	packet->set_schedule(packet, token, time(NULL));
	packet->create_packet1(packet, token, dhkey, spi);

	software->reset(software);
	if ( (cfg_item = cfg->get(cfg, "software")) == NULL )
		goto done;
	software->add_hexstring(software, cfg_item);
	if ( !packet->encode_packet1(packet, software, netbufr) )
		goto done;
	if ( !duct->send_Buffer(duct, netbufr) )
		goto done;
	fprintf(stdout, "%s: Sent host packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	INIT(HurdLib, Buffer, shared_key, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;

	if ( !generate_shared_key(b, nonce, dhkey, public, shared_key) )
		goto done;
	fprintf(stdout, "%s: shared key:\n", __func__);
	shared_key->print(shared_key);
	fputc('\n', stdout);

	spi	 = packet->get_value(packet, PossumPacket_spi);
	protocol = packet->get_value(packet, PossumPacket_protocol);
	setup_ipsec(cfg, protocol, spi, shared_key);

	retn = true;

 done:

	if ( token_file != NULL )
		fclose(token_file);

	sleep(5);
	WHACK(duct);
	WHACK(netbufr);
	WHACK(nonce);
	WHACK(software);
	WHACK(public);
	WHACK(token);
	WHACK(packet);
	WHACK(dhkey);
	WHACK(shared_key);

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
 * \param cfg		The configuration parameter which is used for
 *			master mode.
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

	uint32_t spi,
		 tspi,
		 protocol;

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
	tspi = propose_spi(CLIENT_SPI_ARENA, 0);
	spi = tspi << 16;
	tspi = propose_spi(HOST_SPI_ARENA, 0);
	spi = spi | tspi;

	packet->create_packet1(packet, token, dhkey, spi);

	if ( (cfg_item = cfg->get(cfg, "software")) == NULL )
		goto done;
	software->add_hexstring(software, cfg_item);
	if ( !packet->encode_packet1(packet, software, bufr) )
		goto done;
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;

	fprintf(stdout, "%s: Sent client packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

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
	fprintf(stdout, "%s: Raw receive packet:\n", __func__);
	bufr->hprint(bufr);
	fputc('\n', stdout);

	/* Find the host identity. */
	if ( (cfg_item = cfg->get(cfg, "client_list")) == NULL )
		goto done;

	token->reset(token);
	if ( !find_client(cfg_item, bufr, token) )
		goto done;

	software->reset(software);
	if ( (cfg_item = cfg->get(cfg, "remote_software")) == NULL )
		goto done;
	software->add_hexstring(software, cfg_item);
	if ( !packet->decode_packet1(packet, token, software, bufr) ) {
		fprintf(stdout, "%s: Failed decode packet.\n", __func__);
		goto done;
	}

	fprintf(stdout, "%s: Received host packet 1.\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	if ( (b = packet->get_element(packet, PossumPacket_public)) == NULL )
		goto done;
	public = b;

	if ( (b = packet->get_element(packet, PossumPacket_nonce)) == NULL )
		goto done;

	INIT(HurdLib, Buffer, shared_key, goto done);
	if ( !generate_shared_key(b, nonce, dhkey, public, shared_key) )
		goto done;
	fprintf(stdout, "%s: shared key:\n", __func__);
	shared_key->print(shared_key);
	fputc('\n', stdout);

	spi	 = packet->get_value(packet, PossumPacket_spi);
	protocol = packet->get_value(packet, PossumPacket_protocol);
	setup_ipsec(cfg, protocol, spi, shared_key);
	retn = true;

 done:
	if ( token_file != NULL )
		fclose(token_file);

	WHACK(duct);
	WHACK(nonce);
	WHACK(software);
	WHACK(bufr);
	WHACK(token);
	WHACK(dhkey);
	WHACK(packet);
	WHACK(shared_key);

	return retn;
}

	
/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	char *personality;

	int opt;

	enum {host, client} mode;

	Config config = NULL;


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

 done:
	WHACK(config);

	return retn;
}
