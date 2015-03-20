/** \file
 * This file contains the implementation of the PossumPipe object.
 * This object provides a conduit for implementing secured
 * communication between two devices based on the identity and mutual
 * attestation state of the devices.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <glob.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Config.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <IDtoken.h>
#include <SHA256.h>
#include <SHA256_hmac.h>
#include <AES256_cbc.h>
#include <RandomBuffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "SoftwareStatus.h"
#include "Curve25519.h"
#include "PossumPacket.h"
#include "IDmgr.h"
#include "Ivy.h"
#include "TPMcmd.h"
#include "PossumPipe.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PossumPipe_OBJID)
#error Object identifier not defined.
#endif

/* State extraction macro. */
#define STATE(var) CO(PossumPipe_State, var) = this->state


/** PossumPipe private state information. */
struct NAAAIM_PossumPipe_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Network connection object. */
	Duct duct;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_PossumPipe_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information which
 *        	is to be initialized.
 */

static void _init_state(CO(PossumPipe_State,S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PossumPipe_OBJID;

	return;
}


/**
 * Private function.
 *
 * This function is responsible for searching the list of attestable
 * clients based on the identification challenge.
 *
 * \param packet	The Buffer object containing the type 1 POSSUM
 *			packet which was received.
 *
 * \param token		The IDtoken object which will be loaded with
 *			the identity token which identifies the
 *			client.
 *
 * \param ivy		The identify verifier object which will be
 *			loaded with the verifier which matches the
 *			client.
 *
 * \return		A true value is used to indicate the search
 *			for the client was successful.  A false value
 *			is returned if the search was unsuccessful.
 */

static _Bool find_client(CO(Buffer, packet), CO(IDtoken, token), CO(Ivy, ivy))

{
	_Bool retn	 = false,
	      changed_id = false;

	size_t lp;

	glob_t identities;

	Buffer b,
	       asn	= NULL,
	       idkey	= NULL,
	       identity = NULL;

	File file = NULL;

	SHA256_hmac idf = NULL;


	/* Loop over the available identities. */
	INIT(HurdLib, Buffer, asn, goto done);
	INIT(HurdLib, Buffer, idkey, goto done);
	INIT(HurdLib, Buffer, identity, goto done);
	INIT(HurdLib, File, file, goto done);

	/* Load the identity key/salt and the asserted client identity. */
	if ( !idkey->add(idkey, packet->get(packet), NAAAIM_IDSIZE) )
		goto done;
	if ( !identity->add(identity, packet->get(packet) + NAAAIM_IDSIZE, \
			    NAAAIM_IDSIZE) )
		goto done;
	if ( (idf = NAAAIM_SHA256_hmac_Init(idkey)) == NULL )
		goto done;


	/*
	 * Extract each available identity and compute its identity
	 * assertion against the value provided by the caller.
	 *
	 * The call to the glob() function is done with non-root
	 * privileges in order to prevent the device identification
	 * files from being incorporated in the system measurement.
	 */
#if 0
	if ( setreuid(1, -1) == -1 )
		goto done;
	changed_id = true;
#endif

	if ( glob("/etc/conf/*.ivy", 0, NULL, &identities) != 0 )
		goto done;

	for (lp= 0; lp < identities.gl_pathc; ++lp) {
		token->reset(token);
		ivy->reset(ivy);

		file->open_ro(file, identities.gl_pathv[lp]);
		if ( !file->slurp(file, asn) )
			goto done;
		file->reset(file);

		if ( !ivy->decode(ivy, asn) )
			goto done;
		asn->reset(asn);

		/* Extract identity token. */
		if ( (b = ivy->get_element(ivy, Ivy_id)) == NULL )
			goto done;
		if ( !token->decode(token, b) )
			goto done;

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
	if ( changed_id ) {
		if ( setreuid(geteuid(), -1) == -1 )
			retn = false;
	}

	WHACK(asn);
	WHACK(idkey);
	WHACK(identity);
	WHACK(file);
	WHACK(idf);

	return retn;
}


#if 0
/**
 * Private function.
 *
 * This function is responsible for setting the active personality in
 * the configuration object to the identity of the counter-party
 * which is requesting setup of the session.
 *
 * \param config	The configuration object which is to have its
 *			personality configured.
 *
 * \param token	        The identity of the counter-party involved in
 *			the connection.  The organizational ID of this
 *			counter-party is used as the personality name
 *			of the section.
 *
 * \return		A false value indicates the personality could
 *			not be set or did not exist.  A true value
 *			indicates the personality was successfuly
 *			set.
 */

static _Bool set_counter_party_personality(CO(Config, cfg), CO(IDtoken, token))

{
	_Bool retn = false;

	unsigned char *p;

	char bufr[3];

	size_t lp,
	       cnt;

	Buffer b;

	String personality = NULL;


	INIT(HurdLib, String, personality, goto done);
	if ( (b = token->get_element(token, IDtoken_id)) == NULL )
		goto done;

	p   = b->get(b);
        cnt = b->size(b);
        for (lp= 0; lp < cnt; ++lp) {
                snprintf(bufr, sizeof(bufr), "%02x", *p);
                personality->add(personality, bufr);
                ++p;
        }

	if ( cfg->set_section(cfg, personality->get(personality)) )
		retn = true;

 done:
	WHACK(personality);

	return retn;
}
#endif


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
	 * Generate the HMAC_SHA256 hash of the XOR'ed buffer under
	 * the ECDH generated key.
	 */
	INIT(HurdLib, Buffer, key, goto done);
	dhkey->compute(dhkey, public, key);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, xor);
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
 * This function waits to receive a hardware reference quote.
 *
 * \param duct		The network object which the reference quote is
 *			to be received on.
 *
 * \param bufr		The Buffer object which is to be used to receive
 *			the platform quote.
 *
 * \param ivy		The identify reference which is to be used to
 *			verify the platform reference quote.
 *
 * \param nonce		The nonce which was used to create the reference.
 *
 * \param key		The shared key to be used to decrypt the reference
 *			quote.
 *
 * \return		If the quote is received and verified a true
 *			value is returned.  If an error is encountered a
 *			false value is returned.
 */

static _Bool receive_platform_quote(CO(Duct, duct), CO(Buffer, bufr), \
				    CO(Ivy, ivy), CO(Buffer, nonce),  \
				    CO(Buffer, key))

{
	_Bool retn = false;

	size_t payload;

	Buffer pubkey,
	       ref,
	       cksum = NULL,
	       iv    = NULL,
	       quote = NULL;

	TPMcmd tpmcmd = NULL;

	AES256_cbc cipher = NULL;

	SHA256_hmac hmac = NULL;


	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;


	INIT(HurdLib, Buffer, cksum, goto done);
	payload = bufr->size(bufr) - 32;
	cksum->add(cksum, bufr->get(bufr) + payload, 32);


	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	bufr->shrink(bufr, 32);
	hmac->add_Buffer(hmac, bufr);
	if ( !hmac->compute(hmac) )
		goto done;
	if ( !cksum->equal(cksum, hmac->get_Buffer(hmac)) )
		goto done;


	INIT(HurdLib, Buffer, iv, goto done);
	if ( !iv->add(iv, bufr->get(bufr), 16) )
		goto done;

	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		goto done;

	INIT(HurdLib, Buffer, quote, goto done);
	cksum->reset(cksum);
	if ( !cksum->add(cksum, bufr->get(bufr) + 16, bufr->size(bufr) - 16) )
		goto done;
	if ( !cipher->decrypt(cipher, cksum) )
		goto done;
	if ( !quote->add_Buffer(quote, cipher->get_Buffer(cipher)) )
		goto done;


	INIT(NAAAIM, TPMcmd, tpmcmd, goto done);

	if ( (pubkey = ivy->get_element(ivy, Ivy_pubkey)) == NULL )
		goto done;
	if ( (ref = ivy->get_element(ivy, Ivy_reference)) == NULL )
		goto done;
	if ( !tpmcmd->verify(tpmcmd, pubkey, ref, nonce, quote) )
		goto done;

	retn = true;


 done:
	WHACK(cksum);
	WHACK(iv);
	WHACK(quote);
	WHACK(tpmcmd);
	WHACK(cipher);
	WHACK(hmac);

	return retn;
}


/**
 * Private function.
 *
 * This function creates and sends a platform reference quote.
 *
 * \param duct		The network object which the reference quote is
 *			to be sent on on.
 *
 * \param bufr		The Buffer object which is to be used to transmit
 *			the platform quote.
 *
 * \param key		The shared key to be used to encrypt the reference
 *			quote.
 *
 * \param nonce		The nonce to be used to generate the quote.
 *
 * \return		If the quote is received and verified a true
 *			value is returned.  If an error is encountered a
 *			false value is returned.
 */

static _Bool send_platform_quote(CO(Duct, duct), CO(Buffer, bufr), \
				 CO(Buffer, key), CO(Buffer, nonce))

{
	_Bool retn = false;

	Buffer b,
	       uuid  = NULL,
	       quote = NULL;

	File aik_file = NULL;

	TPMcmd tpmcmd = NULL;

	AES256_cbc cipher = NULL;

	RandomBuffer iv = NULL;

	SHA256_hmac hmac = NULL;


	INIT(HurdLib, File, aik_file, goto done);
	INIT(HurdLib, Buffer, uuid, goto done);
	aik_file->open_ro(aik_file, "/etc/conf/aik");
	if ( !aik_file->slurp(aik_file, uuid) )
		goto done;

	INIT(NAAAIM, TPMcmd, tpmcmd, goto done);
	INIT(HurdLib, Buffer, quote, goto done);
	INIT(NAAAIM, RandomBuffer, iv, goto done);

	if ( !tpmcmd->pcrmask(tpmcmd, 10, 15, 17, 18, -1) )
		goto done;
	if ( !quote->add_Buffer(quote, nonce) )
		goto done;

	if ( !tpmcmd->quote(tpmcmd, uuid, quote) )
		goto done;

	if ( !iv->generate(iv, 16) )
		goto done;
	b= iv->get_Buffer(iv);
	bufr->add_Buffer(bufr, b);

	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, b)) == NULL )
		goto done;
	if ( !cipher->encrypt(cipher, quote) )
		goto done;
	if ( !bufr->add_Buffer(bufr, cipher->get_Buffer(cipher)) )
		goto done;

	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, bufr);
	if ( !hmac->compute(hmac) )
		goto done;
	if ( !bufr->add_Buffer(bufr, hmac->get_Buffer(hmac)) )
		goto done;

	if ( !duct->send_Buffer(duct, bufr) )
		goto done;
	retn = true;


 done:
	WHACK(uuid);
	WHACK(quote);
	WHACK(aik_file);
	WHACK(tpmcmd);
	WHACK(iv);
	WHACK(cipher);
	WHACK(hmac);

	return retn;
}


/**
 * Private function.
 *
 * This function receives and confirms a request to initiate a
 * connection from the client.
 *
 * \param duct		The network object which the reference quote is
 *			to be received on.
 *
 * \param bufr		The Buffer object which is to be used to receive
 *			the initiation request.
 *
 * \param key		The shared key used to authenticated the request.
 *
 * \return		If a confirmation quote is received without
 *			error and validated a true value is returned.  A
 *			false value indicates the confirmation failed.
 */

static _Bool receive_connection_start(CO(Duct, duct), CO(Buffer, bufr), \
				      CO(Buffer, key))

{
	_Bool retn = false;

	size_t payload;

	Buffer b,
	       cksum = NULL,
	       iv    = NULL;

	AES256_cbc cipher = NULL;

	SHA256 sha256 = NULL;

	SHA256_hmac hmac = NULL;


	/* Receive the confirmation message. */
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;


	/* Validate the confirmation checksum. */
	INIT(HurdLib, Buffer, cksum, goto done);
	payload = bufr->size(bufr) - 32;
	cksum->add(cksum, bufr->get(bufr) + payload, 32);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	bufr->shrink(bufr, 32);
	hmac->add_Buffer(hmac, bufr);
	if ( !hmac->compute(hmac) )
		goto done;
	if ( !cksum->equal(cksum, hmac->get_Buffer(hmac)) )
		goto done;


	/* Decrypt the authenticator. */
	INIT(HurdLib, Buffer, iv, goto done);
	if ( !iv->add(iv, bufr->get(bufr), 16) )
		goto done;

	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		goto done;
	cksum->reset(cksum);
	if ( !cksum->add(cksum, bufr->get(bufr) + 16, bufr->size(bufr) - 16) )
		goto done;
	if ( !cipher->decrypt(cipher, cksum) )
		goto done;


	/* Confirm the authenticator. */
	INIT(NAAAIM, SHA256, sha256, goto done);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		goto done;
	b = sha256->get_Buffer(sha256);
	if ( !b->equal(b, cipher->get_Buffer(cipher)) )
		goto done;

	retn = true;


 done:
	WHACK(cksum);
	WHACK(iv);
	WHACK(cipher);
	WHACK(sha256);
	WHACK(hmac);

	return retn;

}


/**
 * External public method.
 *
 * This method encapsulates all of the functionality needed to
 * initiate a PossumPipe running in server mode.
 *
 * \param this		A pointer to the object which is to be initialized
 *			as a server.
 *
 * \param host		The name or ID address of the interface which
 *			the server is to listen on.
 *
 * \param port		The port number which the server is to listen on.
 *
 * \param do_reverse	A flag to indicate whether or not reverse DNS
 *			lookups are to be done on the incoming connection.
 *			A false value inhibits reverse DNS lookups while
 *			a true value (default).
 *
 * \return		A boolean value is returned to indicate the
 *			status of the server setup.  A false value
 *			indicates that connection setup failed while a
 *			true value indicates the server is listening
 *			for connections.
 */

static _Bool init_server(CO(PossumPipe, this), CO(char *, host), \
			 const int port, const _Bool do_reverse)

{
	STATE(S);

	_Bool retn = false;


	if ( !S->duct->init_server(S->duct) )
		goto done;
	if ( (host != NULL) && !S->duct->set_server(S->duct, host) )
		goto done;
	if ( !S->duct->init_port(S->duct, NULL, port) )
		goto done;
	S->duct->do_reverse(S->duct, do_reverse);

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements accepting a connection on an initialized server
 * port.  This is an inheritance interface to the Duct object imbeded
 * in this object.
 *
 * \param this	The object which is to accept the client connection.
 *
 * \return	This call blocks until a connection occurs.  If a
 *		connection is successfully established a true value is
 *		returned to the caller.  A false value indicates the
 *		connection was not successfully established.
 */

static _Bool accept_connection(CO(PossumPipe, this))

{
	STATE(S);

	return S->duct->accept_connection(S->duct);
}


/**
 * External public method.
 *
 * This method implements handling the authentication and initiation of
 * a client connection.  It is designed to be called after the successful
 * acceptance of a client connection.
 *
 * \param this		A pointer to the object which is to be initiated
 *			in server mode.
 *
 * \return		A boolean value is returned to indicate the
 *			status of session initiation.  A false value
 *			indicates that connection setup failed while
 *			a true value indicates a session has been
 *			established and is valid.
 */

static _Bool start_host_mode(CO(PossumPipe, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t spi;

	SoftwareStatus software_status = NULL;

	Duct duct = S->duct;

	Buffer b,
	       netbufr		= NULL,
	       nonce		= NULL,
	       quote_nonce	= NULL,
	       software		= NULL,
	       public		= NULL,
	       shared_key	= NULL;

	String name	 = NULL,
	       remote_ip = NULL;

	IDtoken token  = NULL;

	PossumPacket packet = NULL;

	Curve25519 dhkey = NULL;

	IDmgr idmgr = NULL;

	Ivy ivy = NULL;


	/* Get current software status. */
	INIT(NAAAIM, SoftwareStatus, software_status, goto done);
	software_status->open(software_status);
	fputs("Measuring software status.\n", stderr);
	if ( !software_status->measure(software_status) )
		goto done;
	fputs("Host software status:\n", stdout);
	b = software_status->get_template_hash(software_status);
	b->print(b);

	/* Setup the network port. */
	INIT(HurdLib, Buffer, netbufr, goto done);
	INIT(HurdLib, Buffer, software, goto done);

	/* Wait for a packet to arrive. */
	fprintf(stderr, "%s: Waiting for initialization packet.\n", __func__);
	if ( !duct->receive_Buffer(duct, netbufr) ) {
		fputs("Packet receive failed.\n", stderr);
		goto done;
	}
	fprintf(stdout, "\n%s: Raw receive packet:\n", __func__);
	netbufr->hprint(netbufr);
	fputc('\n', stdout);

	/* Lookup the client identity. */
	INIT(NAAAIM, IDtoken, token, goto done);
	INIT(NAAAIM, Ivy, ivy, goto done);
	if ( !find_client(netbufr, token, ivy) ) {
		fputs("Cannot locate client.\n", stdout);
		goto done;
	}

	/* Set the client configuration personality. */
#if 0
	/*
	 * Setting the counter party personality was only needed when
	 * the PossumPipe object was intimately connected to establishing
	 * an IPsec tunnel.
	 *
	 * A decision needs to be made as to how the remote client
	 * is to be surfaced from this object since the remote client
	 * is a characteristic of the connection.
	 */
	if ( !set_counter_party_personality(cfg, token) ) {
		fputs("Cannot find personality.\n", stdout);
		goto done;
	}
#endif

	/* Verify and decode packet. */
	if ( (b = ivy->get_element(ivy, Ivy_software)) == NULL )
		goto done;
	software->add_Buffer(software, b);
	fputs("Client software:\n", stdout);
	software->print(software);
	fputc('\n', stdout);

	INIT(NAAAIM, PossumPacket, packet, goto done);
	if ( !packet->decode_packet1(packet, token, software, netbufr) )
		goto done;
	fprintf(stdout, "%s: Incoming client packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	/* Extract the replay and quote nonces supplied by client. */
	INIT(HurdLib, Buffer, nonce, goto done);
	INIT(HurdLib, Buffer, quote_nonce, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_replay_nonce)) \
	     == NULL )
		goto done;
	if ( !nonce->add_Buffer(nonce, b) )
		goto done;
	if ( (b = packet->get_element(packet, PossumPacket_quote_nonce)) \
	     == NULL )
		goto done;

	if ( !quote_nonce->add_Buffer(quote_nonce, b) )
		goto done;

	/* Verify hardware quote. */

	/* Verify protocol. */

	INIT(HurdLib, Buffer, public, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_public)) == NULL )
		goto done;
	if ( !public->add_Buffer(public, b) )
		goto done;

	/* Generate DH public key for shared secret. */
	INIT(NAAAIM, Curve25519, dhkey, goto done);
	dhkey->generate(dhkey);

	/* Compose and send a reply packet. */
	token->reset(token);
	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( (name = HurdLib_String_Init_cstr("device")) == NULL )
		goto done;

	idmgr->attach(idmgr);
	if ( !idmgr->get_idtoken(idmgr, name, token) )
		goto done;

	packet->reset(packet);
	netbufr->reset(netbufr);

	/*
	 * Check both SPI's proposed by the caller.  If neither are
	 * available allocate an SPI from the reserve arena.
	 */
#if 0
	if ( (tspi = packet->get_value(packet, PossumPacket_spi)) == 0 )
		goto done;
	spi = propose_spi(HOST_SPI_ARENA, tspi & UINT16_MAX);
	if ( spi == 0 )
		spi = propose_spi(CLIENT_SPI_ARENA, tspi >> 16);
	if ( spi == 0 )
		spi = propose_spi(RESERVE_SPI_ARENA, 0);
	if ( spi == 0 )
		goto done;
#endif

	packet->set_schedule(packet, token, time(NULL));
	packet->create_packet1(packet, token, dhkey, spi);

	/* Reset the section back to the original. */
	b = software_status->get_template_hash(software_status);
	software->reset(software);
	software->add_Buffer(software, b);
	fputs("Local software status:\n", stdout);
	software->print(software);
	fputc('\n', stdout);

	if ( !packet->encode_packet1(packet, software, netbufr) )
		goto done;
	if ( !duct->send_Buffer(duct, netbufr) )
		goto done;
	fprintf(stdout, "%s: Sent host packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	INIT(HurdLib, Buffer, shared_key, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_replay_nonce)) \
	     == NULL )
		goto done;
	if ( !generate_shared_key(b, nonce, dhkey, public, shared_key) )
		goto done;
	fprintf(stdout, "%s: shared key:\n", __func__);
	shared_key->print(shared_key);
	fputc('\n', stdout);

	/* Wait for platform verification reference quote. */
	netbufr->reset(netbufr);
	if ( (b = packet->get_element(packet, PossumPacket_quote_nonce)) == \
	     NULL )
		goto done;
	if ( !receive_platform_quote(duct, netbufr, ivy, b, shared_key ) )
		goto done;
	fputs("\nVerified secure counter-party:\n", stdout);
	ivy->print(ivy);
	fputc('\n', stdout);

	/* Send platform verification quote. */
	netbufr->reset(netbufr);
	if ( !send_platform_quote(duct, netbufr, shared_key, quote_nonce) )
		goto done;

	/* Get connection confirmation start. */
	netbufr->reset(netbufr);
	if ( !receive_connection_start(duct, netbufr, shared_key) ) {
		fputs("Failed connection start.\n", stderr);
		goto done;
	}

	fputs("Have connection start.\n", stderr);
	retn = true;

 done:
	sleep(5);

	WHACK(software_status);
	WHACK(netbufr);
	WHACK(nonce);
	WHACK(quote_nonce);
	WHACK(software);
	WHACK(public);
	WHACK(token);
	WHACK(packet);
	WHACK(dhkey);
	WHACK(shared_key);
	WHACK(name);
	WHACK(remote_ip);
	WHACK(idmgr);
	WHACK(ivy);

	return retn;
}


/**
 * External public method.
 *
 * This method encapsulates the functionality needed to initiate the
 * client side of a PossumPipe connection.
 *
 * \param this		A pointer to the object which is to be initialized
 *			as a client.
 *
 * \param host		The name or ID address of the server to be
 *			connected to.
 *
 * \param port		The port number on the server to which the
 *			connection is to be initiatedto.
 *
 * \return		A boolean value is returned to indicate the
 *			status of the connection.  A false value denotes
 *			connection setup failed while a true value
 *			indicates the setup was successful.
 */

static _Bool init_client(CO(PossumPipe, this), CO(char *, host), \
			 const int port)

{
	STATE(S);

	_Bool retn = false;


	if ( !S->duct->init_client(S->duct) )
		goto done;
	if ( !S->duct->init_port(S->duct, host, 11990) )
		goto done;

	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function transmits confirmation for the host to move forward
 * with the secured connection.  The confirmation consists of
 * the SHA256 hash of the negotiated secret.
 *
 * \param duct		The network object which the reference quote is
 *			to be received on.
 *
 * \param bufr		The Buffer object which is to be used to send the
 *			confirmation message.
 *
 * \param key		The shared key used in the connextion.
 *
 *
 * \return		If an error is encountered in composing or
 *			sending the confirmation a false value is
 *			returned.  Success is indicated by returning
 *			true.
 */

static _Bool send_connection_start(CO(Duct, duct), CO(Buffer, bufr), \
				   CO(Buffer, key))

{
	_Bool retn = false;

	Buffer b;

	AES256_cbc cipher = NULL;

	RandomBuffer iv = NULL;

	SHA256 sha256 = NULL;

	SHA256_hmac hmac = NULL;


	/* Generate the initialization vector. */
	INIT(NAAAIM, RandomBuffer, iv, goto done);
	if ( !iv->generate(iv, 16) )
		goto done;
	if ( !bufr->add_Buffer(bufr, iv->get_Buffer(iv)) )
		goto done;

	/* Generate the connection authenticator. */
	INIT(NAAAIM, SHA256, sha256, goto done);
	sha256->add(sha256, key);
	if ( !sha256->compute(sha256) )
		goto done;

	/* Encrypt the authenticator. */
	b = iv->get_Buffer(iv);
	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, b)) == NULL )
		goto done;
	if ( !cipher->encrypt(cipher, sha256->get_Buffer(sha256)) )
		goto done;
	if ( !bufr->add_Buffer(bufr, cipher->get_Buffer(cipher)) )
		goto done;

	/* Add the authenticator checksum. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, bufr);
	if ( !hmac->compute(hmac) )
		goto done;
	if ( !bufr->add_Buffer(bufr, hmac->get_Buffer(hmac)) )
		goto done;

	/* Send the authenticator. */
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;
	retn = true;


 done:
	WHACK(iv);
	WHACK(cipher);
	WHACK(sha256);
	WHACK(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method implements handling the initiation and setup of a
 * connection to a remote server port.  Upon successful return the
 * object has a secured context established to the remote host.
 *
 * \param this		A pointer to the object which is to initiate
 *			a remote connection.
 *
 * \return		A boolean value is returned to indicate the
 *			status of session initiation.  A false value
 *			indicates that connection setup failed while
 *			a true value indicates a session has been
 *			established and is valid.
 */

static _Bool start_client_mode(CO(PossumPipe, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t spi;

	Duct duct = S->duct;

	SoftwareStatus software_status = NULL;

	Buffer b,
	       public,
	       nonce	   = NULL,
	       quote_nonce = NULL,
	       software	   = NULL,
	       bufr	   = NULL,
	       shared_key  = NULL;

	String name = NULL;

	IDmgr idmgr = NULL;

	IDtoken token = NULL;

	Curve25519 dhkey = NULL;

	PossumPacket packet = NULL;

	Ivy ivy = NULL;


	/* Load identity token. */
	INIT(NAAAIM, IDtoken, token, goto done);
	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( (name = HurdLib_String_Init_cstr("device")) == NULL )
		goto done;

	idmgr->attach(idmgr);
	if ( !idmgr->get_idtoken(idmgr, name, token) ) {
		fputs("Failed to obtain identity token.\n", stderr);
		goto done;
	}

	/* Measure the current software state. */
	INIT(NAAAIM, SoftwareStatus, software_status, goto done);
	software_status->open(software_status);
	if ( !software_status->measure(software_status) )
		goto done;

	/* Send a session initiation packet. */
	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, software, goto done);
	INIT(NAAAIM, Curve25519, dhkey, goto done);

	INIT(NAAAIM, PossumPacket, packet, goto done);
	packet->set_schedule(packet, token, time(NULL));
	dhkey->generate(dhkey);

#if 0
	tspi = propose_spi(CLIENT_SPI_ARENA, 0);
	spi = tspi << 16;
	tspi = propose_spi(HOST_SPI_ARENA, 0);
	spi = spi | tspi;
#endif
	packet->create_packet1(packet, token, dhkey, spi);

	b = software_status->get_template_hash(software_status);
	fputs("Software status:\n", stdout);
	b->print(b);
	software->add_Buffer(software, b);
	if ( !packet->encode_packet1(packet, software, bufr) )
		goto done;
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;

	fprintf(stdout, "\n%s: Sent client packet 1:\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	/* Save transmitted nonces for subsequent use. */
	INIT(HurdLib, Buffer, nonce, goto done);
	INIT(HurdLib, Buffer, quote_nonce, goto done);
	if ( (b = packet->get_element(packet, PossumPacket_quote_nonce)) == \
	     NULL )
		goto done;
	if ( !quote_nonce->add_Buffer(quote_nonce, b) )
		goto done;

	if ( (b = packet->get_element(packet, PossumPacket_replay_nonce)) \
	     == NULL )
		goto done;
	if ( !nonce->add_Buffer(nonce, b) )
		goto done;

	/* Wait for a packet to arrive. */
	packet->reset(packet);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;
	fprintf(stdout, "%s: Raw receive packet:\n", __func__);
	bufr->hprint(bufr);
	fputc('\n', stdout);

	/* Find the host identity. */
	INIT(NAAAIM, Ivy, ivy, goto done);
	token->reset(token);
	if ( !find_client(bufr, token, ivy) )
		goto done;

	/* Set the host configuration personality. */

#if 0
	/*
	 * See comments above in host_mode() as to disposition of this
	 * function
	 */
	if ( !set_counter_party_personality(cfg, token) )
	     goto done;
#endif

	software->reset(software);
	if ( (b = ivy->get_element(ivy, Ivy_software)) == NULL )
		goto done;
	software->add_Buffer(software, b);
	if ( !packet->decode_packet1(packet, token, software, bufr) )
		goto done;

	fprintf(stdout, "%s: Received host packet 1.\n", __func__);
	packet->print(packet);
	fputc('\n', stdout);

	if ( (b = packet->get_element(packet, PossumPacket_public)) == NULL )
		goto done;
	public = b;

	if ( (b = packet->get_element(packet, PossumPacket_replay_nonce)) \
	     == NULL )
		goto done;
	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, b) )
		goto done;

	INIT(HurdLib, Buffer, shared_key, goto done);
	if ( !generate_shared_key(bufr, nonce, dhkey, public, shared_key) )
		goto done;
	fprintf(stdout, "%s: shared key:\n", __func__);
	shared_key->print(shared_key);
	fputc('\n', stdout);

	/* Send platform reference. */
	if ( (b = packet->get_element(packet, PossumPacket_quote_nonce)) \
	     == NULL )
		goto done;
	bufr->reset(bufr);
	if ( !send_platform_quote(duct, bufr, shared_key, b) )
		goto done;

	/* Receive platform reference. */
	bufr->reset(bufr);
	if ( !receive_platform_quote(duct, bufr, ivy, quote_nonce, \
				     shared_key) )
		goto done;
	fputs("\nVerified secure host:\n", stderr);
	ivy->print(ivy);
	fputc('\n', stdout);

	/* Send initiation packet. */
	bufr->reset(bufr);
	if ( !send_connection_start(duct, bufr, shared_key) )
		goto done;

	retn = true;

 done:
	WHACK(software_status);
	WHACK(nonce);
	WHACK(quote_nonce);
	WHACK(software);
	WHACK(bufr);
	WHACK(idmgr);
	WHACK(token);
	WHACK(dhkey);
	WHACK(packet);
	WHACK(shared_key);
	WHACK(name);
	WHACK(ivy);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a PossumPipe object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(PossumPipe, this))

{
	STATE(S);


	S->duct->whack(S->duct);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a PossumPipe object.
 *
 * \return	A pointer to the initialized PossumPipe.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PossumPipe NAAAIM_PossumPipe_Init(void)

{
	auto Origin root;

	auto PossumPipe this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PossumPipe);
	retn.state_size   = sizeof(struct NAAAIM_PossumPipe_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PossumPipe_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	INIT(NAAAIM, Duct, this->state->duct, goto fail);

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_server = init_server;
	this->init_client = init_client;

	this->accept_connection = accept_connection;

	this->start_host_mode = start_host_mode;
	this->start_client_mode = start_client_mode;

	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->duct);

	root->whack(root, this, this->state);
	return NULL;

}
