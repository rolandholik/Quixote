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

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <IDtoken.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "SoftwareStatus.h"
#include "Curve25519.h"
#include "PossumPacket.h"
#include "IDmgr.h"
#include "Ivy.h"
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
	if ( (host != NULL) & !S->duct->set_server(S->duct, host) )
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
	_Bool retn = false;

#if 0
	uint32_t tspi,
		 spi,
		 protocol;

	SoftwareStatus software_status = NULL;

	Duct duct = NULL;

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
	if ( !software_status->measure(software_status) )
		goto done;
	fputs("Host software status:\n", stdout);
	b = software_status->get_template_hash(software_status);
	b->print(b);

	/* Setup the network port. */
	INIT(HurdLib, Buffer, netbufr, goto done);
	INIT(HurdLib, Buffer, software, goto done);

	INIT(NAAAIM, Duct, duct, goto done);
	duct->init_server(duct);
	duct->init_port(duct, NULL, 10902);
	duct->accept_connection(duct);

	/* Wait for a packet to arrive. */
	if ( !duct->receive_Buffer(duct, netbufr) )
		goto done;
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
	if ( !set_counter_party_personality(cfg, token) ) {
		fputs("Cannot find personality.\n", stdout);
		goto done;
	}

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

	/* Create IPsec endpoint. */
	spi	 = packet->get_value(packet, PossumPacket_spi);
	protocol = packet->get_value(packet, PossumPacket_protocol);

	INIT(HurdLib, String, remote_ip, goto done);
	if ( !remote_ip->add(remote_ip, inet_ntoa(*(duct->get_ipv4(duct)))) )
		goto done;
	if ( !setup_ipsec(cfg, remote_ip->get(remote_ip), protocol, spi, \
			  shared_key) )
		goto done;

	retn = true;

 done:
	sleep(5);
	WHACK(software_status);
	WHACK(duct);
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
#endif
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
	_Bool retn = false;

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
	_Bool retn = false;

#if 0
	const char *retry,
		   *remote_ip;

	uint32_t spi,
		 tspi,
		 protocol;

	Duct duct = NULL;

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

	/* Setup a connection to the remote host. */
	if ( (remote_ip = cfg->get(cfg, "remote_ip")) == NULL )
		goto done;
	retry = cfg->get(cfg, "retry");

	if ( retry != NULL ) {
		while ( retry != NULL ) {
			INIT(NAAAIM, Duct, duct, goto done);
			duct->init_client(duct);
			if ( !duct->init_port(duct, remote_ip, POSSUM_PORT) ) {
				fputs("Retrying possum connection in " \
				      "five seconds.\n", stderr);
				sleep(5);
				WHACK(duct);
			}
			else
				retry = NULL;
		}
	} else {
		INIT(NAAAIM, Duct, duct, goto done);
		duct->init_client(duct);
		if ( duct->init_port(duct, remote_ip, POSSUM_PORT) )
			goto done;
	}

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
	if ( !set_counter_party_personality(cfg, token) )
	     goto done;

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

	/* Initiate IPsec link. */
	spi	 = packet->get_value(packet, PossumPacket_spi);
	protocol = packet->get_value(packet, PossumPacket_protocol);
	if ( !setup_ipsec(cfg, remote_ip, protocol, spi, shared_key) )
		goto done;

	retn = true;

 done:
	WHACK(duct);
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
#endif
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
