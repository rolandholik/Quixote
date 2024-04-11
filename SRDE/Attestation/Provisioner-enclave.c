/** \file
 * This file contains the primary enclave code for provisioning
 * credentials for the IAS Attestation enclave.  It is designed to
 * use a mode 2 POSSUM connection in order to register credentials
 * for the platform.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define PORT 12902

/* Macro to clear an array object. */
#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <SRDE.h>
#include <SRDEfusion.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include <NAAAIM.h>
#include <RSAkey.h>
#include <SHA256.h>
#include <PossumPipe.h>

#include "Provisioner-interface.h"


/**
 * The device identity to be used.  This is unused for mode 2
 * authentication but needed in order to satisfy the link dependency
 * from the PossumPipe object.
 */
size_t Identity_size	= 0;
unsigned char *Identity = NULL;


/**
 * The list of verifiers for communication counter-parties.
 */
Buffer Verifiers = NULL;


/**
 * The seed time for the time() function.
 */
static time_t Current_Time;


/**
 * Key identifier for identity key.
 */
const uint8_t Keyid[32] = {
	0xe5, 0x2a, 0x82, 0xc9, 0x8b, 0x3a, 0xb3, 0x49, \
	0x52, 0x18, 0x22, 0x0d, 0xd0, 0x08, 0x58, 0x51, \
	0x65, 0xb7, 0xed, 0xfb, 0x9e, 0x25, 0x41, 0xaa, \
	0xac, 0xf1, 0xc3, 0xd8, 0xcd, 0x6f, 0x3d, 0x85
};


/**
 * Array of allowed attestation client endpoints.
 */
const struct SRDEendpoint Endpoints[] = {
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 5,
		.isv_id	     = 0x11,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) Production_key,
		.mrenclave   = NULL
	},
#if !defined(SRDE_PRODUCTION)
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 7,
		.isv_id	     = 0x11,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) Debug_key,
		.mrenclave   = NULL
	}
#endif
};


/**
 * Global function.
 *
 * The following function implements a function for returning something
 * that approximates monotonic time for the enclave.  The expection
 * is for an ECALL to set the Current_Time variable to some initial
 * value, typically when the ECAL was made.  Each time this function
 * is called the value is incremented so a value which roughly
 * approximately monotonic time is available.
 *
 * For the purposes of a PossumPipe this is sufficient since the
 * replay defense is based on the notion that an endpoint will never
 * see an OTEDKS key repeated.
 *
 * \param timeptr	If this value is non-NULL the current time
 *			value is copied into the location specified by
 *			this pointer.
 *
 * \return		The current value of the enclave time variable
 *			is returned to the caller.
 */

time_t time(time_t *timeptr)

{
	if ( timeptr != NULL )
		*timeptr = Current_Time;

	return Current_Time++;
}


/**
 * ECALL 0.
 *
 * This method provides an ECALL for registering public keys for clients
 * that credentials will be provisioned to.
 *
 * ip:		A pointer to the structure that marshalls the arguements
 *		for this ECALL.
 *
 * \return	A boolean value is used to indicate whether or not
 *		registration of the keys was successful.  A false value
 *		indicates the call failed and the enclave will not
 *		support provisioning services.  A true value indicates
 *		the credentials were provisioned and the enclave is
 *		available for service.
 */

_Bool register_keys(struct Provisioner_ecall0 *ep)

{
	_Bool retn = false;

	Buffer b,
	       bufr = NULL;

	RSAkey key = NULL;

	Sha256 sha256 = NULL;


	/* Load the RSAkey object. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) ep->key, ep->key_size) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_public(key, bufr) )
		ERR(goto done);


	/* Generate a fingerprint of the identity. */
	bufr->reset(bufr);
	if ( !key->get_modulus(key, bufr) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	if ( !sha256->add(sha256, bufr) )
		ERR(goto done);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	fputs("\tID:  ", stdout);
	b = sha256->get_Buffer(sha256);
	b->print(b);


	/* Initialize and add the key object. */
	if ( Verifiers == NULL )
		INIT(HurdLib, Buffer, Verifiers, ERR(goto done));

	if ( !Verifiers->add(Verifiers, (unsigned char *) &key, \
			     sizeof(RSAkey)) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		WHACK(key);

	WHACK(bufr);
	WHACK(sha256);

	return retn;
}


/**
 * Private function.
 *
 * The following function is a wrapper function for one invocation of
 * a credential provisioning session.  It verifies the identity of
 * the requesting enclave and if it matches one of the approved identity
 * characteristics a copy of the SPID and APIkey are returned.
 *
 * \param pipe		The communications object being used for the
 *			connection.
 *
 * \param spid		The object containing the service provisioning
 *			identity to be returned.
 *
 * \param apikey	The object containing the APIkey that is to
 *			be returned.
 *
 * \return		No return value is currently defined.
 */

static void _process_request(CO(PossumPipe, pipe), CO(Buffer, spid), \
			     CO(Buffer, apikey))

{
	_Bool status;

	RSAkey key;

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;


	/* Verify client connection. */
	fputs("Verifying endpoint.\n", stdout);
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) Endpoints, sizeof(Endpoints)) )
		ERR(goto done);
	if ( !pipe->verify(pipe, bufr, &status) ) {
		fputs("Error verifying endpoint.\n", stdout);
		goto done;
	}
	if ( !status ) {
		fprintf(stdout, "Invalid endpoint, status=%01x.\n", status);
		goto done;
	}


	/* Output the client identity. */
	bufr->reset(bufr);
	key = pipe->get_client(pipe);
	if ( !key->get_modulus(key, bufr) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	if ( !sha256->add(sha256, bufr) )
		ERR(goto done);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	b = sha256->get_Buffer(sha256);

	fputs("Client:   ", stdout);
	b->print(b);


	/* Send the identifier for key generation. */
	bufr->reset(bufr);
	if ( !bufr->add(bufr, Keyid, sizeof(Keyid)) )
		ERR(goto done);
	if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) )
		ERR(goto done);


	/* Wait for the static identity key. */
	bufr->reset(bufr);
	if ( !pipe->receive_packet(pipe, bufr) )
		ERR(goto done);

	fputs("Endpoint: ", stdout);
	bufr->print(bufr);


	/* Return the SPID and APIkey. */
	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, spid) )
		ERR(goto done);
	if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, apikey) )
		ERR(goto done);
	if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) )
		ERR(goto done);


 done:
	WHACK(bufr);
	WHACK(sha256);

	return;
}


/**
 * ECALL 1.
 *
 * This method implements the loading of public keys that verify clients
 * who are allowed to provision credentials to their platforms.
 *
 * \param ep	A pointer to the structure that marshals arguements
 *		for the ECALL.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the key provisioning was successful.  A false value
 *		indicates the server encountered an error while a
 *		true value indicates the key was provisioned correctly.
 */

_Bool provisioner(struct Provisioner_ecall1 *ep)

{
	_Bool retn = false;

	PossumPipe pipe = NULL;

	Buffer pipespid = NULL,
	       spid	= NULL,
	       apikey	= NULL;

	String spidstr = NULL;

	File file = NULL;


	/* Initialize the time. */
	Current_Time = ep->current_time;


	/* Load a local SPID to authenticate the PossumPipe connection. */
	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, "/opt/ESD/etc/spid.txt") )
		ERR(goto done);

	INIT(HurdLib, String, spidstr, ERR(goto done));
	if ( !file->read_String(file, spidstr) )
		ERR(goto done);

	INIT(HurdLib, Buffer, pipespid, ERR(goto done));
	if ( !pipespid->add_hexstring(pipespid, spidstr->get(spidstr)) )
		ERR(goto done);

	WHACK(file);
	WHACK(spidstr);


	/* Convert the SPID's to buffer object. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add(spid, (void *) ep->spid, strlen(ep->spid)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, apikey, ERR(goto done));
	if ( !apikey->add(apikey, (void *) ep->apikey, strlen(ep->apikey)) )
		ERR(goto done);


	/* Start the server listening. */
	fputs("\nStarting provisioning listener.\n", stdout);

	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( !pipe->init_server(pipe, NULL, PORT, false) )
		ERR(goto done);

	while ( 1 ) {
		fputs("\nWaiting for connection.\n", stdout);
		if ( !pipe->accept_connection(pipe) ) {
			fputs("Error accepting connection.\n", stderr);
			ERR(goto done);
		}
		fputs("Have connection, setting up context.\n", stdout);
		if ( !pipe->start_host_mode2(pipe, pipespid) ) {
			if ( pipe->get_error(pipe) == \
			     PossumPipe_error_no_identity )
				fputs("\tInvalid client identity.\n", stdout);
			else
				fputs("\tUnable to start connection\n", \
				      stdout);
			pipe->reset(pipe);
			continue;
		}

		_process_request(pipe, spid, apikey);
		pipe->reset(pipe);
	}


 done:
	GWHACK(RSAkey, Verifiers);
	WHACK(Verifiers);

	WHACK(pipe);
	WHACK(pipespid);
	WHACK(spid);
	WHACK(apikey);

	return retn;
}
