/** \file
 * This file contains the primary enclave code for provisioning
 * credentials for the IAS Attestation enclave.  It is designed to
 * use a mode 2 POSSUM connection in order to register credentials
 * for the platform.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
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
 * MRSIGNER value for IDfusion debug key.
 */
const uint8_t idf_debug_key[32] = {
	0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, \
	0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43, \
	0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, \
	0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
};


/**
 * Array of allowed endpoints.
 */
const struct SRDEendpoint Endpoints[1] = {
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 7,
		.isv_id	     = 0x11,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) idf_debug_key,
		.mrenclave   = NULL
	}
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

	Buffer bufr = NULL;

	RSAkey key = NULL;


	/* Load the RSAkey object. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) ep->key, ep->key_size) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_public(key, bufr) )
		ERR(goto done);


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

	return retn;
}


/**
 * Private function.
 *
 * The following function implements verification of the connecting
 * endpoint.
 *
 * \param pipe		The communications object being used for the
 *			connection.
 *
 * \param status	A pointer to the boolean value that will be set
 *			to the status of whether or not endpoint
 *			verification succeeded.
 *
 * \return		A boolean value is returned to indicate the
 *			status of conducting the endpoint verification.
 *			A false value indicates there was a procedural
 *			error in conducting the verification.  In this
 *			case the value placed in the status output
 *			variable will be indeterminate.  A true value
 *			indicates that the status variable can be used
 *			to determine whether or not the endpoint should
 *			be trusted.
 */

static _Bool _verify_endpoint(CO(PossumPipe, pipe), uint8_t *status)

{
	_Bool retn = false;

	unsigned int lp,
		     cnt = sizeof(Endpoints)/sizeof(struct SRDEendpoint);

	uint16_t isv_id,
		 isv_svn;

	uint64_t attributes;

	struct SRDEendpoint *ep;

	Buffer chk	   = NULL,
	       mrsigner	   = NULL,
	       mrenclave   = NULL;


	/* Get connection parameters. */
	INIT(HurdLib, Buffer, mrsigner, ERR(goto done));
	INIT(HurdLib, Buffer, mrenclave, ERR(goto done));

	if ( !pipe->get_connection(pipe, &attributes, mrsigner, mrenclave, \
				   &isv_id, &isv_svn) )
		ERR(goto done);


	/* Verify against each endpoint. */
	INIT(HurdLib, Buffer, chk, ERR(goto done));

	ep	= (struct SRDEendpoint *) Endpoints;
	*status = 0;

	for (lp= 0; lp < cnt; ++ep, ++lp) {
		fprintf(stdout, "Using mask: %02x\n", ep->mask);
		if ( ep->mask & SRDEendpoint_attribute ) {
			if ( attributes != ep->attributes )
				*status |= SRDEendpoint_bad_attribute;
		}
		if ( ep->mask & SRDEendpoint_vendor ) {
			if ( isv_id != ep->isv_id )
				*status |= SRDEendpoint_bad_vendor;
		}
		if ( ep->mask & SRDEendpoint_svn ) {
			if ( isv_svn < ep->isv_svn )
				*status |= SRDEendpoint_bad_svn;
		}

		if ( ep->mask & SRDEendpoint_mrsigner ) {
			if ( !chk->add(chk, ep->mrsigner, SGX_HASH_SIZE) )
				ERR(goto done);
			if ( !chk->equal(chk, mrsigner) )
				*status |= SRDEendpoint_bad_mrsigner;
		}

		if ( ep->mask & SRDEendpoint_mrenclave ) {
			if ( !chk->add(chk, ep->mrenclave, SGX_HASH_SIZE) )
				ERR(goto done);
			if ( !chk->equal(chk, mrenclave) )
				*status |= SRDEendpoint_bad_mrenclave;
		}

		chk->reset(chk);
	}

	retn = true;


 done:
	WHACK(chk);
	WHACK(mrsigner);
	WHACK(mrenclave);

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
	uint8_t status;


	/* Verify client connection. */
	fputs("Verifying endpoint.\n", stdout);
	if ( !_verify_endpoint(pipe, &status) ) {
		fputs("Error verifying endpoint.\n", stdout);
		goto done;
	}

	if ( status != 0 ) {
		fprintf(stdout, "Invalid endpoint, status=%01x.\n", status);
		goto done;
	}


	/* Return the SPID and APIkey. */
	fputs("Processing request.\n", stdout);
	if ( !pipe->send_packet(pipe, PossumPipe_data, spid) )
		ERR(goto done);
	if ( !pipe->send_packet(pipe, PossumPipe_data, apikey) )
		ERR(goto done);


 done:
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
	if ( !file->open_ro(file, "/opt/IDfusion/etc/spid.txt") )
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
			fputs("\tUnable to start connection.\n", stdout);
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
