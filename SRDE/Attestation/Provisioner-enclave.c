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

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

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

	uint16_t vendor,
		 svn;

	uint64_t attributes;

	PossumPipe pipe = NULL;

	Buffer spid	   = NULL,
	       signer	   = NULL,
	       measurement = NULL;


	/* Initialize the time. */
	Current_Time = ep->current_time;

	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, ep->spid) )
		ERR(goto done);


	/* Start the server listening. */
	fputs("Starting provisioning server.\n", stdout);

	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( !pipe->init_server(pipe, NULL, PORT, false) )
		ERR(goto done);

	if ( !pipe->accept_connection(pipe) ) {
		fputs("Error accepting connection.\n", stderr);
		ERR(goto done);
	}

	if ( !pipe->start_host_mode2(pipe, spid) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}

	/* Display remote connection parameters. */
	INIT(HurdLib, Buffer, signer, ERR(goto done));
	INIT(HurdLib, Buffer, measurement, ERR(goto done));

	if ( !pipe->get_connection(pipe, &attributes, signer, measurement, \
				   &vendor, &svn) )
		ERR(goto done);

	fputs("\nHave connection.\n", stdout);
	fputs("Signer:\n\t", stdout);
	signer->print(signer);
	fputs("Measurement:\n\t", stdout);
	measurement->print(measurement);
	fprintf(stdout, "Attributes:\n\t%lu\n", attributes);
	fprintf(stdout, "Software:\n\t%u/%u\n", vendor, svn);

	retn = true;


 done:
	GWHACK(RSAkey, Verifiers);
	WHACK(Verifiers);

	WHACK(pipe);
	WHACK(spid);
	WHACK(signer);
	WHACK(measurement);

	return retn;
}
