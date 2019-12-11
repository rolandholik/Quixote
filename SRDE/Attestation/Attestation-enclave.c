/** \file
 * This file contains the primary enclave code that generates
 * attestation reports from the Intel Authentication Services (IAS).
 * It is designed to implement an on-system Service Provider (SP) that
 * allows local enclaves to implement generation of attestation
 * reports for themselves for review by relying parties.
 *
 * An ECALL is provided to provision a SPID and an APIkey to the
 * platform.  Both entities are cached in encrypted form on the
 * platform using an enclave specific sealing key.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define PROVISIONER_HOST "localhost"
#define PROVISIONER_PORT 12902


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

#include <NAAAIM.h>
#include <RandomBuffer.h>
#include <Curve25519.h>
#include <RSAkey.h>
#include <SRDEquote.h>
#include <Report.h>
#include <SRDEpipe.h>
#include <PossumPipe.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>
#include "Attestation-interface.h"


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
 * This method implements the provisioning of credentials to the
 * enclave from the IDfusion credential provisioning server.
 *
 * \param ep	A pointer to the structure that marshals arguements
 *		for the ECALL.
 *
 * \return	A boolean value is used to indicate whether or not
 *		provisioning of credentials was successful.  A false
 *		value indicates an error occurred and no assumption
 *		can be made regarding the availability of
 *		credentials.  A true values indicates that credentials
 *		were successfully provisioned and sealed to the
 *		platform.
 */

_Bool provision_credentials(struct Attestation_ecall0 *ep)

{
	_Bool retn = false;

	uint16_t vendor,
		 svn;

	uint64_t attributes;

	PossumPipe pipe = NULL;

	Buffer signer	   = NULL,
	       measurement = NULL;

	RSAkey key = NULL;


	/* Initialize the time. */
	Current_Time = ep->current_time;


	/* Load the identifier key. */
	INIT(HurdLib, Buffer, signer, ERR(goto done));
	if ( !signer->add(signer, ep->key, ep->key_size) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_private(key, signer) )
		ERR(goto done);


	/* Start client mode. */
	fputs("Attestation client connecting.\n", stdout);
	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));

	if ( !pipe->init_client(pipe, PROVISIONER_HOST, PROVISIONER_PORT) ) {
		fputs("Cannot initialize secured channel.\n", stderr);
		goto done;
	}
	if ( !pipe->start_client_mode2(pipe, key)) {
		fputs("Error starting client mode.\n", stderr);
		goto done;
	}


	/* Display remote connection parameters. */
	INIT(HurdLib, Buffer, measurement, ERR(goto done));

	signer->reset(signer);
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


	/* Run client mode test. */


 done:
	WHACK(pipe);
	WHACK(signer);
	WHACK(measurement);
	WHACK(key);

	return retn ? 0 : 1;

}


/**
 * ECALL 1.
 *
 * This method implements an SRDEpipe compliant ECALL interface for a
 * local enclave to request a remote attestion report.
 *
 * ip:		A pointer to the structure that marshalls the arguements
 *		for this ECALL.
 *
 * \return	A boolean value is used to indicate whether or not
 *		execution of the ECALL was successful.  A false value
 *		indicates the call failed and further functioning of
 *		the ECALL may result in indeterminate behavior.
 */

_Bool generate_report(struct SRDEpipe_ecall *ep)

{
	_Bool retn = false;

	SRDEpipe_type type;

	static Buffer packet = NULL;

	static SRDEpipe pipe = NULL;


	if ( packet != NULL ) {
		if ( ep->bufr_size != packet->size(packet) )
			ERR(goto done);
		memcpy(ep->bufr, packet->get(packet), packet->size(packet));

		WHACK(packet);
		return true;
	}

	if ( pipe == NULL ) {
		INIT(NAAAIM, SRDEpipe, pipe, ERR(goto done));

		if ( !pipe->accept(pipe, &ep->target, &ep->report) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/* Handle second stage of connection. */
	if ( !pipe->connected(pipe) ) {
		if ( !pipe->accept(pipe, &ep->target, &ep->report) )
			ERR(goto done);

		retn = true;
		goto done;
	}


	/* Connection is established - handle packet processing. */
	if ( packet == NULL )
		INIT(HurdLib, Buffer, packet, ERR(goto done));
	if ( !packet->add(packet, ep->bufr, ep->bufr_size) )
		ERR(goto done);

	if ( (type = pipe->receive_packet(pipe, packet)) == SRDEpipe_failure )
		ERR(goto done);

	if ( type == SRDEpipe_eop ) {
		retn = true;
		WHACK(pipe);
		goto done;
	}

	fputs("\nTarget packet contents:\n", stdout);
	packet->hprint(packet);


	/* Send return packet message. */
#if 0
	if ( !packet->add(packet, (void *) msg, strlen(msg) + 1) )
		ERR(goto done);
#endif

	fputs("\nTarget sending return message:\n", stdout);
	packet->hprint(packet);

	if ( !pipe->send_packet(pipe, SRDEpipe_data, packet) )
		ERR(goto done);

	if ( packet->size(packet) > ep->bufr_size ) {
		ep->needed = packet->size(packet);
		ep->bufr_size = 0;
		return true;
	}

	retn = true;


 done:
	ep->bufr_size = 0;
	WHACK(packet);

	return retn;
}
