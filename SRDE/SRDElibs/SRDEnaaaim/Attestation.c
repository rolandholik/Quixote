/** \file
 * This file contains the implementation of an object used to access
 * SRDE attestation services.  It provides an encapsulation of the
 * infrastructure needed to create an SRDEpipe connection to the
 * Attestation.signed.so enclave that implements the generation of
 * an quote for the enclave initiating the connection with subsequent
 * conversion of that quote into an attestation report.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <SRDE.h>
#include <SRDEfusion.h>

#include "NAAAIM.h"
#include "SRDEpipe.h"
#include "Report.h"
#include "SRDEquote.h"
#include "Attestation.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Attestation_OBJID)
#error Object identifier not defined.
#endif

/* State extraction macro. */
#define STATE(var) CO(Attestation_State, var) = this->state

/**
 * The location of the attestation services enclave and its launch
 * token.  The standard enclave positioning macro is not used here
 * since this will largely be a production service used even by
 * development enclavess.
 */
#define ATTESTATION_ENCLAVE "/opt/IDfusion/lib/enclaves/Attestation.signed.so"
#define ATTESTATION_TOKEN   SGX_TOKEN_DIRECTORY"/Attestation.token"


/** Attestation private state information. */
struct NAAAIM_Attestation_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

};


/**
 * Allowed endpoints for Attestation services.
 */
const static struct SRDEendpoint Attestation_enclave[] = {
#if !defined(SRDE_PRODUCTION)
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 7,
		.isv_id	     = 0x11,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) IDfusion_debug_key,
	},
#endif
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 5,
		.isv_id	     = 0x11,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) IDfusion_production_key,
	}
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Attestation_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(CO(Attestation_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Attestation_OBJID;

	return;
}


/**
 * External public method.
 *
 * This method implements the generation of an attestation report by
 * connecting to the Attestation services enclave.
 *
 * \param this		A pointer to the object that is to generate
 *			the attestation report.
 *
 * \param nonce		A nonce value up to 128 bits in length that
 *			will be included as a freshness verifier in
 *			attestation report.  If this parameter is
 *			NULL a nonce is not included.
 *
 * \param reportdata	An object containing report data, up to 64
 *			bytes in length that will be included in the
 *			enclave report.  If this value is NULL no
 *			data will be included in the report.
 *
 * \param output	A pointer to the object that will be loaded
 *			with the ASCII representation of the report.
 *
 * \return		A false value is returned to indicate that
 *			there was some type of operational error with
 *			generation of the attestation report.  In
 *			this case no assumptions can be made about
 *			the contents of the output object.  A true
 *			value indicates the attestation report was
 *			generated and the output object contains an
 *			attestation as to the state of the enclave.
 */

static _Bool generate(CO(Attestation, this), CO(Buffer, nonce), \
		      CO(Buffer, reportdata), CO(String, output))

{
	_Bool status,
	      connected = false,
	      retn	= false;

	unsigned int cmd;

	struct SGX_targetinfo target;

	struct SGX_report report;

	Buffer packet = NULL;

	SRDEpipe pipe = NULL;

	Report rpt = NULL;


	/* Verify arguement status. */
	if ( (nonce != NULL) && (nonce->size(nonce) > 16) )
		ERR(goto done);
	if ( (reportdata != NULL) && (reportdata->size(reportdata) > 64) )
		ERR(goto done);


	INIT(NAAAIM, SRDEpipe, pipe, ERR(goto done));
	if ( !pipe->setup(pipe, ATTESTATION_ENCLAVE, 1, ATTESTATION_TOKEN, \
			  false) )
		ERR(goto done);

	if ( !pipe->connect(pipe) )
		ERR(goto done);
	connected = true;


	/* Verify the attestation enclave. */
	INIT(HurdLib, Buffer, packet, ERR(goto done));
	if ( !packet->add(packet, (void *) Attestation_enclave, \
			  sizeof(Attestation_enclave)) )
		ERR(goto done);
	if ( !pipe->verify(pipe, packet, &status) )
		ERR(goto done);
	if ( !status )
		ERR(goto done);

	packet->reset(packet);


	/* Request QE target information. */
	cmd = 1;
	if ( !packet->add(packet, (void *) &cmd, sizeof(unsigned int)) )
		ERR(goto done);
	if ( !pipe->send_packet(pipe, SRDEpipe_data, packet) )
		ERR(goto done);

	if ( !pipe->receive_packet(pipe, packet) )
		ERR(goto done);
	if ( packet->size(packet) == 0 )
		ERR(goto done);


	/* Generate enclave report and return it. */
	INIT(NAAAIM, Report, rpt, ERR(goto done));
	memcpy(&target, packet->get(packet), sizeof(struct SGX_targetinfo));
	if ( !rpt->generate_report(rpt, &target, reportdata, &report) )
		ERR(goto done);

	cmd = 2;
	packet->reset(packet);

	if ( !packet->add(packet, (void *) &cmd, sizeof(unsigned int)) )
		ERR(goto done);
	if ( !packet->add(packet, (void *) &report, sizeof(report)) )\
		ERR(goto done);
	if ( nonce != NULL ) {
		if ( !packet->add(packet, nonce->get(nonce), \
				  nonce->size(nonce)) )
			ERR(goto done);
	}

	if ( !pipe->send_packet(pipe, SRDEpipe_data, packet) )
		ERR(goto done);


	/* Process the report. */
	if ( !pipe->receive_packet(pipe, packet) )
		ERR(goto done);
	if ( packet->size(packet) == 0 )
		ERR(goto done);

	if ( !output->add(output, (char *) packet->get(packet)) )
		ERR(goto done);

	retn = true;


 done:
	if ( connected )
		pipe->close(pipe);

	WHACK(packet);
	WHACK(pipe);
	WHACK(rpt);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Attestation object.
 *
 * \param this	A pointer to the object that is to be destroyed.
 */

static void whack(CO(Attestation, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an Attestation object.
 *
 * \return	A pointer to the initialized Attestation.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Attestation NAAAIM_Attestation_Init(void)

{
	Origin root;

	Attestation this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Attestation);
	retn.state_size   = sizeof(struct NAAAIM_Attestation_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Attestation_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->generate = generate;

	this->whack = whack;

	return this;
}
