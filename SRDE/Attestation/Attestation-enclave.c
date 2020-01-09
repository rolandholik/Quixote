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
#if defined(SRDE_PRODUCTION)
#define PROVISIONER_HOST "acpv.idfusion.net"
#define CREDENTIAL_FILE  "/var/lib/IDfusion/data/Attestation.bin"
#else
#define PROVISIONER_HOST "localhost"
#define CREDENTIAL_FILE  "Attestation.bin"
#endif

#define PROVISIONER_PORT 12902

#define QE_TOKEN	"/var/lib/IDfusion/tokens/libsgx_qe.token"
#define PCE_TOKEN	"/var/lib/IDfusion/tokens/libsgx_pce.token"
#define EPID		"/var/lib/IDfusion/data/EPID.bin"


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
#include <File.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>
#include <Curve25519.h>
#include <RSAkey.h>
#include <SRDEquote.h>
#include <Report.h>
#include <SRDEpipe.h>
#include <PossumPipe.h>
#include <SEALkey.h>
#include <SEALEDblob.h>

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
 * Allowed Provisioner endpoints.
 */
const static struct SRDEendpoint Provisioner[] = {
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 5,
		.isv_id	     = 0x10,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) IDfusion_production_key,
	},
#if !defined(SRDE_PRODUCTION)
	{
		.mask	     = SRDEendpoint_all & ~SRDEendpoint_mrenclave,
		.accept	     = true,
		.attributes  = 7,
		.isv_id	     = 0x10,
		.isv_svn     = 0,
		.mrsigner    = (uint8_t *) IDfusion_debug_key,
	},
#endif
};


/**
 * Allowed endpoints from attestation clients.
 */
const static struct SRDEendpoint Attestation_clients[] = {
	{
		.mask	     = SRDEendpoint_attribute,
		.accept	     = true,
		.attributes  = 7,
	},
	{
		.mask	     = SRDEendpoint_attribute,
		.accept	     = true,
		.attributes  = 5,
	},
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
	_Bool status,
	      retn = false;

	PossumPipe pipe = NULL;

	Buffer spid	   = NULL,
	       apikey	   = NULL,
	       signer	   = NULL;

	RSAkey key = NULL;

	SEALkey idkey = NULL;

	SEALEDblob creds = NULL;

	File file = NULL;


	/* Initialize the time. */
	Current_Time = ep->current_time;


	/* Load the identifier key. */
	INIT(HurdLib, Buffer, signer, ERR(goto done));
	if ( !signer->add(signer, ep->key, ep->key_size) )
		ERR(goto done);

	fputs("\nLoading private key.\n", stdout);
	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->load_private(key, signer) )
		ERR(goto done);


	/* Start client mode. */
	fputs("\nConnecting to provisioning server.\n", stdout);
	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));

	if ( !pipe->init_client(pipe, PROVISIONER_HOST, PROVISIONER_PORT) ) {
		fputs("Cannot initialize secured channel.\n", stderr);
		goto done;
	}
	if ( !pipe->start_client_mode2(pipe, key)) {
		fputs("Error starting client mode.\n", stderr);
		goto done;
	}


	/* Verify remote connection. */
	signer->reset(signer);
	if ( !signer->add(signer, (void *) Provisioner, sizeof(Provisioner)) )
		ERR(goto done);
	if ( !pipe->verify(pipe, signer, &status) )
		ERR(goto done);
	if ( !status )
		ERR(goto done);
	fputs("\nVerified provisioning server.\n", stdout);


	/* Read the keyid from the caller. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	INIT(HurdLib, Buffer, apikey, ERR(goto done));

	if ( !pipe->receive_packet(pipe, apikey) )
		ERR(goto done);


	/* Generate and send the enclave identity. */
	INIT(NAAAIM, SEALkey, idkey, ERR(goto done));
	if ( !idkey->generate_static_key(idkey, SRDE_KEYPOLICY_SIGNER, \
					 apikey) )
		ERR(goto done);

	apikey->reset(apikey);
	if ( !idkey->get_iv_key(idkey, spid, apikey) )
		ERR(goto done);

	if ( !pipe->send_packet(pipe, PossumPipe_data, apikey) )
		ERR(goto done);


	/* Receive the SPID and APIkey. */
	spid->reset(spid);
	apikey->reset(apikey);
	if ( !pipe->receive_packet(pipe, spid) )
		ERR(goto done);
	if ( !pipe->receive_packet(pipe, apikey) )
		ERR(goto done);


	/* Save the keys. */
	INIT(NAAAIM, SEALEDblob, creds, ERR(goto done));
	if ( !creds->add_Buffer(creds, spid) )
		ERR(goto done);
	if ( !creds->add_Buffer(creds, apikey) )
		ERR(goto done);
	if ( !creds->seal(creds) )
		ERR(goto done);

	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_rw(file, CREDENTIAL_FILE) )
		ERR(goto done);

	apikey->reset(apikey);
	if ( !creds->get_Buffer(creds, apikey) )
		ERR(goto done);

	if ( !file->write_Buffer(file, apikey) )
		ERR(goto done);

	fputs("\nProvisioned credentials.\n", stdout);


 done:
	WHACK(spid);
	WHACK(apikey);
	WHACK(pipe);
	WHACK(signer);
	WHACK(key);
	WHACK(idkey);
	WHACK(creds);
	WHACK(file);

	return retn ? 0 : 1;

}


/**
 * Private function
 *
 * This function fetches the quoting enclave target information for
 * the attesting client.
 *
 * \param		The SRDEquote object that is being used to
 *			implement the report generation.

 * \param packet	A pointer to the object that will be used
 *			to return information to the client.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the generation of the target information succeeded.  A
 *		false value indicates testing failed while a true value
 *		indicates it was successful.
 */

_Bool _get_qe_targetinfo(CO(SRDEquote, quoter), CO(Buffer, packet))

{
	_Bool retn = false;

	struct SGX_targetinfo *tp;


	/* Initial the quoting object and obtain QE target information. */
	if ( !quoter->init(quoter, QE_TOKEN, PCE_TOKEN, EPID) )
		ERR(goto done);

	tp = quoter->get_qe_targetinfo(quoter);

	packet->reset(packet);
	if ( !packet->add(packet, (void *) tp, sizeof(struct SGX_targetinfo)) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Private function
 *
 * This function implements generation of the quote for the enclave
 * that has initiated the request for attestation.  That quote is
 * then used to generate a request for a remote attestation report
 * on that enclave
 *
 * \param quoter	The SRDEquote object being used to manage
 *			generation of the quote and report.
 *
 * \param packet	A pointer to the object containing the target
 *			report and in which the attestation report
 *			will be returned.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the generation fo the report succeeded.  A false value
 *		indicates testing failed while a true value indicates
 *		the output object contains a valid report.
 */

_Bool _request_report(CO(SRDEquote, quoter), CO(Buffer, packet))

{
	_Bool retn = false;

	uint8_t *bp;

	size_t nonce_size;

	char keystr[33];

	struct SGX_report report;

	Buffer spid   = NULL,
	       creds  = NULL,
	       quote  = NULL;

	String spidkey = NULL,
	       apikey  = NULL,
	       ias     = NULL;

	File file = NULL;

	SEALEDblob credblob = NULL;

	RandomBuffer nonce = NULL;


	/* Unseal the attestation credentials. */
	INIT(HurdLib, Buffer, creds, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, CREDENTIAL_FILE) )
		ERR(goto done);
	if ( !file->slurp(file, creds) )
		ERR(goto done);

	INIT(NAAAIM, SEALEDblob, credblob, ERR(goto done));
	if ( !credblob->add_Buffer(credblob, creds) )
		ERR(goto done);
	if ( !credblob->unseal(credblob) )
		ERR(goto done);

	creds->reset(creds);
	if ( !credblob->get_Buffer(credblob, creds) )
		ERR(goto done);

	INIT(HurdLib, String, spidkey, ERR(goto done));
	memset(keystr, '\0', sizeof(keystr));
	memcpy(keystr, creds->get(creds), creds->size(creds) / 2);
	if ( !spidkey->add(spidkey, keystr) )
		ERR(goto done);

	INIT(HurdLib, String, apikey, ERR(goto done));
	memcpy(keystr, creds->get(creds) + spidkey->size(spidkey), \
	       creds->size(creds) / 2);
	if ( !apikey->add(apikey, keystr) )
		ERR(goto done);


	/* Generate quote. */
	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( !nonce->generate(nonce, 16) )
		ERR(goto done);

	bp = packet->get(packet) + sizeof(unsigned int);
	memcpy(&report, bp, sizeof(struct SGX_report));

	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spidkey->get(spidkey)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quoter->generate_quote(quoter, &report, spid, \
				     nonce->get_Buffer(nonce), quote) )
		ERR(goto done);


	/* Add report nonce if one has been provided. */
	nonce_size = packet->size(packet) - sizeof(unsigned int) - \
		sizeof(struct SGX_report);
	if ( nonce_size > 0 ) {
		if ( nonce_size > 16 )
			ERR(goto done);

		bp += sizeof(struct SGX_report);
		spid->reset(spid);
		if ( !spid->add(spid, bp, nonce_size) )
			ERR(goto done);
		if ( !quoter->set_nonce(quoter, spid) )
			ERR(goto done);
	}


	/* Generate attestation report. */
	INIT(HurdLib, String, ias, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, ias, apikey) )
		ERR(goto done);

	packet->reset(packet);
	if ( !packet->add(packet, (void *) ias->get(ias), ias->size(ias) + 1) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(spid);
	WHACK(creds);
	WHACK(quote);
	WHACK(spidkey);
	WHACK(apikey);
	WHACK(ias);
	WHACK(file);
	WHACK(credblob);
	WHACK(nonce);

	return retn;
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
	_Bool status,
	      retn = false;

	unsigned int *sp;

	SRDEpipe_type type;

	static enum {
		waiting,
		send_report
	} request_state = waiting;

	Buffer endpoint = NULL;

	static Buffer packet = NULL;

	static SRDEpipe pipe = NULL;

	static SRDEquote quoter = NULL;


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

		INIT(HurdLib, Buffer, endpoint, ERR(goto done));
		if ( !endpoint->add(endpoint, (void *) Attestation_clients, \
				  sizeof(Attestation_clients)) )
			ERR(goto done);
		if ( !pipe->verify(pipe, endpoint, &status) )
			ERR(goto done);
		if ( !status )
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
		WHACK(packet);
		WHACK(pipe);

		retn = true;
		goto done;
	}


	/* Handle incoming packet. */
	sp = (unsigned int *) packet->get(packet);

	switch ( request_state ) {
		case waiting:
			if ( *sp != 1 )
				ERR(goto done);

			INIT(NAAAIM, SRDEquote, quoter, ERR(goto done));
			if ( !_get_qe_targetinfo(quoter, packet) )
				ERR(goto done);

			request_state = send_report;
			break;

		case send_report:
			if ( *sp != 2 )
				ERR(goto done);
			if ( !_request_report(quoter, packet) )
				ERR(goto done);
			WHACK(quoter);
			break;
	}


	/* Return packet. */
	if ( !pipe->send_packet(pipe, SRDEpipe_data, packet) )
		ERR(goto done);
	if ( packet->size(packet) > ep->bufr_size ) {
		ep->needed = packet->size(packet);
		ep->bufr_size = 0;
		return true;
	}
	else {
		memset(ep->bufr, '\0', ep->bufr_size);
		memcpy(ep->bufr, packet->get(packet), packet->size(packet));
		ep->bufr_size = packet->size(packet);
		WHACK(packet);
		return true;
	}

	retn = true;


 done:
	ep->bufr_size = 0;

	WHACK(endpoint);

	return retn;
}
