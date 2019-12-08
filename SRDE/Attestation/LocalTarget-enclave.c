/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

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
#include <SRDEquote.h>
#include <Report.h>
#include <SRDEpipe.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>
#include "LocalTarget-interface.h"


sgx_status_t sgx_rijndael128_cmac_msg(uint8_t (*)[16], uint8_t *, size_t, \
				      uint8_t *);


/**
 * The elliptic curve object which will be used.
 */
static Curve25519 SharedKey = NULL;


/**
 * External ECALL 0.
 *
 * This method implements the generation of a REPORTDATA structure
 * destined for the specified target enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		generation of the report succeeded.  A false value
 *		indicates the report data is not valid.  A true
 *		value indicates the report data is valid.
 */

_Bool get_report(unsigned int mode, struct SGX_targetinfo *target, \
		 struct SGX_report *report)

{
	_Bool status;

	Buffer b,
	       bufr = NULL,
	       key  = NULL;

	Report rpt = NULL;


	if ( (mode == 1) || (mode == 3) ) {
		INIT(NAAAIM, Report, rpt, ERR(goto done));
		INIT(NAAAIM, Curve25519, SharedKey, goto done);

		if ( !SharedKey->generate(SharedKey) )
			ERR(goto done);
		b = SharedKey->get_public(SharedKey);

		if ( !rpt->generate_report(rpt, target, b, report) )
			ERR(goto done);
		if ( !rpt->get_targetinfo(rpt, target) )
			ERR(goto done);

		if ( mode == 3 )
			WHACK(SharedKey);

		WHACK(rpt);
		return true;
	}

	/* Mode 2 - verify remote key and generate shared secret. */
	INIT(NAAAIM, Report, rpt, ERR(goto done));
	if ( !rpt->validate_report(rpt, report, &status) )
		ERR(goto done);

	if ( status )
		fputs("\nSource report verified.\n", stdout);
	else
		fputs("\nSource report not verified.\n", stdout);


	/*
	 * Generate a shared key report response.
	 */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, Buffer, key, ERR(goto done));

	if ( !bufr->add(bufr, report->body.reportdata, 32) )
		ERR(goto done);
	if ( !SharedKey->compute(SharedKey, bufr, key) )
		ERR(goto done);
	fputs("\nTarget shared key:\n", stdout);
	key->print(key);


 done:
	WHACK(bufr);
	WHACK(key);
	WHACK(rpt);

	WHACK(SharedKey);

	return true;
}


/**
 * External ECALL 1.
 *
 * This method implements the generation of a remote attestion quote
 * and its verification from within an enclave.
 *
 * ip:		A pointer to the structure that marshalls the arguements
 *		for this ECALL.
 *
 * \return	A boolean value is used to indicate whether or not
 *		verification of the report succeeded.  A false value
 *		indicates the report verification failed..  A true
 *		value indicates the report is valid.
 */

_Bool test_attestation(struct LocalTarget_ecall1 *ip)

{
	char report_data[64] __attribute__((aligned(128)));

	struct SGX_targetinfo *tp,
			      target;

	struct SGX_report __attribute__((aligned(512))) report;

	Buffer b,
	       spid  = NULL,
	       quote = NULL;

	String apikey = NULL,
	       output = NULL;

	RandomBuffer nonce = NULL;

	SRDEquote quoter = NULL;


	fputs("\nInitializing quote.\n", stdout);
	INIT(NAAAIM, SRDEquote, quoter, ERR(goto done));
	if ( !quoter->init(quoter, ip->qe_token, ip->pce_token, \
			   ip->epid_blob) )
		ERR(goto done);
	quoter->development(quoter, ip->development);

	fputs("\nGetting quoting enclave target information.\n", stdout);
	tp = quoter->get_qe_targetinfo(quoter);
	target = *tp;


	/* Generate enclave report. */
	fputs("\nGenerating enclave report/key.\n", stdout);
	INIT(NAAAIM, Curve25519, SharedKey, goto done);

	memset(&report, '\0', sizeof(struct SGX_report));
	memset(report_data, '\0', sizeof(report_data));

	if ( !SharedKey->generate(SharedKey) )
		ERR(goto done);
	b = SharedKey->get_public(SharedKey);
	memcpy(report_data, b->get(b), b->size(b));

	enclu_ereport(&target, &report, report_data);


	/* Setup spid and nonce for quote generation. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, ip->spid) ) {
		fputs("Invalid SPID.\n", stderr);
		goto done;
	}


	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( ip->nonce ) {
		fputs("Setting IAS nonce.\n", stdout);
		if ( !nonce->generate(nonce, 16) ) {
			fputs("Unable to generate IAS nonce.\n", stderr);
			goto done;
		}
		if ( !quoter->set_nonce(quoter, nonce->get_Buffer(nonce)) ) {
			fputs("Unable to set IAS nonce.\n", stderr);
			goto done;
		}
	}

	if ( !nonce->generate(nonce, 16) ) {
		fputs("Unable to generate quote nonce.\n", stderr);
		goto done;
	}

	fputs("\nGenerating quote with:\n", stdout);
	fputs("\tSPID:  ", stdout);
	spid->print(spid);

	fputs("\tNONCE: ", stdout);
	nonce->get_Buffer(nonce)->print(nonce->get_Buffer(nonce));


	/* Request the quote. */
	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quoter->generate_quote(quoter, &report, spid, \
				     nonce->get_Buffer(nonce), quote) )
		ERR(goto done);

	fputs("\nBinary quote:\n", stdout);
	quote->hprint(quote);


	/* Generate the verifying report. */
	if ( ip->apikey ) {
		if ( ip->key[33] != '\0' )
			ERR(goto done);

		INIT(HurdLib, String, apikey, ERR(goto done));
		if ( !apikey->add(apikey, (char *) ip->key) )
			ERR(goto done);
		fputs("\nUsing APIkey: ", stdout);
		apikey->print(apikey);
	}

	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output, apikey) )
		ERR(goto done);

	fputs("\nAttestation report:\n", stdout);
	output->print(output);


	/* Decode response values. */
	fputc('\n', stdout);
	if ( !quoter->decode_report(quoter, output) )
		ERR(goto done);
	quoter->dump_report(quoter);


 done:
	WHACK(SharedKey);

	WHACK(spid);
	WHACK(quote);
	WHACK(apikey);
	WHACK(output);
	WHACK(nonce);
	WHACK(quoter);

	return true;
}


/**
 * External ECALL 2.
 *
 * This method implements testing of an SRDEpipe connection to a
 * target enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		testing of the SRDEpipe succeeded.  A false value
 *		indicates the test failed.  A true value indicates
 *		the test was successful.
 */

_Bool test_pipe(struct SRDEpipe_ecall *ep)

{
	_Bool retn = false;

	char *msg = "This is a return message.\n";

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

	fputs("\nTarget received packet:\n", stdout);
	packet->hprint(packet);

	if ( (type = pipe->receive_packet(pipe, packet)) == SRDEpipe_failure )
		ERR(goto done);

	if ( type == SRDEpipe_eop ) {
		fputs("\nTarget received EOP.\n", stdout);
		retn = true;
		WHACK(pipe);
		goto done;
	}

	fputs("\nTarget packet contents:\n", stdout);
	packet->hprint(packet);


	/* Send return packet message. */
	if ( !packet->add(packet, (void *) msg, strlen(msg) + 1) )
		ERR(goto done);

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
