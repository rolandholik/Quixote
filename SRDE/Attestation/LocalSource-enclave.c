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

#include <NAAAIM.h>
#include <Curve25519.h>

#include <SRDE.h>
#include <SRDEfusion.h>
#include <SRDEpipe.h>

#include <Report.h>

#include "LocalSource-interface.h"

sgx_status_t sgx_rijndael128_cmac_msg(uint8_t (*)[16], uint8_t *, size_t, \
				      uint8_t *);

/**
 * The elliptic curve object which will be used.
 */
static Curve25519 SharedKey = NULL;


/**
 * External ECALL 0.
 *
 * This method implements the verification of a REPORTDATA structure
 * provided by the specified target enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		verification of the report succeeded.  A false value
 *		indicates the report verification failed..  A true
 *		value indicates the report is valid.
 */

_Bool verify_report(unsigned int mode, struct SGX_targetinfo *target, \
		    struct SGX_report *rp)

{
	_Bool status,
	      retn = false;

	Buffer b,
	       bufr = NULL,
	       key  = NULL,
	       mac  = NULL,
	       dh   = NULL;

	Report report = NULL;


	/* Generate a NULL report for target context generation. */
	if ( mode == 1 ) {
		INIT(NAAAIM, Report, report, ERR(goto done));
		if ( !report->get_targetinfo(report, target) )
			ERR(goto done);

		WHACK(report);
		return true;
	}


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, Buffer, key,  ERR(goto done));
	INIT(HurdLib, Buffer, mac,  ERR(goto done));
	INIT(HurdLib, Buffer, dh,   ERR(goto done));

	fputs("Source enclave:\n", stdout);
	if ( !key->add(key, (unsigned char *) rp->keyid, sizeof(rp->keyid)) )
		ERR(goto done);
	fputs("keyid:\n", stdout);
	key->print(key);

	if ( !mac->add(mac, (unsigned char *) rp->mac, sizeof(rp->mac)) )
		ERR(goto done);
	fputs("\nMAC:\n", stdout);
	mac->print(mac);

	if ( !dh->add(dh, (unsigned char *) rp->body.reportdata, \
		      sizeof(rp->body.reportdata)) )
		ERR(goto done);
	fputs("\ndata:\n", stdout);
	dh->print(dh);


	/* Verify the remote report. */
	INIT(NAAAIM, Report, report, ERR(goto done));
	if ( !report->validate_report(report, rp, &status) )
		ERR(goto done);

	if ( status )
		fputs("\nTarget report verified.\n", stdout);
	else
		fputs("\nTarget report not verified.\n", stdout);


	/*
	 * Generate a shared key report response.
	 */
	INIT(NAAAIM, Curve25519, SharedKey, ERR(goto done));
	if ( !SharedKey->generate(SharedKey) )
		ERR(goto done);

	key->reset(key);
	bufr->reset(bufr);
	if ( !bufr->add(bufr, rp->body.reportdata, 32) )
		ERR(goto done);
	if ( !SharedKey->compute(SharedKey, bufr, key) )
		ERR(goto done);
	fputs("\nSource shared key:\n", stdout);
	key->print(key);

	b = SharedKey->get_public(SharedKey);

	if ( !report->generate_report(report, target, b, rp) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(key);
	WHACK(mac);
	WHACK(dh);
	WHACK(report);

	WHACK(SharedKey);

	return retn;
}


/**
 * External ECALL 1.
 *
 * This method implements testing of an SRDEpipe connection to a
 * target enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		testing of the SRDEpipe succeeded.  A false value
 *		indicates the test failed.  A true value indicates
 *		the test was successful.
 */

_Bool test_pipe(struct LocalSource_ecall1 *ep)

{
	_Bool retn = false;

	char *msg = "This is a message\n";

	Buffer bufr = NULL;

	SRDEpipe pipe = NULL;


	INIT(NAAAIM, SRDEpipe, pipe, ERR(goto done));
	if ( !pipe->setup(pipe, "LocalTarget.signed.so", 2, "target.token", \
			  true) )
		ERR(goto done);

	if ( !pipe->connect(pipe) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) msg, strlen(msg) + 1) )
		ERR(goto done);

	if ( !pipe->send_packet(pipe, SRDEpipe_data, bufr) )
		ERR(goto done);


	/* Check for and print return packet. */
	if ( bufr->size(bufr) > 0 ) {
		if ( !pipe->receive_packet(pipe, bufr) )
			ERR(goto done);
		fputs("\nClient have return packet:\n", stdout);
		bufr->hprint(bufr);
	}


	/* Terminate the connection. */
	if ( !pipe->close(pipe) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(pipe);
	WHACK(bufr);

	return retn;
}
