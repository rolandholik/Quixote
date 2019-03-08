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

#include <SGX.h>
#include <SGXfusion.h>

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
		    struct SGX_report *report)

{
	_Bool retn = false;

	char report_data[64] __attribute__((aligned(128)));

	int rc;

	uint8_t macbuffer[16],
		keydata[16] __attribute__((aligned(128)));

	struct SGX_keyrequest keyrequest;

	Buffer b,
	       bufr = NULL,
	       key  = NULL,
	       mac  = NULL,
	       dh   = NULL;


	/* Generate a NULL report for target context generation. */
	if ( mode == 1 ) {
		memset(target, '\0', sizeof(struct SGX_targetinfo));
		memset(report_data, '\0', sizeof(report_data));
		enclu_ereport(target, report, report_data);

		target->mrenclave  = report->body.mr_enclave;
		target->attributes = report->body.attributes;
		target->miscselect = report->body.miscselect;

		return true;
	}


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, Buffer, key,  ERR(goto done));
	INIT(HurdLib, Buffer, mac,  ERR(goto done));
	INIT(HurdLib, Buffer, dh,   ERR(goto done));

	fputs("Source enclave:\n", stdout);
	if ( !key->add(key, (unsigned char *) report->keyid, \
		       sizeof(report->keyid)) )
		ERR(goto done);
	fputs("key:\n", stdout);
	key->print(key);

	if ( !mac->add(mac, (unsigned char *) report->mac, \
		       sizeof(report->mac)) )
		ERR(goto done);
	fputs("\nMAC:\n", stdout);
	mac->print(mac);

	if ( !dh->add(dh, (unsigned char *) report->body.reportdata, \
		      sizeof(report->body.reportdata)) )
		ERR(goto done);
	fputs("\ndata:\n", stdout);
	dh->print(dh);


	/* Request the report key. */
	memset(keydata, '\0', sizeof(keydata));
	memset(&keyrequest, '\0', sizeof(struct SGX_keyrequest));

	keyrequest.keyname = SGX_KEYSELECT_REPORT;
	memcpy(keyrequest.keyid, report->keyid, sizeof(keyrequest.keyid));


	/* Get report key and verify. */
	if ( (rc = enclu_egetkey(&keyrequest, keydata)) != 0 ) {
		fprintf(stdout, "EGETKEY return: %d\n", rc);
		goto done;
	}

	rc = sgx_rijndael128_cmac_msg(&keydata, (uint8_t *) report,  \
				      sizeof(struct SGX_reportbody), \
				      macbuffer);
	memset(keydata, '\0', sizeof(keydata));
	if ( rc != SGX_SUCCESS )
		goto done;

	fputs("\ncomputed MAC:\n", stdout);
	bufr->reset(bufr);
	if ( !bufr->add(bufr, (unsigned char *) macbuffer, sizeof(macbuffer)) )
		ERR(goto done);
	bufr->print(bufr);
	fputc('\n', stdout);

	if ( memcmp(report->mac, macbuffer, sizeof(report->mac)) == 0 )
		fputs("Report verified.\n", stdout);
	else
		fputs("Report not verified.\n", stdout);


	/*
	 * Generate a shared key report response.
	 */
	INIT(NAAAIM, Curve25519, SharedKey, ERR(goto done));
	if ( !SharedKey->generate(SharedKey) )
		ERR(goto done);

	key->reset(key);
	bufr->reset(bufr);
	if ( !bufr->add(bufr, report->body.reportdata, 32) )
		ERR(goto done);
	if ( !SharedKey->compute(SharedKey, bufr, key) )
		ERR(goto done);
	fputs("\nSource shared key:\n", stdout);
	key->print(key);

	memset(report_data, '\0', sizeof(report_data));
	b = SharedKey->get_public(SharedKey);
	memcpy(report_data, b->get(b), b->size(b));

	memset(target, '\0', sizeof(struct SGX_targetinfo));
	target->mrenclave  = report->body.mr_enclave;
	target->attributes = report->body.attributes;
	target->miscselect = report->body.miscselect;

	enclu_ereport(target, report, report_data);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(key);
	WHACK(mac);
	WHACK(dh);

	return retn;
}
