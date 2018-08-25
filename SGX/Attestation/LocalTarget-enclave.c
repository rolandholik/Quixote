#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <SGX.h>
#include <SGXfusion.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>
#include <Curve25519.h>
#include <SGXquote.h>

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
	char report_data[64] __attribute__((aligned(128)));

	int rc;

	uint8_t macbuffer[16],
		keydata[16] __attribute__((aligned(128)));

	struct SGX_keyrequest keyrequest;

	Buffer b,
	       bufr = NULL,
	       key  = NULL;


	if ( mode == 1) {
		INIT(NAAAIM, Curve25519, SharedKey, goto done);

		memset(report, '\0', sizeof(struct SGX_report));

		memset(report_data, '\0', sizeof(report_data));
		if ( !SharedKey->generate(SharedKey) )
			ERR(goto done);
		b = SharedKey->get_public(SharedKey);
		memcpy(report_data, b->get(b), b->size(b));

		enclu_ereport(target, report, report_data);
		return true;
	}

	/* Mode 2 - verify remote key and generate shared secret. */
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

	if ( memcmp(report->mac, macbuffer, sizeof(report->mac)) != 0 )
		ERR(goto done);


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
	return true;
}


/**
 * External ECALL 1.
 *
 * This method implements the generation of a remote attestion quote
 * and its verification from within an enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		verification of the report succeeded.  A false value
 *		indicates the report verification failed..  A true
 *		value indicates the report is valid.
 */

_Bool test_attestation(char *qe_token, char *pce_token, char *epid_blob, \
		       char *spid_key)


{
	char report_data[64] __attribute__((aligned(128)));

	struct SGX_targetinfo *tp,
			      target;

	struct SGX_report __attribute__((aligned(512))) report;

	Buffer b,
	       spid  = NULL,
	       quote = NULL;

	String output = NULL;

	RandomBuffer nonce = NULL;

	SGXquote quoter = NULL;


	fputs("\nInitializing quote.\n", stdout);
	INIT(NAAAIM, SGXquote, quoter, ERR(goto done));
	if ( !quoter->init(quoter, "qe.token", "pce.token", epid_blob) )
		ERR(goto done);

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
	if ( !spid->add_hexstring(spid, spid_key) ) {
		fputs("Invalid SPID.\n", stderr);
		goto done;
	}


	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( !nonce->generate(nonce, 16) ) {
		fputs("Unable to generate nonce.\n", stderr);
		goto done;
	}

	fputs("\nGenerating quote with:\n", stdout);
	fprintf(stdout, "\tSPID:  %s\n", spid_key);
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
	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output) )
		ERR(goto done);

	fputs("\nAttestation report:\n", stdout);
	output->print(output);


	/* Decode response values. */
	fputc('\n', stdout);
	if ( !quoter->decode_report(quoter, output) )
		ERR(goto done);
	quoter->dump_report(quoter);


 done:
	WHACK(spid);
	WHACK(nonce);
	WHACK(quoter);

	return true;
}
