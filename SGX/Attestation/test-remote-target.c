/** \file
 * This file contains a test harness for exercising the generation of
 * a remotely verifiable attestation of an enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define PGM "test-remote-target"


#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>
#include <Base64.h>
#include <HTTP.h>

#include "SGX.h"
#include "SGXenclave.h"
#include "SGXquote.h"
#include "SGXepid.h"

#include "LocalTarget-interface.h"


/**
 * The following structure defines the information 'blob' that is
 * returned from the Intel attestation servers if the EPID group
 * has been revoked or is out of date.
 */
struct platform_info_blob {
	uint8_t sgx_epid_group_flags;
	uint8_t sgx_tcb_evaluation_flags[2];
	uint8_t pse_evaluation_flags[2];
	struct SGX_psvn latest_equivalent_tcb_psvn;
	uint8_t latest_pse_isvsvn[4];
	uint8_t latest_psda_svn[4];
	uint32_t xeid;
	uint8_t GroupId[4];
	uint8_t signature[64];
} __attribute__((packed));



/** OCALL interface definition. */
struct SGXfusion_ocall0_interface {
	char* str;
} SGXfusion_ocall0;

int ocall0_handler(struct SGXfusion_ocall0_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

static const struct OCALL_api ocall_table = {
	4,
	{
		ocall0_handler,
		NULL, /*ocall2_handler */
		NULL, /*Duct_sgxmgr*/
		SGXquote_sgxmgr,
	}
};


/**
 * Internal private function.
 *
 * This method parses the supplied input for a single JSON field.
 *
 * \param field	The object containing the field to be parsed.
 *
 * \param rgx	The object which is to be used to create the
 *		regular expression.
 *
 * \param fd	The field descriptor tag which is to be returned.
 *
 * \param value	A pointer to the object that will be loaded with
 *		the parsed field value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_field(CO(String, field), CO(String, rgx), CO(char *, fd), \
			CO(String, value))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     element[2];

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Extract the field element. */
	value->reset(value);

	rgx->reset(rgx);
	rgx->add(rgx, ".*\"");
	rgx->add(rgx, fd);
	if ( !rgx->add(rgx, "\":\"([^\"]*).*") )
		ERR(goto done);

	if ( regcomp(&regex, rgx->get(rgx), REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field->get(field), 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > field->size(field) )
		ERR(goto done);


	/* Copy the field element to the output object. */
	memset(element, '\0', sizeof(element));
	fp = field->get(field) + regmatch[1].rm_so;

	while ( len-- ) {
		element[0] = *fp;
		value->add(value, element);
		++fp;
	}
	if ( value->poisoned(value) )
		ERR(goto done);

	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}

/**
 * Static public function.
 *
 * This function decodes the Intel Authentication Services (IAS) report
 * which is the JSON encoded result from the posting of an enclave quote
 * to the IAS service.
 *
 * \param enclave	The object which contains the quote.
 *
 * \return	If an error is encountered while decoding the response
 *		a false value is returned.  A true value indicates the
 *		quote was succesfully processed.
 */

static _Bool decode_ias_report(CO(String, report))

{
	_Bool retn		 = false,
	      have_platform_info = false;

	uint16_t flags,
	         tlv_size;

	uint32_t gid;

	static const char *revoked  = "GROUP_REVOKED",
			  *outdated = "GROUP_OUT_OF_DATE";

	struct TLVshort {
		uint8_t type;
		uint8_t version;
		uint16_t size;
	} __attribute__((packed)) *tlv;

	struct platform_info_blob plb;

	struct SGX_quote *qp,
			  quote;

	struct SGX_psvn *psvnp;

	struct SGX_reportbody *bp;

	Buffer bufr = NULL;

	String field  = NULL,
	       fregex = NULL;

	Base64 base64 = NULL;


	INIT(HurdLib, String, field, ERR(goto done));
	INIT(HurdLib, String, fregex, ERR(goto done));

	if ( !_get_field(report, fregex, "id", field) )
		ERR(goto done);
	fputs("ID:        ", stdout);
	field->print(field);

	if ( !_get_field(report, fregex, "timestamp", field) )
		ERR(goto done);
	fputs("Timestamp: ", stdout);
	field->print(field);

	if ( !_get_field(report, fregex, "isvEnclaveQuoteStatus", field) )
		ERR(goto done);
	have_platform_info = (strcmp(outdated, field->get(field)) == 0 || \
			      strcmp(revoked,  field->get(field)) == 0);
	fputs("Status:    ", stdout);
	field->print(field);

	if ( !_get_field(report, fregex, "isvEnclaveQuoteBody", field) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !base64->decode(base64, field, bufr) )
		ERR(goto done);

	qp = (struct SGX_quote *) bufr->get(bufr);
	quote = *qp;

	fputs("\nQuote:\n", stdout);
	fprintf(stdout, "\tversion:    %u\n", quote.version);
	fprintf(stdout, "\tsign_type:  %u\n", quote.sign_type);

	memcpy(&gid, quote.epid_group_id, sizeof(gid));
	fprintf(stdout, "\tgroup id:   0x%08x\n", gid);

	fprintf(stdout, "\tQE svn:     %u\n", quote.qe_svn);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, (unsigned char *) quote.basename, \
			sizeof(quote.basename)) )
		ERR(goto done);
	fputs("\tBasename:   ", stdout);
	bufr->print(bufr);

	bp = &quote.report_body;
	fputs("\tReport body:\n", stdout);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->cpusvn, sizeof(bp->cpusvn)) )
		ERR(goto done);
	fputs("\t\tcpusvn:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tmiscselect:  %u\n", bp->miscselect);
	fprintf(stdout, "\t\tattributes:  flags=0x%0lx, xfrm=0x%0lx\n", \
		bp->attributes.flags, bp->attributes.xfrm);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->mr_enclave.m, sizeof(bp->mr_enclave.m)) )
		ERR(goto done);
	fputs("\t\tmeasurement: ", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->mrsigner, sizeof(bp->mrsigner)) )
		ERR(goto done);
	fputs("\t\tsigner:      ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tISV prodid:  %u\n", bp->isvprodid);
	fprintf(stdout, "\t\tISV svn:     %u\n", bp->isvsvn);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, bp->reportdata, sizeof(bp->reportdata)) )
		ERR(goto done);
	fputs("\t\treportdata:  ", stdout);
	bufr->print(bufr);


	/* Decode platform information. */
	if ( !have_platform_info ) {
		retn = true;
		goto done;
	}

	fputs("\nPlatform Info Report:\n", stdout);
	if ( !_get_field(report, fregex, "platformInfoBlob", field) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_hexstring(bufr, field->get(field)) )
		ERR(goto done);

	tlv = (struct TLVshort *) bufr->get(bufr);
	if ( (tlv->type != 21) || (tlv->version != 2) )
		ERR(goto done);
	tlv_size = htons(tlv->size);

	bufr->reset(bufr);
	if ( !bufr->add_hexstring(bufr, field->get(field) + sizeof(*tlv)*2) )
		ERR(goto done);
	if ( tlv_size != bufr->size(bufr) )
		ERR(goto done);

	memcpy(&plb, bufr->get(bufr), sizeof(plb));

	fprintf(stdout, "\tEPID group flags: %u\n", plb.sgx_epid_group_flags);
	if ( plb.sgx_epid_group_flags & 0x1 )
		fputs("\t\tEPID group revoked.\n", stdout);
	if ( plb.sgx_epid_group_flags & 0x2 )
		fputs("\t\tPerformance rekey available.\n", stdout);
	if ( plb.sgx_epid_group_flags & 0x4 )
		fputs("\t\tEPID group out of date.\n", stdout);

	memcpy(&flags, plb.sgx_tcb_evaluation_flags, sizeof(flags));
	flags = htons(flags);
	fprintf(stdout, "\n\tTCB evaluation flags: %u\n", flags);
	if ( flags & 0x1 )
		fputs("\t\tCPU svn out of date.\n", stdout);
	if ( flags & 0x2 )
		fputs("\t\tQE enclave out of date.\n", stdout);
	if ( flags & 0x4 )
		fputs("\t\tPCE enclave out of date.\n", stdout);

	memcpy(&flags, plb.pse_evaluation_flags, sizeof(flags));
	flags = htons(flags);
	fprintf(stdout, "\n\tPSE evaluation flags: %u\n", flags);

	psvnp = &plb.latest_equivalent_tcb_psvn;
	bufr->reset(bufr);
	if ( !bufr->add(bufr, psvnp->cpu_svn, sizeof(psvnp->cpu_svn)) )
		ERR(goto done);

	fputs("\n\tRecommended platform status:\n", stdout);
	fputs("\t\tCPU svn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tISV svn: %u\n", psvnp->isv_svn);

	fprintf(stdout, "\n\tExtended group id: 0x%x\n", plb.xeid);

	retn = true;


 done:
	WHACK(field);
	WHACK(fregex);

	WHACK(bufr);
	WHACK(base64);

	return retn;
}


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *spid_key	     = NULL,
	     *epid_blob	     = NULL,
	     *source_token   = "target.token",
	     *quote_token    = "qe.token",
	     *pce_token	     = "pce.token",
	     *source_enclave = "LocalTarget.signed.so";

	int rc,
	    opt,
	    retn = 1;

	enum {
		untrusted,
		trusted
	} mode = untrusted;

	struct SGX_report __attribute__((aligned(512))) enclave_report;

	struct LocalTarget_ecall0_interface source_ecall0;

	struct LocalTarget_ecall1 source_ecall1;

	Buffer spid	= NULL,
	       quote	= NULL,
	       http_in	= NULL,
	       http_out = NULL;

	String output = NULL;

	RandomBuffer nonce = NULL;

	Base64 base64 = NULL;

	SGXquote quoter = NULL;

	SGXenclave source = NULL;

	HTTP http = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "Te:q:s:")) != EOF )
		switch ( opt ) {
			case 'T':
				mode = trusted;
				break;
			case 'e':
				epid_blob = optarg;
				break;
			case 'q':
				quote_token = optarg;
				break;
			case 's':
				spid_key = optarg;
				break;
		}


	/* Print banner. */
	fprintf(stdout, "%s: Remote test utility.\n", PGM);
	fprintf(stdout, "%s: (C)2018 IDfusion, LLC\n", PGM);


	/* Verify arguements. */
	if ( epid_blob == NULL ) {
		fputs("No EPID blob specified.\n", stderr);
		goto done;
	}

	if ( spid_key == NULL ) {
		fputs("No SPID specified.\n", stderr);
		goto done;
	}


	/* Test trusted mode. */
	if ( mode == trusted ) {
		fputs("\nTesting enclave mode attestation.\n", stdout);

		INIT(NAAAIM, SGXenclave, source, ERR(goto done));
		if ( !source->setup(source, source_enclave, source_token, \
				    debug) )
			ERR(goto done);

		source_ecall1.qe_token	    = quote_token;
		source_ecall1.qe_token_size = strlen(quote_token) + 1;

		source_ecall1.pce_token	     = pce_token;
		source_ecall1.pce_token_size = strlen(pce_token) + 1;

		source_ecall1.epid_blob	     = epid_blob;
		source_ecall1.epid_blob_size = strlen(epid_blob) + 1;

		source_ecall1.spid 	= spid_key;
		source_ecall1.spid_size = strlen(spid_key) + 1;

		if ( !source->boot_slot(source, 1, &ocall_table, \
					&source_ecall1, &rc) ) {
			fprintf(stderr, "Enclave return error: %d\n", rc);
			ERR(goto done);
		}

		if ( !source_ecall1.retn )
			fputs("Trusted remote attestation test failed.\n", \
			      stderr);
		goto done;
	}


	/* Load and initialize the quoting object. */
	fputs("\nTesting non-enclave attestation.\n", stdout);

	fputs("\nInitializing quote.\n", stdout);
	INIT(NAAAIM, SGXquote, quoter, ERR(goto done));
	if ( !quoter->init(quoter, quote_token, pce_token, epid_blob) )
		ERR(goto done);


	/*
	 * Load the source enclave which the quote will be generated
	 * for.  The report will be directed to the quoting enclave.
	 */
	INIT(NAAAIM, SGXenclave, source, ERR(goto done));
	if ( !source->setup(source, source_enclave, source_token, debug) )
		ERR(goto done);

	source_ecall0.mode   = 1;
	source_ecall0.target = quoter->get_qe_targetinfo(quoter);
	source_ecall0.report = &enclave_report;
	if ( !source->boot_slot(source, 0, &ocall_table, &source_ecall0, \
				&rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn )
		ERR(goto done);
	fputs("\nGenerated attesting enclave report.\n", stdout);


	/*
	 * Convert the SPID into a binary buffer and generate the
	 * nonce to be used.
	 */
	if ( strlen(spid_key) != 32 ) {
		fputs("Invalid SPID size.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) ) {
		fputs("Invalid SPID.\n", stderr);
		goto done;
	}
	fputs("\nGenerating quote with:\n", stdout);
	fprintf(stdout, "\tSPID:  %s\n", spid_key);


	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( !nonce->generate(nonce, 16) ) {
		fputs("Unable to generate nonce.\n", stderr);
		goto done;
	}
	fputs("\tNONCE: ", stdout);
	nonce->get_Buffer(nonce)->print(nonce->get_Buffer(nonce));


	/* Request the quote. */
	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quoter->generate_quote(quoter, &enclave_report, spid, \
				     nonce->get_Buffer(nonce), quote) )
		ERR(goto done);

	fputs("\nBinary quote:\n", stdout);
	quote->hprint(quote);
	fputs("\n", stdout);


	/* Request a report on the quote. */
	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output) )
		ERR(goto done);

	fputs("Attestation report:\n", stdout);
	output->print(output);


	/* Decode response values. */
	fputc('\n', stdout);
	decode_ias_report(output);

	retn = 0;


 done:
	WHACK(spid);
	WHACK(quote);
	WHACK(nonce);
	WHACK(source);
	WHACK(output);
	WHACK(base64);
	WHACK(quoter);
	WHACK(http_in);
	WHACK(http_out);
	WHACK(http);

	return retn;

}
