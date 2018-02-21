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
#include "QEenclave.h"
#include "PCEenclave.h"
#include "SGXepid.h"

#include "LocalSource-interface.h"


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
	1, {ocall0_handler}
};


/**
 * Static public function.
 *
 * This function opens and initializes an enclave whose name and
 * token are specified.
 *
 * \param enclave	The object which will be used to manage the
 *			enclave.
 *
 * \param device	A pointer to a null-terminated character buffer
 *			containing the name of the SGX device used to
 *			issue the control commands to the kernel
 *			driver.
 *
 * \param name		A pointer to a null-terminated character buffer
 *			containing the name of the shared object
 *			file containing the enclave image.
 *
 * \param token		A pointer to a null-terminated character buffer
 *			containing the name of the file containing
 *			the initialization token.
 *
 * \param debug		A boolean value used to indicate whether or
 *			not the debug attribute is to be set on
 *			the enclave.
 *
 * \return	If an error is encountered while initializing the
 *		enclave a false value is returned.  A true value indicates
 *		the enclave has been loaded and initialized.
 */

static _Bool open_enclave(CO(SGXenclave, enclave), CO(char *, device), \
			  CO(char *, name), CO(char *, token), 	       \
			  const _Bool debug)

{
	_Bool retn = false;

	struct SGX_einittoken *einit;

	Buffer bufr = NULL;

	File token_file = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	if ( !enclave->open_enclave(enclave, device, name, debug) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}


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
	     *sgx_device     = "/dev/isgx",
	     *source_token   = "target.token",
	     *quote_token    = "qe.token",
	     *pce_token	     = "pce.token",
	     *source_enclave = "LocalTarget.signed.so",
	     *url	     = "https://as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/report";

	char *quote_value = NULL;

	int rc,
	    opt,
	    retn = 1;

	struct SGX_targetinfo qe_target_info;

	struct SGX_report __attribute__((aligned(512))) enclave_report;

	struct SGX_psvn pce_psvn;

	struct LocalSource_ecall0_interface source_ecall0;

	Buffer bufr	= NULL,
	       spid	= NULL,
	       quote	= NULL,
	       http_in	= NULL,
	       http_out = NULL;

	String output = NULL;

	RandomBuffer nonce = NULL;

	Base64 base64 = NULL;

	QEenclave qe = NULL;

	PCEenclave pce = NULL;

	SGXenclave source = NULL;

	HTTP http = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "e:q:s:Q:")) != EOF )
		switch ( opt ) {
			case 'e':
				epid_blob = optarg;
				break;
			case 'q':
				quote_token = optarg;
				break;
			case 's':
				spid_key = optarg;
				break;
			case 'Q':
				quote_value = optarg;
				break;
		}


	/* Verify arguements. */
	if ( epid_blob == NULL ) {
		fputs("No EPID blob specified.\n", stderr);
		goto done;
	}

	if ( spid_key == NULL ) {
		fputs("No SPID specified.\n", stderr);
		goto done;
	}


	/* Print banner. */
	fprintf(stdout, "%s: Remote attestation test utility.\n", PGM);
	fprintf(stdout, "%s: (C)IDfusion, LLC\n", PGM);


	/* Load and initialize the source and target enclaves. */
	INIT(NAAAIM, QEenclave, qe, ERR(goto done));
	if ( !qe->open(qe, quote_token) )
		ERR(goto done);

	qe->get_target_info(qe, &qe_target_info);
	fputs("\nObtained target enclave information.\n\n", stdout);


	/* Verify the EPID blob. */
	if ( !qe->load_epid(qe, epid_blob) )
		ERR(goto done);
	fputs("Loaded and verified EPID.\n", stdout);


	/* Get the platform security information for the PCE enclave. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, PCEenclave, pce, ERR(goto done));
	if ( !pce->open(pce, pce_token) )
		ERR(goto done);
	pce->get_psvn(pce, &pce_psvn);
	fputs("\nHave PCE security information.\n", stdout);

	bufr->add(bufr, pce_psvn.cpu_svn, sizeof(pce_psvn.cpu_svn));
	fputs("\tCPU svn: ", stdout);
	bufr->print(bufr);
	fprintf(stdout, "\tISV svn: %u\n", pce_psvn.isv_svn);
	WHACK(bufr);


	/*
	 * Load the source enclave which the quote will be generated
	 * for.  The report will be directed to the quoting enclave.
	 */
	INIT(NAAAIM, SGXenclave, source, ERR(goto done));
	if ( !open_enclave(source, sgx_device, source_enclave, source_token, \
			   debug) )
		ERR(goto done);

	source_ecall0.mode   = 1;
	source_ecall0.target = &qe_target_info;
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

	if ( !qe->generate_quote(qe, &enclave_report, 0, spid,		\
				 nonce->get_Buffer(nonce), NULL, quote, \
				 pce_psvn.isv_svn) )
		ERR(goto done);

	fputs("\nBinary quote:\n", stdout);
	quote->hprint(quote);
	fputs("\n", stdout);


	INIT(HurdLib, String, output, ERR(goto done));
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !output->add(output, "{\r\n\"isvEnclaveQuote\":\"") )
		ERR(goto done)
	if ( !base64->encode(base64, quote, output) )
		ERR(goto done);
	if ( !output->add(output, "\"\r\n}\r\n") )
		ERR(goto done);


	/* Post the quote. */
	INIT(HurdLib, Buffer, http_in, ERR(goto done));
	INIT(HurdLib, Buffer, http_out, ERR(goto done));
	INIT(NAAAIM, HTTP, http, ERR(goto done));

	http->add_arg(http, "-v");
	http->add_arg(http, "-S");
	http->add_arg(http, "--no-check-certificate");
	http->add_arg(http, "--secure-protocol=TLSv1_2");
	http->add_arg(http, "--private-key=ias-key.pem");
	http->add_arg(http, "--certificate=ias-cert.pem");
	http->add_arg(http, "-oias.log");

	if ( !http_in->add(http_in, (unsigned char *) output->get(output), \
			   output->size(output)) )
		ERR(goto done);
	if ( quote_value == NULL ) {
		if ( !http->post(http, url, http_in, http_out) )
			ERR(goto done);
	}
	else {
		if ( !http_out->add(http_out, (unsigned char *) quote_value, \
				    strlen(quote_value)) )
			ERR(goto done);
	}


	if ( !http_out->add(http_out, (unsigned char *) "\0", 1) )
		ERR(goto done);
	output->reset(output);
	if ( !output->add(output, (char *) http_out->get(http_out)) )
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
	WHACK(qe);
	WHACK(pce);
	WHACK(source);
	WHACK(output);
	WHACK(base64);
	WHACK(http_in);
	WHACK(http_out);
	WHACK(http);


	return retn;

}
