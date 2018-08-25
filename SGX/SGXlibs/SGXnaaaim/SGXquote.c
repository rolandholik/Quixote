/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement remote attestation quote processing via a SGXquote
 * object running in untrusted userspace.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */


/* Local defines. */


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXquote.h"
#include "Base64.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXquote_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXquote_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following array defines the strings used to indicate the
 * general result of the attestation.
 */
static const char *Quote_status[] = {
	"OK",
	"SIGNATURE_INVALID",
	"GROUP_REVOKED",
	"SIGNATURE_REVOKED",
	"KEY_REVOKED",
	"SIGRL_VERSION_MISMATCH",
	"GROUP_OUT_OF_DATE",
	"UNDEFINED",
	NULL
};


/**
 * The following structure defines the information 'blob' that is
 * returned from the Intel attestation servers if the EPID group
 * has been revoked or is out of date.
 */
struct platform_info {
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


/** SGXquote private state information. */
struct NAAAIM_SGXquote_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Untrusted instance. */
	unsigned int instance;

	/* Object status. */
	_Bool poisoned;

	/* Quoting enclave target information. */
	struct SGX_targetinfo qe_target_info;

	/* Information derived from an attestation report. */
	String id;
	String timestamp;

	enum SGXquote_status status;

	struct SGX_quote quote;

	struct platform_info platform_info;
};


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int sgxquote_ocall(struct SGXquote_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	void *ap;

	size_t quote_token_size,
	       pce_token_size,
	       epid_blob_size = 0,
	       arena_size = sizeof(struct SGXquote_ocall);

	struct SGXquote_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == SGXquote_init ) {
		quote_token_size = strlen(ocall->quote_token) + 1;
		if ( !sgx_is_within_enclave(ocall->quote_token, \
					    quote_token_size) )
			goto done;
		arena_size += quote_token_size;

		pce_token_size = strlen(ocall->pce_token) + 1;
		if ( !sgx_is_within_enclave(ocall->pce_token, \
					    pce_token_size) )
			goto done;
		arena_size += pce_token_size;

		if ( ocall->epid_blob != NULL ) {
			epid_blob_size = strlen(ocall->epid_blob) + 1;
			if ( !sgx_is_within_enclave(ocall->epid_blob, \
						    epid_blob_size) )
				goto done;
			arena_size += epid_blob_size;
		}
	}

	if ( ocall->ocall == SGXquote_generate_report ) {
		if ( !sgx_is_within_enclave(ocall->arena, ocall->bufr_size) )
			goto done;
		arena_size += ocall->bufr_size;
	}


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == SGXquote_init ) {
		ap = ocp->arena;

		memcpy(ap, ocall->quote_token, quote_token_size);
		ocp->quote_token = ap;
		ap += quote_token_size;

		memcpy(ap, ocall->pce_token, pce_token_size);
		ocp->pce_token = ap;
		ap += pce_token_size;

		if ( ocall->epid_blob != NULL ) {
			memcpy(ap, ocall->epid_blob, epid_blob_size);
			ocp->epid_blob = ap;
		}
	}

	if ( ocall->ocall == SGXquote_generate_report )
		memcpy(ocp->arena, ocall->bufr, ocall->bufr_size);


	/* Call the SGX duct manager. */
	if ( (status = sgx_ocall(4, ocp)) == 0 ) {
		retn = true;
		*ocall = *ocp;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXquote_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXquote_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXquote_OBJID;


	S->poisoned = false;
	S->instance = 0;

	return;
}


/**
 * External public method.
 *
 * This method implements the OCALL which initializes the object
 * in untrusted userspace.
 *
 * \param this		A pointer to the quoting object to be initialized.
 *
 * \param quote_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the quoting enclave.
 *
 * \param pce_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the PCE enclave.
 *
 * \param epid_blob	The name of the file containing the EPID
 *			blob.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool init(CO(SGXquote, this), CO(char *, quote_token), \
		  CO(char *, pce_token), CO(char *, epid_blob))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_init;
	ocall.instance	= S->instance;

	ocall.quote_token = (char *) quote_token;
	ocall.pce_token	  = (char *) pce_token;
	ocall.epid_blob	  = (char *) epid_blob;

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which is used to generate an
 * enclave quote for remote attestation.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param report	A pointer to to the enclave report that is to
 *			be attested.
 *
 * \param spid		The service provider identity to be used for
 *			the quote.
 *
 * \param nonce		The random nonce to be used for the quote.
 *
 * \param quote		The object which the binary quote is to be
 *			loaded into.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool generate_quote(CO(SGXquote, this),				 \
			    struct SGX_report *report, CO(Buffer, spid), \
			    CO(Buffer, nonce), CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( spid->poisoned(spid) )
		ERR(goto done);
	if ( spid->size(spid) != 16 )
		ERR(goto done);
	if ( nonce->poisoned(nonce) )
		ERR(goto done);
	if ( nonce->size(nonce) != 16 )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_generate_quote,
	ocall.instance	= S->instance;

	ocall.report = *report;
	memcpy(ocall.spid, spid->get(spid), spid->size(spid));
	memcpy(ocall.nonce, nonce->get(nonce), nonce->size(nonce));

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	if ( !quote->add(quote, ocall.bufr, ocall.bufr_size) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which implements the generation of
 * an attestation requote on an enclave quote.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param quote		The object which contains the quote which is
 *			to be verifed by the authentication servers.
 *
 * \param report	The object that will be loaded with the report
 *			that is returned.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the report generation.  A false value indicates
 *		an error occurred while a true value indicates the report
 *		was successfully generated.
 */

static _Bool generate_report(CO(SGXquote, this), CO(Buffer, quote), \
			     CO(String, report))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;

	struct SGXquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( quote->poisoned(quote) )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_generate_report,
	ocall.instance	= S->instance;

	ocall.bufr	= quote->get(quote);
	ocall.bufr_size = quote->size(quote);

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, ocall.bufr, ocall.bufr_size) )
		ERR(goto done);
	if ( !report->add(report, (char *) bufr->get(bufr)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return true;
}


/**
 * Internal private function.
 *
 * This method parses the supplied input for a single JSON field.  It
 * is a subordinate helper function for the ->decode_report method.
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
 * External public method.
 *
 * This method implements the decoding of an enclave attestation report
 * that has been previously requested.
 *
 * \param this		A pointer to the quoting object which is to
 *			be used for decoding the report.
 *
 * \param report	The object containing the report that is to
 *			be decoded.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool decode_report(CO(SGXquote, this), CO(String, report))

{
	STATE(S);

	_Bool retn = false;

	uint16_t tlv_size;

	struct TLVshort {
		uint8_t type;
		uint8_t version;
		uint16_t size;
	} __attribute__((packed)) *tlv;

	Buffer bufr = NULL;

	String field  = NULL,
	       fregex = NULL;

	Base64 base64 = NULL;


	/* Decode the mandatory information fields. */
	INIT(HurdLib, String, fregex, ERR(goto done));

	INIT(HurdLib, String, S->id, ERR(goto done));
	if ( !_get_field(report, fregex, "id", S->id) )
		ERR(goto done);

	INIT(HurdLib, String, S->timestamp, ERR(goto done));
	if ( !_get_field(report, fregex, "timestamp", S->timestamp) )
		ERR(goto done);

	INIT(HurdLib, String, field, ERR(goto done));
	if ( !_get_field(report, fregex, "isvEnclaveQuoteStatus", field) )
		ERR(goto done);

	for (S->status= 0; Quote_status[S->status] != NULL; ++S->status) {
		if ( strcmp(field->get(field), Quote_status[S->status]) \
		     == 0)
			break;
	}


	/* Decode the quote body. */
	field->reset(field);
	if ( !_get_field(report, fregex, "isvEnclaveQuoteBody", field) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !base64->decode(base64, field, bufr) )
		ERR(goto done);

	memcpy(&S->quote, bufr->get(bufr), sizeof(struct SGX_quote));


	/* Decode the platform information report if available. */
	if ( S->status == SGXquote_status_GROUP_OUT_OF_DATE ||
	     S->status == SGXquote_status_GROUP_REVOKED ) {
		field->reset(field);
		if ( !_get_field(report, fregex, "platformInfoBlob", field) )
			ERR(goto done);

		bufr->reset(bufr);
		if ( !bufr->add_hexstring(bufr, field->get(field)) )
			ERR(goto done);

		tlv = (struct TLVshort *) bufr->get(bufr);
		if ( (tlv->type != 21) || (tlv->version != 2) )
			ERR(goto done);
		tlv_size = ntohs(tlv->size);

		bufr->reset(bufr);
		if ( !bufr->add_hexstring(bufr, \
					  field->get(field) + sizeof(*tlv)*2) )
			ERR(goto done);
		if ( tlv_size != bufr->size(bufr) )
			ERR(goto done);

		memcpy(&S->platform_info, bufr->get(bufr), \
		       sizeof(struct platform_info));
	}
	retn = true;


 done:
	WHACK(field);
	WHACK(fregex);

	WHACK(bufr);
	WHACK(base64);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests access to the
 * target information for the quoting enclave.
 *
 * \param this	A pointer to the object whose quoting enclave
 *		information is to be returned.
 *
 * \return	A pointer to the target structure is returned.  This
 *		may contain all null values if the object has not
 *		been initialized.
 */

static struct SGX_targetinfo * get_qe_targetinfo(CO(SGXquote, this))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_get_qe_targetinfo;
	ocall.instance	= S->instance;

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	S->qe_target_info = *ocall.qe_target_info;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return &S->qe_target_info;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning a pointer
 * to the structure containing the quote information for the attesting
 * enclave.
 *
 * \param this	A pointer to the object whose quote information is to
 *		be returned.
 *
 * \return	A pointer to the quote information structure is returned.
 *		This may contain all null values if the quote has not
 *		been generated.
 */

static struct SGX_quote * get_quoteinfo(CO(SGXquote, this))

{
	STATE(S);

	return &S->quote;
}


/**
 * External public method.
 *
 * This method implements the decoding and print out of an attestation
 * report
 *
 * \param this	A pointer to the object containing the attestation report
 *		to be generated.
 */

static void dump_report(CO(SGXquote, this))

{
	STATE(S);

	uint16_t flags;

	uint32_t gid;

	struct SGX_reportbody *bp;

	struct platform_info *plb;

	struct SGX_psvn *psvnp;

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*POISONED*\n", stdout);
		return;
	}
	if ( S->status == SGXquote_status_UNDEFINED ) {
		fputs("No report available.\n", stdout);
		return;
	}

	fputs("ID:        ", stdout);
	S->id->print(S->id);

	fputs("Timestamp: ", stdout);
	S->timestamp->print(S->timestamp);

	fprintf(stdout, "Status:    %s\n", Quote_status[S->status]);


	fputs("\nQuote:\n", stdout);
	fprintf(stdout, "\tversion:    %u\n", S->quote.version);
	fprintf(stdout, "\tsign_type:  %u\n", S->quote.sign_type);

	memcpy(&gid, S->quote.epid_group_id, sizeof(gid));
	fprintf(stdout, "\tgroup id:   0x%08x\n", gid);

	fprintf(stdout, "\tQE svn:     %u\n", S->quote.qe_svn);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) S->quote.basename, \
			sizeof(S->quote.basename)) )
		ERR(goto done);
	fputs("\tBasename:   ", stdout);
	bufr->print(bufr);

	bp = &S->quote.report_body;
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


	/* Report platform status. */
	fprintf(stdout, "\nPlatform status: %s\n", Quote_status[S->status]);

	if ( !(S->status == SGXquote_status_GROUP_OUT_OF_DATE ||
	       S->status == SGXquote_status_GROUP_REVOKED) )
		goto done;


	/* Output platform information report. */
	fputs("\nPlatform Info Report:\n", stdout);
	plb = &S->platform_info;

	fprintf(stdout, "\tEPID group flags: %u\n", plb->sgx_epid_group_flags);
	if ( plb->sgx_epid_group_flags & 0x1 )
		fputs("\t\tEPID group revoked.\n", stdout);
	if ( plb->sgx_epid_group_flags & 0x2 )
		fputs("\t\tPerformance rekey available.\n", stdout);
	if ( plb->sgx_epid_group_flags & 0x4 )
		fputs("\t\tEPID group out of date.\n", stdout);


	memcpy(&flags, plb->sgx_tcb_evaluation_flags, sizeof(flags));
	flags = ntohs(flags);
	fprintf(stdout, "\n\tTCB evaluation flags: %u\n", flags);
	if ( flags & 0x1 )
		fputs("\t\tCPU svn out of date.\n", stdout);
	if ( flags & 0x2 )
		fputs("\t\tQE enclave out of date.\n", stdout);
	if ( flags & 0x4 )
		fputs("\t\tPCE enclave out of date.\n", stdout);

	memcpy(&flags, plb->pse_evaluation_flags, sizeof(flags));
	flags = ntohs(flags);
	fprintf(stdout, "\n\tPSE evaluation flags: %u\n", flags);

	psvnp = &plb->latest_equivalent_tcb_psvn;
	bufr->reset(bufr);
	if ( !bufr->add(bufr, psvnp->cpu_svn, sizeof(psvnp->cpu_svn)) )
		ERR(goto done);

	fputs("\n\tRecommended platform status:\n", stdout);
	fputs("\t\tCPU svn: ", stdout);
	bufr->print(bufr);

	fprintf(stdout, "\t\tISV svn: %u\n", psvnp->isv_svn);

	fprintf(stdout, "\n\tExtended group id: 0x%x\n", plb->xeid);


 done:
	WHACK(bufr);

	return;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests destruction of
 * the userspace instance of the SGXquote object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXquote, this))

{
	STATE(S);

	struct SGXquote_ocall ocall;


	/* Release implementation object. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));
	ocall.ocall    = SGXquote_whack;
	ocall.instance = S->instance;
	sgxquote_ocall(&ocall);


	/* Destroy resources. */
	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXquote object.
 *
 * \return	A pointer to the initialized SGXquote.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXquote NAAAIM_SGXquote_Init(void)

{
	Origin root;

	SGXquote this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct SGXquote_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXquote);
	retn.state_size   = sizeof(struct NAAAIM_SGXquote_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXquote_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));
	ocall.ocall = SGXquote_init_object;
	if ( sgxquote_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->init = init;

	this->generate_quote  = generate_quote;
	this->generate_report = generate_report;
	this->decode_report   = decode_report;

	this->get_qe_targetinfo = get_qe_targetinfo;
	this->get_quoteinfo	= get_quoteinfo;

	this->dump_report = dump_report;
	this->whack	  = whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
