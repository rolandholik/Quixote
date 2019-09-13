/** \file
 * This file contains the implementation of an object which is used to
 * manage the Intel quoting enclave.  This enclave is provided as
 * a signed enclave by Intel as part of their runtime distribution.
 *
 * The quoting enclave is used generate platform 'quotes' which can
 * be submitted to Intel for verification.  The quoting enclave has
 * two major roles.  The fist is to verify the integrity of the EPID
 * 'blob' which has been provisioned to the platform.  The second
 * is to generate a platform quote using this 'blob'.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
#define DEVICE	"/dev/isgx"
#define ENCLAVE	"/opt/intel/sgxpsw/aesm/libsgx_qe.signed.so"


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "SRDE.h"
#include "SRDEenclave.h"
#include "SRDEepid.h"
#include "QEenclave.h"


/* Name and location of launch token. */
#define TOKEN_FILE SGX_TOKEN_DIRECTORY"/libsgx_qe.token"


/* Object state extraction macro. */
#define STATE(var) CO(QEenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_QEenclave_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following defines an empty OCALL table for the quoting
 * enclave.
 */
static const struct OCALL_api QE_ocall_table = {
	0,
	{
		NULL
	}
};


/** QEenclave private state information. */
struct NAAAIM_QEenclave_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The enclave object. */
	SRDEenclave enclave;

	/* The buffer containing the EPID. */
	SRDEepid epid;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_QEenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(QEenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_QEenclave_OBJID;


	S->poisoned = false;

	S->enclave = NULL;
	S->epid	   = NULL;
	return;
}


/**
 * External public method.
 *
 * This method is responsible for loading and initializing the
 * quoting enclave.
 *
 * \param this		A pointer to the quoting enclave object
 *			that is to be opened.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the launch token for the quoting
 *			enclave.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool open(CO(QEenclave, this), CO(char *, token))

{
	STATE(S);

	_Bool retn = false;

	const char *token_name = token == NULL ? TOKEN_FILE : token;

	struct SGX_einittoken *einit;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Load the launch token. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token_name);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SRDEenclave, S->enclave, ERR(goto done));

	if ( !S->enclave->open_enclave(S->enclave, DEVICE, ENCLAVE, false) )
		ERR(goto done);

	if ( !S->enclave->create_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->load_enclave(S->enclave) )
		ERR(goto done);

	if ( !S->enclave->init_enclave(S->enclave, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the target information for the
 * quoting enclave so a report can be generated against it.  This
 * method is a direct passthrough call to the underlying object.
 *
 * \param this	A pointer to the QE object for which target
 *		information is to be returned.
 *
 * \param tgt	A pointer to the target information structure which
 *		is to be populated.
 *
 * \return	If an error is encountered while generating the QE
 *		information a false value is returned.  A true value
 *		indicates the object contains valid information about
 *		the quoting enclave.
 */

static void get_target_info(CO(QEenclave, this), struct SGX_targetinfo *tgt)

{
	STATE(S);

	S->enclave->get_target_info(S->enclave, tgt);
	return;
}


/**
 * External public method.
 *
 * This method is responsible for loading and verifying the EPID
 * that has been provisioned to the platform.
 *
 * \param this		A pointer to the quoting enclave object
 *			that is to load the EPID.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the EPID.
 *
 * \return	If an error is encountered while loading the EPID a
 *		false value is returned.  A true value indicates the
 *		EPID has been successfully loaded and verified.
 */

static _Bool load_epid(CO(QEenclave, this), CO(char *, epid_name))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	uint8_t resealed,
		cpusvn[16];

	File epid_file = NULL;

	Buffer b;

	struct {
		uint32_t retn;
		uint8_t *p_blob;
		uint32_t blob_size;
		uint8_t *p_is_resealed;
		uint8_t *cpusvn;
	} ecall0;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Allocate the EPID buffer if this is the first call, otherwise
	 * reset it.
	 */
	INIT(NAAAIM, SRDEepid, S->epid, ERR(goto done));
	if ( !S->epid->load(S->epid, epid_name) )
		ERR(goto done);
	b = S->epid->get_epid(S->epid);

	/* Call slot 0 to verify the blob. */
	memset(&ecall0, '\0', sizeof(ecall0));

	ecall0.p_blob	     = b->get(b);
	ecall0.blob_size     = b->size(b);
	ecall0.p_is_resealed = &resealed;
	ecall0.cpusvn	     = cpusvn;

	if ( !S->enclave->boot_slot(S->enclave, 0, &QE_ocall_table, &ecall0, \
				    &rc) ) {
		fprintf(stderr, "QE slot 0 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall0.retn != 0 ) {
		fprintf(stderr, "QE error: %d\n", ecall0.retn);
		ERR(goto done);
	}

	if ( resealed )
		fputs("EPID blob resealed.\n", stderr);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(epid_file);

	return retn;
}


/**
 * External public method.
 *
 * This method is responsible for generating a platform specific enclave
 * quote.  It is a wrapper around the following enclave ECALL:
 *
 * get_quote
 *
 *
 * Withe the following ECALL signature:
 *        public uint32_t get_quote([size = blob_size, in, out] uint8_t *p_blob,
 *		uint32_t blob_size,
 *		[in] const sgx_report_t *p_report,
 *		sgx_quote_sign_type_t quote_type,
 *		[in] const sgx_spid_t *p_spid,
 *		[in] const sgx_quote_nonce_t *p_nonce,
 *		[user_check] const uint8_t *p_sig_rl,
 *		uint32_t sig_rl_size,
 *		[out] sgx_report_t *qe_report,
 *		[user_check] uint8_t *p_quote,
 *		uint32_t quote_size,
 *		sgx_isv_svn_t pce_isvnsvn);
 *
 * \param this		A pointer to the quoting enclave object which
 *			is to generate the quote.
 *
 * \param ereport	A pointer to the structure containing the enclave
 *			report that is to be attested.
 *
 * \param type		The type of quote that is to be generated.
 *			Either linkable or unlinkable.
 *
 * \param spid		A pointer to an object containing the binary
 *			representation of the service provider identity.
 *
 * \param nonce		A pointer to the object containing the nonce
 *			that is to be used for generating the quote.
 *
 * \param sigrl		A pointer to the object containing the signature
 *			revocation list to be used for the quote.   A
 *			null value indicates that no revocation list is
 *			to be used.
 *
 * \param report	A pointer to the structure that will hold the
 *			report from the quoting enclave.
 *
 * \param quote		A pointer to the object which will hold the
 *			quote.  The object will be this method to
 *			hold the size of the quote generated.
 *
 * \param pce_svn	The security version of the PCE enclave that
 *			is being used.
 *
 * \return	If an error is encountered while generating the quote
 *		a false value is returned.  A true value indicates the
 *		report object holds a valid quote.
 */

static _Bool generate_quote(CO(QEenclave, this), struct SGX_report *ereport, \
			    int type, CO(Buffer, spid), CO(Buffer, nonce),   \
			    CO(Buffer, sigrl), CO(Buffer, quote),	     \
			    uint16_t pce_svn)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	uint32_t n2 = 0;

	size_t size;

	struct SGX_report __attribute__((aligned(512))) qe_report;

	struct {
		uint32_t retn;

		uint8_t *p_blob;
		uint32_t blob_size;
		struct SGX_report *p_report;
		int quote_type;
		uint8_t *spid;
		uint8_t *p_nonce;
		uint8_t *p_sig_rl;
		uint32_t sig_rl_size;
		struct SGX_report *qe_report;
		uint8_t *quote;
		uint32_t quote_size;
		uint16_t pce_isvnsvn;
	} ecall1;

	Buffer b;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call slot 1 to generate the report. */
	memset(&ecall1, '\0', sizeof(ecall1));

	b = S->epid->get_epid(S->epid);
	ecall1.p_blob	 = b->get(b);
	ecall1.blob_size = b->size(b);

	ecall1.p_report	  = ereport;
	ecall1.quote_type = type;

	ecall1.spid    = spid->get(spid);
	ecall1.p_nonce = nonce->get(nonce);

	if ( sigrl != NULL )
		ecall1.sig_rl_size = sigrl->size(sigrl);

	ecall1.qe_report = &qe_report;


	/*
	 * The quote size is calculated as follows:
	 *
	 * quote_length_without_sig + signature_size
	 *
	 * Where:
	 *	quote_length_without_sig: 756
	 *	signature_size: sizeof(EpidSignature) - sizeof(NrProof) +
	 *			sig_rl.n2 * sizeof(NrProof)
	 *
	 *	EpidSignature: 520
	 *	NrProof: 160
	 */
	ecall1.quote_size = 756 + 520 - 160;
	if ( ecall1.sig_rl_size > 0 ) {
		ecall1.quote_size += n2*160;
		fputs("SIGRL not fully supported.\n", stderr);
		ERR(goto done);
	}

	size = ecall1.quote_size;
	while ( size ) {
		quote->add(quote, (unsigned char *) "\0", 1);
		--size;
	}
	if ( quote->poisoned(quote) )
		ERR(goto done);
	ecall1.quote = quote->get(quote);

	ecall1.pce_isvnsvn = pce_svn;


	/* Call ECALL1 to generate the quote. */
	if ( !S->enclave->boot_slot(S->enclave, 1, &QE_ocall_table, &ecall1, \
				    &rc) ) {
		fprintf(stderr, "QE slot 1 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall1.retn != 0 ) {
		fprintf(stderr, "QE error: %d\n", ecall1.retn);
		ERR(goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for the QEenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(QEenclave, this))

{
	STATE(S);


	WHACK(S->enclave);
	WHACK(S->epid);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a QEenclave object.
 *
 * \return	A pointer to the initialized QEenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern QEenclave NAAAIM_QEenclave_Init(void)

{
	Origin root;

	QEenclave this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_QEenclave);
	retn.state_size   = sizeof(struct NAAAIM_QEenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_QEenclave_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->open = open;

	this->get_target_info = get_target_info;

	this->load_epid	     = load_epid;
	this->generate_quote = generate_quote;

	this->whack = whack;

	return this;
}
