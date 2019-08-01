/** \file
 * This file contains the implementation of an object which is used to
 * manage the Intel PCE enclave.  This enclave is provided as
 * a signed enclave by Intel as part of their runtime distribution.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define DEVICE	"/dev/isgx"
#define ENCLAVE	"/opt/intel/sgxpsw/aesm/libsgx_pce.signed.so"

#define XID_SIZE 8
#define MAX_HEADER_SIZE 6


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
#include "SHA256.h"
#include "RandomBuffer.h"
#include "SRDE.h"
#include "SRDEenclave.h"
#include "PCEenclave.h"
#include "SGXmessage.h"


/* Name and location of launch token. */
#define TOKEN_FILE SGX_TOKEN_DIRECTORY"/libsgx_pce.token"


/* Object state extraction macro. */
#define STATE(var) CO(PCEenclave_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PCEenclave_OBJID)
#error Object identifier not defined.
#endif


/**
 * The following defines an empty OCALL table for the provisioning
 * enclave.
 */
static const struct {
	size_t nr_ocall;
	void *table[1];
} PCE_ocall_table = { 0, {NULL}};


/**
 * The following structure defines the PCE information structure.
 */
struct PCEinfo {
	uint16_t pce_isvn;
	uint16_t pce_id;
};


/** PCEenclave private state information. */
struct NAAAIM_PCEenclave_State
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

	/* The encrypted output from the PCE enclave. */
	uint8_t ppid[384];

	/* The signature scheme. */
	uint8_t signature;

	struct PCEinfo info;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_PCEenclave_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(PCEenclave_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PCEenclave_OBJID;


	S->poisoned = false;
	S->enclave  = NULL;

	return;
}


/**
 * External public method.
 *
 * This method loads and initializes the PCE enclave.
 *
 * \param this		A pointer to the PCE enclave object which
 *			is to be opened.
 *
 * \param token		A pointer to a null terminated character
 *			buffer containing the name of the file
 *			containing the launch token computed for
 *			the enclave.
 *
 * \return	If an error is encountered while opening the enclave a
 *		false value is returned.   A true value indicates the
 *		enclave has been successfully initialized.
 */

static _Bool open(CO(PCEenclave, this), CO(char *, token))

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
 * This method implements returning the target information for
 * the PCE enclave so a report can be generated against it.
 *
 * \param this	A pointer to the PCE object for which target
 *		information is to be returned.
 *
 * \param tgt	A pointer to the target information structure which
 *		is to be populated.
 *
 * \return	If an error is encountered while generating the PCE
 *		information a false value is returned.  A true value
 *		indicates the object contains valid information about
 *		the PCE enclave.
 */

static void get_target_info(CO(PCEenclave, this), struct SGX_targetinfo *tgt)

{
	STATE(S);

	struct SGX_secs secs;


	/* Get the enclave control structure information. */
	S->enclave->get_secs(S->enclave, &secs);


	/* Populate the target information. */
	memset(tgt, '\0', sizeof(struct SGX_targetinfo));

	tgt->miscselect = secs.miscselect;
	memcpy(tgt->mrenclave.m, secs.mrenclave, sizeof(secs.mrenclave));
	memcpy(&tgt->attributes, &secs.attributes, sizeof(tgt->attributes));


	return;
}


/**
 * External public method.
 *
 * This method implements a wrapper for calling the following ECALL:
 *
 * get_pc_info
 *
 * Withe the following ECALL signature:
 *
 * public uint32_t get_pc_info([in] const sgx_report_t *report,
 *                             [in, size=key_size] const uint8_t *public_key,
 * 			       uint32_t key_size,
 *                             uint8_t crypto_suite,
 *                             [out, size=encrypted_ppid_buf_size] uint8_t *encrypted_ppid,
 *			       uint32_t encrypted_ppid_buf_size,
 *                             [out] uint32_t *encrypted_ppid_out_size,
 *			       [out] pce_info_t *pce_info,
 *                             [out] uint8_t *signature_scheme);
 *
 * \param this	A pointer to the PCE object which information is
 *		to be generated for.
 *
 * \param pek	An untyped byte pointer to the PEK object which is to
 *		be passed into the ECALL.
 *
 * \return	If an error is encountered while generating the PCE
 *		information a false value is returned.  A true value
 *		indicates the object contains valid information about
 *		the PCE enclave.
 */

static _Bool get_info(CO(PCEenclave, this), struct SGX_pek *pekp, \
		      struct SGX_report *pek_report)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	uint32_t outsize;

	struct {
		uint32_t retn;
		struct SGX_report *report;
		uint8_t *public_key;
		uint32_t key_size;
		uint8_t crypto_suite;
		uint8_t *encrypted_ppid;
		uint32_t encrypted_ppid_buf_size;
		uint32_t *encrypted_ppid_out_size;
		struct PCEinfo *pce_info;
		uint8_t *signature_scheme;
	} ecall0;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/*
	 * Call slot 0 to obtain PCE information
	 *
	 * The value of zero for crypto_suite is ALG_RSA_OAEP_2048.  It
	 * is the only value currently defined for SGX.
	 */
	ecall0.report = pek_report;

	ecall0.public_key   = (uint8_t *) pekp;
	ecall0.key_size	    = sizeof(pekp->n) + sizeof(pekp->e);
	ecall0.crypto_suite = 1;

	ecall0.encrypted_ppid	       = S->ppid;
	ecall0.encrypted_ppid_buf_size = sizeof(S->ppid);
	ecall0.encrypted_ppid_out_size = &outsize;

	ecall0.pce_info = &S->info;
	ecall0.signature_scheme = &S->signature;

	if ( !S->enclave->boot_slot(S->enclave, 0, &PCE_ocall_table, &ecall0, \
				    &rc) ) {
		fprintf(stderr, "PCE slot 0 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall0.retn != 0 ) {
		fprintf(stderr, "PCE error: %d\n", ecall0.retn);
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
 * This method implements a wrapper for calling the following ECALL:
 *
 * certify_enclave
 *
 * With the following ECALL signature:
 *
 * public uint32_t certify_enclave([in]const psvn_t *cert_psvn,
 *	[in]const sgx_report_t *report,
 *	[out, size=signature_buf_size] uint8_t *signature,
 *	uint32_t signature_buf_size,
 *	[out] uint32_t *signature_out_size);
 *
 * This enclave call signs the report in message 3 generated by the
 * provisioning enclave.
 *
 * \param this		A pointer to the PCE object which is certifying
 *			the message report.
 *
 * \param report	A pointer to the report that is to be signed.
 *
 * \param version	A pointer to the structure containing the
 *			platform version information.
 *
 * \param signature	The object which the signature will be loaded
 *			into.
 *
 * \return	If an error is encountered while signing the report
 *		a false value is returned.  A true value indicates
 *		a valid signature is in the output object.
 */

static _Bool certify_enclave(CO(PCEenclave, this), struct SGX_report *report, \
			     struct SGX_platform_info *version,		      \
			     CO(Buffer, signature))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	uint8_t sigbufr[64];

	uint32_t sigsize;

	struct psvn {
		uint8_t cpu_svn[16];
		uint16_t isv_svn;
	} __attribute__((packed)) psvn;

	struct {
		uint32_t retn;

		struct psvn *cert_psvn;
		struct SGX_report *report;
		uint8_t *signature;
		uint32_t signature_buf_size;
		uint32_t *signature_out_size;
	} ecall1;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( signature->poisoned(signature) )
		ERR(goto done);


	/* Populate the platform information structure. */
	psvn.isv_svn = version->pce_svn;
	memcpy(psvn.cpu_svn, version->cpu_svn, sizeof(version->cpu_svn));


	/* Setup and call slot 1. */
	memset(&ecall1, '\0', sizeof(ecall1));

	ecall1.cert_psvn	  = &psvn;
	ecall1.report		  = report;
	ecall1.signature	  = sigbufr;
	ecall1.signature_buf_size = sizeof(sigbufr);
	ecall1.signature_out_size = &sigsize;

	if ( !S->enclave->boot_slot(S->enclave, 1, &PCE_ocall_table, &ecall1, \
				    &rc) ) {
		fprintf(stderr, "PCE slot 1 call error: %d\n", rc);
		ERR(goto done);
	}
	if ( ecall1.retn != 0 ) {
		fprintf(stderr, "PCE error: %d\n", ecall1.retn);
		ERR(goto done);
	}

	if ( sizeof(sigbufr) != sigsize )
		ERR(goto done);
	if ( !signature->add(signature, sigbufr, sizeof(sigbufr)) )
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
 * This method implements an accessor method for returning the PPID
 * blob generated by the ->get_info method.
 *
 * \param this	A pointer to the PCE object for which the PPID is
 *		to be returned.
 *
 * \param ppid	The object which the buffer is to be loaded into.
 *
 * \return	If an error is encountered while accessing the PPID
 *		information a false value is returned.  A true value
 *		indicates the object contains a valid PPID structure.
 */

static _Bool get_ppid(CO(PCEenclave, this), CO(Buffer, ppid))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( ppid->poisoned(ppid) )
		ERR(goto done);

	/* Load the PPID into the supplied object. */
	if ( !ppid->add(ppid, S->ppid, sizeof(S->ppid)) )
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
 * This method implements an accessor method for returning the PCE
 * version information.
 *
 * \param this	A pointer to the PCE object whose version information
 *		is to be returned.
 *
 * \param svn	A pointer to the location where the enclave version
 *		will be copied.
 *
 * \param id	A pointer to the location where the enclave id will
 *		be copied.
 *
 * \return	No return value is defined.
 */

static void get_version(CO(PCEenclave, this), uint16_t *svn, uint16_t *id)

{
	STATE(S);


	*svn = S->info.pce_isvn;
	*id  = S->info.pce_id;

	return;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning the platform
 * security information for the PCE enclave.
 *
 * \param this	A pointer to the PCE object whose security version
 *		information is to be returned.
 *
 * \param psvn	A pointer to the structure which will be populated with
 *		the platform security information.
 *
 * \return	No return value is defined.
 */

static void get_psvn(CO(PCEenclave, this), struct SGX_psvn *psvn)

{
	STATE(S);

	S->enclave->get_psvn(S->enclave, psvn);
	return;
}


/**
 * External public method.
 *
 * This method implements a method for dumping the current status of
 * the PCE object for diagnostic purposes.
 *
 * \param this	A pointer to the object whose status is to be
 *		dumped.
 */

static void dump(CO(PCEenclave, this))

{
	STATE(S);

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, S->ppid, sizeof(S->ppid)) )
		goto done;

	fputs("PPID:\n", stdout);
	bufr->print(bufr);

	fputs("Enclave info:\n", stdout);
	fprintf(stdout, "\tsvn: %u\n", S->info.pce_isvn);
	fprintf(stdout, "\tid:  %u\n", S->info.pce_id);

	fprintf(stdout, "\nSignature scheme: %u\n", S->signature);


 done:
	WHACK(bufr);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for the PCEenclave object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(PCEenclave, this))

{
	STATE(S);


	WHACK(S->enclave);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a PCEenclave object.
 *
 * \return	A pointer to the initialized PCEenclave.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PCEenclave NAAAIM_PCEenclave_Init(void)

{
	Origin root;

	PCEenclave this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PCEenclave);
	retn.state_size   = sizeof(struct NAAAIM_PCEenclave_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PCEenclave_OBJID, &retn) )
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

	this->get_info	  = get_info;
	this->get_ppid	  = get_ppid;
	this->get_version = get_version;
	this->get_psvn	  = get_psvn;

	this->certify_enclave = certify_enclave;

	this->dump  = dump;
	this->whack = whack;

	return this;
}
