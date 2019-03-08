/** \file
 * This file contains definitions for an object which implements the
 * generation and verification of an enclave quote.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXquote_HEADER
#define NAAAIM_SGXquote_HEADER


/**
 * Enumeration type which defines the method type whose userspace
 * implementation is being requested.
 */
enum SGXquote_ocalls {
	SGXquote_init_object,

	SGXquote_init,
	SGXquote_generate_quote,
	SGXquote_generate_report,

	SGXquote_get_qe_targetinfo,

	SGXquote_whack,

	SGXquote_END
};


/**
 * Structure which marshalls the data for the call into and out of
 * the Duct manager.
 */
struct SGXquote_ocall {
	_Bool retn;
	enum SGXquote_ocalls ocall;
	unsigned int instance;

	char *quote_token;
	char *pce_token;
	char *epid_blob;

	struct SGX_targetinfo *qe_target_info;
	struct SGX_report report;

	unsigned char spid[16];
	unsigned char nonce[16];

	size_t bufr_size;
	unsigned char *bufr;
	unsigned char arena[];
};


/**
 * Enumeration type which defines the status of the remote enclave.
 */
enum SGXquote_status {
	SGXquote_status_OK=0,
	SGXquote_status_SIGNATURE_INVALID,
	SGXquote_status_GROUP_REVOKED,
	SGXquote_status_SIGNATURE_REVOKED,
	SGXquote_status_KEY_REVOKD,
	SGXquote_status_SIGRL_VERSION_MISMATCH,
	SGXquote_status_GROUP_OUT_OF_DATE,
	SGXquote_status_UNDEFINED
};


/* Object type definitions. */
typedef struct NAAAIM_SGXquote * SGXquote;

typedef struct NAAAIM_SGXquote_State * SGXquote_State;

/**
 * External SGXquote object representation.
 */
struct NAAAIM_SGXquote
{
	/* External methods. */
	_Bool (*init)(const SGXquote, const char *, const char *, \
		      const char *);
	_Bool (*generate_quote)(const SGXquote, struct SGX_report *report, \
				const Buffer, const Buffer, const Buffer);
	_Bool (*generate_report)(const SGXquote, const Buffer, const String);
	_Bool (*decode_report)(const SGXquote, const String);

	struct SGX_targetinfo * (*get_qe_targetinfo)(const SGXquote);
	struct SGX_quote * (*get_quoteinfo)(const SGXquote);

	void (*dump_report)(const SGXquote);
	void (*whack)(const SGXquote);


	/* Private state. */
	SGXquote_State state;
};


/* Sgxmetadata constructor call. */
extern SGXquote NAAAIM_SGXquote_Init(void);

/* Definition for entry point for SGXquote SGX manager. */
extern int SGXquote_sgxmgr(struct SGXquote_ocall *ocp);

#endif
