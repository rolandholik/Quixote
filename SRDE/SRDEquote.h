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

#ifndef NAAAIM_SRDEquote_HEADER
#define NAAAIM_SRDEquote_HEADER


/**
 * Enumeration type which defines the method type whose userspace
 * implementation is being requested.
 */
enum SRDEquote_ocalls {
	SRDEquote_init_object,

	SRDEquote_init,
	SRDEquote_generate_quote,
	SRDEquote_generate_report,

	SRDEquote_get_qe_targetinfo,

	SRDEquote_whack,

	SRDEquote_END
};


/**
 * Structure which marshalls the data for the call into and out of
 * the Duct manager.
 */
struct SRDEquote_ocall {
	_Bool retn;
	enum SRDEquote_ocalls ocall;
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
enum SRDEquote_status {
	SRDEquote_status_OK=0,
	SRDEquote_status_SIGNATURE_INVALID,
	SRDEquote_status_GROUP_REVOKED,
	SRDEquote_status_SIGNATURE_REVOKED,
	SRDEquote_status_KEY_REVOKD,
	SRDEquote_status_SIGRL_VERSION_MISMATCH,
	SRDEquote_status_GROUP_OUT_OF_DATE,
	SRDEquote_status_CONFIGURATION_NEEDED,
	SRDEquote_status_UNDEFINED
};


/* Object type definitions. */
typedef struct NAAAIM_SRDEquote * SRDEquote;

typedef struct NAAAIM_SRDEquote_State * SRDEquote_State;

/**
 * External SRDEquote object representation.
 */
struct NAAAIM_SRDEquote
{
	/* External methods. */
	_Bool (*init)(const SRDEquote, const char *, const char *, \
		      const char *);
	_Bool (*generate_quote)(const SRDEquote, struct SGX_report *report, \
				const Buffer, const Buffer, const Buffer);
	_Bool (*generate_report)(const SRDEquote, const Buffer, const String);
	_Bool (*decode_report)(const SRDEquote, const String);
	_Bool (*validate_report)(const SRDEquote, _Bool *);

	struct SGX_targetinfo * (*get_qe_targetinfo)(const SRDEquote);
	struct SRDE_quote * (*get_quoteinfo)(const SRDEquote);

	void (*dump_report)(const SRDEquote);
	void (*whack)(const SRDEquote);


	/* Private state. */
	SRDEquote_State state;
};


/* Sgxmetadata constructor call. */
extern SRDEquote NAAAIM_SRDEquote_Init(void);

/* Definition for entry point for SRDEquote SGX manager. */
extern HCLINK int SRDEquote_mgr(struct SRDEquote_ocall *ocp);
#endif
