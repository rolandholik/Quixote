/** \file
 * This file contains definitions for an object which implements the
 * generation and verification of an enclave quote.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

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

	struct SGX_targetinfo * (*get_qe_targetinfo)(const SGXquote);
	void (*whack)(const SGXquote);


	/* Private state. */
	SGXquote_State state;
};


/* Sgxmetadata constructor call. */
extern SGXquote NAAAIM_SGXquote_Init(void);

/* Definition for entry point for SGXquote SGX manager. */
extern int SGXquote_sgxmgr(struct SGXquote_ocall *ocp);

#endif
