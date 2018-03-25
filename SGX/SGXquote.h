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

#endif
