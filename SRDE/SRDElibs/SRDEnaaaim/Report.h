/** \file
 * This file contains the API definitions for an object that
 * implements that implements enclave report generation and verification.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Report_HEADER
#define NAAAIM_Report_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Report * Report;

typedef struct NAAAIM_Report_State * Report_State;

/**
 * External Report object representation.
 */
struct NAAAIM_Report
{
	/* External methods. */
	_Bool (*generate_report)(const Report, struct SGX_targetinfo *, \
				 const Buffer, struct SGX_report *);
	_Bool (*validate_report)(const Report, const struct SGX_report *, \
				 _Bool *status);

	_Bool (*get_targetinfo)(const Report, struct SGX_targetinfo *);
	_Bool (*get_report)(const Report, struct SGX_report *);

	void (*whack)(const Report);

	/* Private state. */
	Report_State state;
};


/* Report constructor call. */
extern HCLINK Report NAAAIM_Report_Init(void);

#endif
