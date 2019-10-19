/** \file
* This file contains the API definitions for an object that manages
* and manipulates X.509 certificates.
*/

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_X509cert_HEADER
#define NAAAIM_X509cert_HEADER


/* Object type definitions. */
typedef struct NAAAIM_X509cert * X509cert;

typedef struct NAAAIM_X509cert_State * X509cert_State;

/**
 * External X509cert object representation.
 */
struct NAAAIM_X509cert
{
	/* External methods. */
	_Bool (*add)(const X509cert, const Buffer);
	_Bool (*verify)(const X509cert, const Buffer, _Bool *);

	void (*time_check)(const X509cert, const _Bool);

	void (*whack)(const X509cert);

	/* Private state. */
	X509cert_State state;
};


/* X509cert constructor call. */
extern HCLINK X509cert NAAAIM_X509cert_Init(void);
#endif
