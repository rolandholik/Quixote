/** \file
 * This file contains definitions for an object which implements
 * management of the quoting enclave.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_QEenclave_HEADER
#define NAAAIM_QEenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_QEenclave * QEenclave;

typedef struct NAAAIM_QEenclave_State * QEenclave_State;

/**
 * External QEenclave object representation.
 */
struct NAAAIM_QEenclave
{
	/* External methods. */
	_Bool (*open)(const QEenclave, const char *);

	_Bool (*load_epid)(const QEenclave, const char *);

	void (*whack)(const QEenclave);


	/* Private state. */
	QEenclave_State state;
};


/* Sgxmetadata constructor call. */
extern QEenclave NAAAIM_QEenclave_Init(void);

#endif
