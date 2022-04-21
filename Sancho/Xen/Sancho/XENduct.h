/** \file
 * This file contains the header definitions for the XENduct object
 * which implements a packet based interface for I/O between Xen
 * domains.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#ifndef NAAAIM_XENduct_HEADER
#define NAAAIM_XENduct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_XENduct * XENduct;

typedef struct NAAAIM_XENduct_State * XENduct_State;

/**
 * External LocalDuct object representation.
 */
struct NAAAIM_XENduct
{
	/* External methods. */
	_Bool (*init_device)(const XENduct, const char *);
	_Bool (*accept_connection)(const XENduct);

	_Bool (*send_Buffer)(const XENduct, const Buffer);
	_Bool (*receive_Buffer)(const XENduct, const Buffer);

	_Bool (*eof)(const XENduct);
	void (*reset)(const XENduct);
	void (*whack)(const XENduct);

	/* Private state. */
	XENduct_State state;
};


/* LocalDuct constructor call. */
extern HCLINK XENduct NAAAIM_XENduct_Init(void);
#endif
