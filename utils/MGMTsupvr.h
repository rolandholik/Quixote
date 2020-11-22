/** \file
 * This file contains the method and API definitions for an object
 * which implements management of a token which authorizes and
 * controls processing of the platform specific configuration.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_MGMTsupvr_HEADER
#define NAAAIM_MGMTsupvr_HEADER


/* Object type definitions. */
typedef struct NAAAIM_MGMTsupvr * MGMTsupvr;

typedef struct NAAAIM_MGMTsupvr_State * MGMTsupvr_State;


/**
 * External MGMTsupvr object representation.
 */
struct NAAAIM_MGMTsupvr
{
	/* External methods. */
	_Bool (*load_key)(const MGMTsupvr, const char *, const char **, \
			  const char *);
	_Bool (*write_key)(const MGMTsupvr, const char *, const char **, \
			   const char *);

	_Bool (*set_iv_key)(const MGMTsupvr, const Buffer, const Buffer);

	void (*dump)(const MGMTsupvr);

	_Bool (*poisoned)(const MGMTsupvr);
	void (*whack)(const MGMTsupvr);

	/* Private state. */
	MGMTsupvr_State state;
};


/* MGMTsupvr constructor call. */
extern HCLINK MGMTsupvr NAAAIM_MGMTsupvr_Init(void);
#endif
