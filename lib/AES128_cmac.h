/** \file
 * This file contains the API definitions for an object that
 * implements the AES128 based cipher block message authentication
 * code.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_AES128_cmac_HEADER
#define NAAAIM_AES128_cmac_HEADER


/* Object type definitions. */
typedef struct NAAAIM_AES128_cmac * AES128_cmac;

typedef struct NAAAIM_AES128_cmac_State * AES128_cmac_State;

/**
 * External AES128_cmac object representation.
 */
struct NAAAIM_AES128_cmac
{
	/* External methods. */
	_Bool (*set_key)(const AES128_cmac, const Buffer);

	_Bool (*add)(const AES128_cmac, const uint8_t *, const size_t);

	_Bool (*compute)(const AES128_cmac);
	Buffer (*get_Buffer)(const AES128_cmac);

	void (*whack)(const AES128_cmac);

	/* Private state. */
	AES128_cmac_State state;
};


/* AES128_cmac constructor call. */
extern HCLINK AES128_cmac NAAAIM_AES128_cmac_Init(void);

#endif
