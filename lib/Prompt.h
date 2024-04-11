/** \file
 * This file implements the API definitions for an object used to
 * prompt the user for a password with optional verification.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Prompt_HEADER
#define NAAAIM_Prompt_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Prompt * Prompt;

typedef struct NAAAIM_Prompt_State * Prompt_State;

/**
 * External Prompt object representation.
 */
struct NAAAIM_Prompt
{
	/* External methods. */
	_Bool (*get)(const Prompt, const String, const String, const int, \
		     const String, _Bool *);

	void (*whack)(const Prompt);

	/* Private state. */
	Prompt_State state;
};


/* Prompt constructor call. */
extern HCLINK Prompt NAAAIM_Prompt_Init(void);
#endif
