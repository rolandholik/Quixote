/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage and manipulate a subject identity in the
 * IDfusion iso-identity behavioral modeling system.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Subject_HEADER
#define NAAAIM_Subject_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Subject * Subject;

typedef struct NAAAIM_Subject_State * Subject_State;

/**
 * External Actor object representation.
 */
struct NAAAIM_Subject
{
	/* External methods. */
#if 0
	void (*set_identity_elements)(const Actor, uint32_t, uint32_t,	      \
				      uint32_t, uint32_t, uint32_t, uint32_t, \
				      uint32_t, uint32_t, uint64_t);
#endif
	_Bool (*parse)(const Subject, const String);
	_Bool (*measure)(const Subject);
	_Bool (*get_measurement)(const Subject, const Buffer);

	_Bool (*format)(const Subject, const String);

	void (*reset)(const Subject);
	void (*dump)(const Subject);
	void (*whack)(const Subject);

	/* Private state. */
	Subject_State state;
};


/* Actor constructor call. */
extern HCLINK Subject NAAAIM_Subject_Init(void);
#endif
