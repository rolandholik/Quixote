/** \file
 * This file contains the header and API definitions for an object
 * that implements parsing of a TSEM security state event description.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_TSEMparser_HEADER
#define NAAAIM_TSEMparser_HEADER


/* Object type definitions. */
typedef struct NAAAIM_TSEMparser * TSEMparser;

typedef struct NAAAIM_TSEMparser_State * TSEMparser_State;

/**
 * External TSEMparser object representation.
 */
struct NAAAIM_TSEMparser
{
	/* External methods. */
	_Bool (*extract_field)(const TSEMparser, const String, const char *);

	_Bool (*get_field)(const TSEMparser, const String);
	_Bool (*get_integer)(const TSEMparser, const char *, long long int *);
	_Bool (*get_text)(const TSEMparser, const char *, const String);

	_Bool (*has_key)(const TSEMparser, const char *);

	void (*print)(const TSEMparser);
	void (*reset)(const TSEMparser);
	void (*whack)(const TSEMparser);

	/* Private state. */
	TSEMparser_State state;
};


/* Exchange event constructor call. */
extern HCLINK TSEMparser NAAAIM_TSEMparser_Init(void);
#endif
