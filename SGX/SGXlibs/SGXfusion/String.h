/** \file
 * This file contains API definitions for the String object.  This object
 * implements a null-terminated C character buffer which can be either
 * fixed or dynamic in size.
 *
 * This file should be inclujded by any application which creates or uses
 * this object.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef HurdLib_String_HEADER
#define HurdLib_String_HEADER


/* Object type definitions. */
typedef struct HurdLib_String * String;

typedef struct HurdLib_String_State * String_State;

/**
 * External String object representation.
 */
struct HurdLib_String
{
	/* External methods. */
	_Bool (*add)(const String, char const *);
	char * (*get)(const String);
	size_t (*size)(const String);
	void (*print)(const String);
	_Bool (*poisoned)(const String);
	void (*reset)(const String);
	void (*whack)(const String);

	/* Private state. */
	String_State state;
};


/* String constructor calls. */
extern String HurdLib_String_Init(void);
extern String HurdLib_String_Init_cstr(const char *);

#endif
