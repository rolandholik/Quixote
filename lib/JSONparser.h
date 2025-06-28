/** \file
 * This file contains the API definition for an object that implements
 * the parsing of JSON documents.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_JSONparser_HEADER
#define NAAAIM_JSONparser_HEADER


/* Object type definitions. */
typedef struct NAAAIM_JSONparser * JSONparser;

typedef struct NAAAIM_JSONparser_State * JSONparser_State;

/**
 * External ESclient object representation.
 */
struct NAAAIM_JSONparser
{
	/* External methods. */
	_Bool (*parse_Buffer)(const JSONparser, const Buffer);
	_Bool (*select_object)(const JSONparser, const char *);

	_Bool (*select_integer)(const JSONparser, const char *);
	_Bool (*get_integer)(const JSONparser, int *);

	_Bool (*select_array)(const JSONparser, const char *);
	_Bool (*get_array_size)(const JSONparser, int *);
	_Bool (*select_array_object)(const JSONparser, int);

	_Bool (*select_string)(const JSONparser, const char *);
	_Bool (*get_String)(const JSONparser, const String);

	_Bool (*get_object_String)(const JSONparser, const String);

	void (*print)(const JSONparser);
	void (*clear)(const JSONparser);
	void (*reset)(const JSONparser);
	void (*whack)(const JSONparser);


	/* Private state. */
	JSONparser_State state;
};


/* ESclient constructor call. */
extern HCLINK JSONparser NAAAIM_JSONparser_Init(void);

#endif
