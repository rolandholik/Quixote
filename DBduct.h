/** \file
 * This file is a companion file to the DBduct.c file.  It implements
 * global definitions for the object which implements an API for
 * managing a connection with a Postgresql database.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_DBduct_HEADER
#define NAAAIM_DBduct_HEADER

/* Include files. */
#include <stddef.h>
#include <stdbool.h>

#include <Origin.h>
#include <Buffer.h>


/* Object type definitions. */
typedef struct NAAAIM_DBduct * DBduct;

typedef struct NAAAIM_DBduct_State * DBduct_State;

/**
 * External DBduct object representation.
 */
struct NAAAIM_DBduct
{
	/* External methods. */
	_Bool (*init_connection)(const DBduct, const char *);
	_Bool (*exec)(const DBduct, const char *);
	int (*query)(const DBduct, const char *);
	char * (*get_element)(const DBduct, int, int);
	void (*print)(const DBduct);
	void (*whack)(const DBduct);

	/* Private state. */
	DBduct_State state;
};


/* DBduct constructor call. */
extern HCLINK DBduct NAAAIM_DBduct_Init(void);
#endif
