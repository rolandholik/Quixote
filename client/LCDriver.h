/** \file
 * This file contains the external definitions for an object which
 * implements control of the Ituner LCD display.
 */

/**************************************************************************
 * (C)Copyright 2011, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_LCDriver_HEADER
#define NAAAIM_LCDriver_HEADER


/* Object type definitions. */
typedef struct NAAAIM_LCDriver * LCDriver;

typedef struct NAAAIM_LCDriver_State * LCDriver_State;

typedef enum {
	LCDriver_key_error=0,
	LCDriver_key_release,
	LCDriver_key_F1
} LCDriver_key;

/**
 * External LCDriver object representation.
 */
struct NAAAIM_LCDriver
{
	/* External methods. */
	void (*on)(const LCDriver);
	void (*off)(const LCDriver);

	void (*clear)(const LCDriver);
	void (*text)(const LCDriver, unsigned int, unsigned int, const char *);
	void (*center)(const LCDriver, unsigned int, const char *);

	LCDriver_key (*read_key)(const LCDriver);
	
	void (*whack)(const LCDriver);

	/* Private state. */
	LCDriver_State state;
};


/* LCDriver constructor call. */
extern LCDriver NAAAIM_LCDriver_Init(void);

#endif
