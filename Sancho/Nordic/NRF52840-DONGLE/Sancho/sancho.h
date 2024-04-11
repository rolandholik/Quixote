/** \file
 * This file contains generic configuration definitions for the
 * Sancho implementation.
 */

/**************************************************************************
 * (C)Copyright 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* LED indicators. */
#define ACTIVE_LED	0
#define FAULT_LED	1
#define CONNECTION_LED	2
#define ACTIVITY_LED	3

/* External function definitions. */
extern void sancho_interpreter(const TTYduct);
