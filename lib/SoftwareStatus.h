/** \file
 * This file contains the object definitions for the SoftwareStatus
 * object which implements accessing the measurements of an application
 * environment.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SoftwareStatus_HEADER
#define NAAAIM_SoftwareStatus_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SoftwareStatus * SoftwareStatus;

typedef struct NAAAIM_SoftwareStatus_State * SoftwareStatus_State;

/**
 * External SoftwareStatus object representation.
 */
struct NAAAIM_SoftwareStatus
{
	/* External methods. */
	_Bool (*open)(const SoftwareStatus);
	_Bool (*measure)(const SoftwareStatus);

	Buffer (*get_template_hash)(const SoftwareStatus);
	Buffer (*get_file_hash)(const SoftwareStatus);

	void (*whack)(const SoftwareStatus);

	/* Private state. */
	SoftwareStatus_State state;
};


/* SoftwareStatus constructor call. */
extern SoftwareStatus NAAAIM_SoftwareStatus_Init(void);

#endif
