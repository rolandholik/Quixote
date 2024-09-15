/** \file
 * This file contains the header definitions for the TSEMworkload object.
 * This object implements the functionality needed to run a workload
 * in a security modeling namespace.
 */

/**************************************************************************
 * Copyright (c) 2024, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_TSEMworkload_HEADER
#define NAAAIM_TSEMworkload_HEADER

typedef struct NAAAIM_TSEMworkload * TSEMworkload;

typedef struct NAAAIM_TSEMworkload_State * TSEMworkload_State;

/**
 * External TSEMworkload object representation.
 */
struct NAAAIM_TSEMworkload
{
	/* External methods. */
	_Bool (*configure_export)(const TSEMworkload, const char *,	   \
				  const char *, const char *, const _Bool);

	void (*set_debug)(const TSEMworkload, FILE *);
	void (*set_execute_mode)(const TSEMworkload, int argc, char *argv[]);
	_Bool (*set_container_mode)(const TSEMworkload, const char *, \
				    const char *);

	_Bool (*run_monitor)(const TSEMworkload, pid_t, const LocalDuct, \
			     _Bool (*event_Handler)(TSEMevent));
	_Bool (*run_workload)(const TSEMworkload);

	void (*whack)(const TSEMworkload);

	/* Private state. */
	TSEMworkload_State state;
};


/* TSEMcontrol constructor call. */
extern TSEMworkload NAAAIM_TSEMworkload_Init(void);

#endif
