/** \file
 * This file contains the header definitions for the TSEMcontrol object
 * that implements the ability to control the Trusted Security Event
 * Modeling system in the Linux kernel.
 */

/**************************************************************************
 * Copyright (c) 2022, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_TSEMcontrol_HEADER
#define NAAAIM_TSEMcontrol_HEADER

/**
 * Enumerations for setting up a TSEM namespace.
 */
enum TSEMcontrol_ns_config {
	TSEMcontrol_TYPE_INTERNAL = 1,
	TSEMcontrol_TYPE_EXTERNAL,
	TSEMcontrol_TYPE_EXPORT,
	TSEMcontrol_INIT_NS,
	TSEMcontrol_CURRENT_NS
};

/* Object type definitions. */
typedef struct NAAAIM_TSEMcontrol * TSEMcontrol;

typedef struct NAAAIM_TSEMcontrol_State * TSEMcontrol_State;

/**
 * External TSEMcontrol object representation.
 */
struct NAAAIM_TSEMcontrol
{
	/* External methods. */
	_Bool (*create_ns)(const TSEMcontrol,
			   const enum TSEMcontrol_ns_config, char *, \
			   const enum TSEMcontrol_ns_config,	     \
			   const unsigned int);
	_Bool (*enforce)(const TSEMcontrol);
	_Bool (*external)(const TSEMcontrol);
	_Bool (*internal)(const TSEMcontrol);
	_Bool (*seal)(const TSEMcontrol);

	_Bool (*discipline)(const TSEMcontrol, pid_t);
	_Bool (*release)(const TSEMcontrol, pid_t);

	_Bool (*set_base)(const TSEMcontrol, const Buffer);
	_Bool (*add_state)(const TSEMcontrol, const Buffer);
	_Bool (*pseudonym)(const TSEMcontrol, const Buffer);

	_Bool (*id)(const TSEMcontrol, uint64_t *);

	_Bool (*generate_key)(const TSEMcontrol);
	void (*whack)(const TSEMcontrol);

	/* Private state. */
	TSEMcontrol_State state;
};


/* TSEMcontrol constructor call. */
extern TSEMcontrol NAAAIM_TSEMcontrol_Init(void);

#endif
