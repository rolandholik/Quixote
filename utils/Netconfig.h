/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_Netconfig_HEADER
#define NAAAIM_Netconfig_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Netconfig * Netconfig;

typedef struct NAAAIM_Netconfig_State * Netconfig_State;

/**
 * External Netconfig object representation.
 */
struct NAAAIM_Netconfig
{
	/* External methods. */
	_Bool (*set_address)(const Netconfig, char const *, char const *, \
			     char const *);
	_Bool (*get_address)(const Netconfig, char const *, struct in_addr *, \
			     struct in_addr *);
	_Bool (*set_route)(const Netconfig, char const *, char const *, \
			   char const *);
	int (*get_error)(const Netconfig);

	void (*whack)(const Netconfig);

	/* Private state. */
	Netconfig_State state;
};


/* Netconfig constructor call. */
extern Netconfig NAAAIM_Netconfig_Init(void);

#endif
