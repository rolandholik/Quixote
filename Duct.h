/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_Duct_HEADER
#define NAAAIM_Duct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Duct * Duct;

typedef struct NAAAIM_Duct_State * Duct_State;

/**
 * External Duct object representation.
 */
struct NAAAIM_Duct
{
	/* External methods. */
	_Bool (*init_server)(const Duct);
	_Bool (*load_credentials)(const Duct, const char *, const char *);
	_Bool (*init_port)(const Duct, int);
	int (*accept_connection)(const Duct);
	void (*whack)(const Duct);

	/* Private state. */
	Duct_State state;
};


/* Duct constructor call. */
extern Duct NAAAIM_Duct_Init(void);

#endif
