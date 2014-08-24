/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_IDmgr_HEADER
#define NAAAIM_IDmgr_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IDmgr * IDmgr;

typedef struct NAAAIM_IDmgr_State * IDmgr_State;

/**
 * External IDmgr object representation.
 */
struct NAAAIM_IDmgr
{
	/* External methods. */
	_Bool (*setup)(const IDmgr);
	_Bool (*attach)(const IDmgr);

	_Bool (*get_id_key)(const IDmgr, const Buffer, const Buffer);
	_Bool (*set_id_key)(const IDmgr, const Buffer, const Buffer);

	void (*whack)(const IDmgr);

	/* Private state. */
	IDmgr_State state;
};


/* IDmgr constructor call. */
extern IDmgr NAAAIM_IDmgr_Init(void);

#endif
