/** \file
 * This file contains the API definitions for an object that creates
 * an encrypted 'blob' of data.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SEALEDblob_HEADER
#define NAAAIM_SEALEDblob_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SEALEDblob * SEALEDblob;

typedef struct NAAAIM_SEALEDblob_State * SEALEDblob_State;

/**
 * External SEALEDblob object representation.
 */
struct NAAAIM_SEALEDblob
{
	/* External methods. */
	_Bool (*add_Buffer)(const SEALEDblob, const Buffer);
	_Bool (*get_Buffer)(const SEALEDblob, const Buffer);

	_Bool (*seal)(const SEALEDblob);
	_Bool (*unseal)(const SEALEDblob);

	void (*whack)(const SEALEDblob);

	/* Private state. */
	SEALEDblob_State state;
};


/* SEALEDblob constructor call. */
extern HCLINK SEALEDblob NAAAIM_SEALEDblob_Init(void);
#endif
