/** \file
 * This file contains API definitions for the Buffer object which implements
 * a dynamically sized character buffer.  It should be included by any
 * applications which desire to create or use this object.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef HurdLib_Buffer_HEADER
#define HurdLib_Buffer_HEADER


/* Object type definitions. */
typedef struct HurdLib_Buffer * Buffer;

typedef struct HurdLib_Buffer_State * Buffer_State;

/**
 * External Buffer object representation.
 */
struct HurdLib_Buffer
{
	/* External methods. */
	_Bool (*add)(const Buffer, unsigned char const *, size_t);
	_Bool (*add_Buffer)(const Buffer, const Buffer);
	_Bool (*add_hexstring)(const Buffer, char const *);
	_Bool (*equal)(const Buffer, const Buffer);

	unsigned char * (*get)(const Buffer);
	void (*shrink)(const Buffer, size_t);
	size_t (*size)(const Buffer);
	void (*reset)(const Buffer);
	void (*print)(const Buffer);
	void (*hprint)(const Buffer);
	void (*dump)(const Buffer, int);
	_Bool (*poisoned)(const Buffer);
	void (*whack)(const Buffer);

	/* Private state. */
	Buffer_State state;
};


/* Buffer constructor call. */
extern Buffer HurdLib_Buffer_Init(void);

#endif
