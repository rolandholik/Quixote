/** \file
 * The file implements the API definitions for the RandomBuffer object
 * which generates Buffer objects populated with random data.
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_RandomBuffer_HEADER
#define NAAAIM_RandomBuffer_HEADER


/* Object type definitions. */
typedef struct NAAAIM_RandomBuffer * RandomBuffer;

typedef struct NAAAIM_RandomBuffer_State * RandomBuffer_State;

/**
 * External RandomBuffer object representation.
 */
struct NAAAIM_RandomBuffer
{
	/* External methods. */
	_Bool (*generate)(const RandomBuffer, unsigned int);
	Buffer (*get_Buffer)(const RandomBuffer);
	void (*print)(const RandomBuffer);
	void (*whack)(const RandomBuffer);

	/* Private state. */
	RandomBuffer_State state;
};


/* RandomBuffer constructor call. */
extern RandomBuffer NAAAIM_RandomBuffer_Init(void);

#endif
