/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
	_Bool (*generate)(const RandomBuffer, int);
	Buffer (*get_Buffer)(const RandomBuffer);
	void (*print)(const RandomBuffer);
	void (*whack)(const RandomBuffer);

	/* Private state. */
	RandomBuffer_State state;
};


/* RandomBuffer constructor call. */
extern RandomBuffer NAAAIM_RandomBuffer_Init(void);

#endif
