/** \file
 * This file contains the header and API definitions for an object
 * which is used to implement and manage a single contour point in
 * an ISOidentity behavioral map.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_ContourPoint_HEADER
#define NAAAIM_ContourPoint_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ContourPoint * ContourPoint;

typedef struct NAAAIM_ContourPoint_State * ContourPoint_State;

/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_ContourPoint
{
	/* External methods. */
	void (*add)(const ContourPoint, const Buffer);
	unsigned char * (*get)(const ContourPoint);

	void (*set_invalid)(const ContourPoint);
	_Bool (*is_valid)(const ContourPoint);
	_Bool (*equal)(const ContourPoint, const ContourPoint);

	void (*whack)(const ContourPoint);

	/* Private state. */
	ContourPoint_State state;
};


/* Exchange event constructor call. */
extern ContourPoint NAAAIM_ContourPoint_Init(void);
#endif