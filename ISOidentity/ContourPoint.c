/** \file
 * This file contains the implementation of an object which manages
 * a single contour point in an iso-identity behavioral map.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "ContourPoint.h"


/* Object state extraction macro. */
#define STATE(var) CO(ContourPoint_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ContourPoint_OBJID)
#error Object identifier not defined.
#endif


/** ExchangeEvent private state information. */
struct NAAAIM_ContourPoint_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate this point represents a behavior violation. */
	_Bool violation;

	/* The measurement */
	unsigned char point[NAAAIM_IDSIZE];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_ExhangeEvent_State structure which holds state information
 * for each the event.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(ContourPoint_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_ContourPoint_OBJID;

	S->poisoned  = false;
	S->violation = false;

	memset(S->point, '\0', sizeof(S->point));

	return;
}


/**
 * External public method.
 *
 * This method implements a method for adding a measurement value to
 * the point.
 *
 * \param this		The object whose value is to be returned.
 *
 * \param bufr		The object containing the measurement value
 *			for the point.
 */

static void add(CO(ContourPoint, this), CO(Buffer, bufr))

{
	STATE(S);


	/* Verify object status. */
	if ( bufr->poisoned(bufr) )
		return;
	if ( bufr->size(bufr) != NAAAIM_IDSIZE )
		return;


	/* Set the value of the object. */
	memcpy(S->point, bufr->get(bufr), NAAAIM_IDSIZE);

	return;
}


/**
 * External public method.
 *
 * This method implements an accessor method for retrieving the
 * value of the contour point.
 *
 * \param this	The object whose value is to be returned.
 *
 * \return	A pointer to the memory buffer containing the
 *		measurement value of the point.
 */

static unsigned char * get(CO(ContourPoint, this))

{
	return this->state->point;
}


/**
 * External public method.
 *
 * This method implements an accessor method for retrieving the
 * value of the contour point as a Buffer object.
 *
 * \param this	The object whose value is to be returned.
 *
 * \param bufr	A pointer to the object which is to be loaded with
 *		the measurement value of the contour point.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the supplied object has a valid value.  A false
 *		value indicates an error was encountered and the
 *		object does not have a valid value.  A true value
 *		indicates the supplied object has a valid
 *		measurement point.
 */

static _Bool get_Buffer(CO(ContourPoint, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr == NULL )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Load the buffer with the measurement value. */
	if ( !bufr->add(bufr, S->point, sizeof(S->point)) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for indicating the point represents
 * an invalid behavior.
 *
 * \param this		The object whose status is to be set.
 */

static void set_invalid(CO(ContourPoint, this))

{
	this->state->violation = true;
	return;
}


/**
 * External public method.
 *
 * This method implements a method for testing wehther or not the
 * the point represents a valid measurement value.
 *
 * \param this		The object whose value is to be checked.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the point represents a valid behavior.  A false
 *		value indicates the point represents an invalid
 *		behavior while a true value indicates the point
 *		is a valid behavior point on the contour map.
 */

static _Bool is_valid(CO(ContourPoint, this))

{
	return !this->state->violation;
}


/**
 * External public method.
 *
 * This method implements a method for determining whether or not
 * two points are equal.
 *
 * \param this	The object whose value is to be checked.
 *
 * \param other	The point which is to be compared to the existing
 *		point.
 *
 * \return	A boolean value is returned to indicate the result
 *		of the equality check.  A false value indicates
 *		the values do not match while a true value indicates
 *		the points are equal.
 */

static _Bool equal(CO(ContourPoint, this), CO(ContourPoint, other))

{
	STATE(S);

	return memcmp(S->point, other->get(other), sizeof(S->point)) == 0;
}


/**
 * External public method.
 *
 * This method implements a destructor for the object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(ContourPoint, this))

{
	STATE(S);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an ExchangeEvent object.
 *
 * \return	A pointer to the initialized exchange event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern ContourPoint NAAAIM_ContourPoint_Init(void)

{
	Origin root;

	ContourPoint this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ContourPoint);
	retn.state_size   = sizeof(struct NAAAIM_ContourPoint_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ContourPoint_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->add = add;
	this->get = get;

	this->get_Buffer = get_Buffer;

	this->set_invalid = set_invalid;
	this->is_valid	  = is_valid;

	this->equal = equal;

	this->whack = whack;

	return this;
}
