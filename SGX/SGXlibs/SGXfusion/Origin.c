/** \file
 * This file contains the implementation of the Origin object which is
 * the parent object for any components which use the HurdLib C
 * component library.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include "HurdLib.h"
#include "Origin.h"


/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_Origin_OBJID)
#error Object identifier not defined.
#endif


/*
 * Static function declarations. These need to be located before 
 * HurdLib_Origin structure definition below.
 */
static _Bool init(const Origin, int, int, struct HurdLib_Origin_Retn *);
static void whack(const Origin, void *, void *);
static void iprint(const Origin, int, char const *, ...);


/** Origin private state information. */
struct HurdLib_Origin_State
{
	unsigned int init_count;
} state = { 0 };

/**
 * The root structure is the top of the object tree.
 */
static struct HurdLib_Origin root = {

	/* External method calls. */
	.init   = init,
	.whack  = whack,
	.iprint = iprint,

	/* Private object state. */
	.state = &state,
};

static Origin Root = &root;


/**
 * Internal private function.
 *
 * This is an internal function which checks the consistency of object
 * allocation.  If a single object initializaiton is carried out an
 * atexit call is registered for this function.
 */

static void _check_state(void)

{
	if ( Root->state->init_count != 0 ) {
		fprintf(stderr, "%s[%s]:\n", __FILE__, __FUNCTION__);
		fprintf(stderr, "\tUnmatched object allocation, " \
			"count = %d\n", Root->state->init_count);
	}

	return;
}


/**
 * External public method.
 *
 * This function is the generic allocator function for all objects.  Object
 * allocation is centralized here so as to minimize the need to do
 * error checking in each constructor.  The object is also placed in the
 * pool table for tracking and reclamation.
 *
 * \param this:	The Origin object which is the base of all objects generated
 * 	        for the project.
 *
 * \param libid	The numeric identifier for the library which the the object
 *	        object is being initialized for.
 * 
 * \param objid	The numeric identifier for the object being initialized.
 *
 * \param retn 	A pointer to a structure which contains the allocation amounts
 *	   	for the object structure and the internal state information of
 *		the object.  The object and state structure pointers will be
 *		returned in this structure.
 *
 * \return	A boolean value is used to indicate success or failure of
 *		the base object allocation.  A false value indicates an
 *		error condition.
 */

static _Bool init(const Origin const this, int const libid, int const objid, \
		  struct HurdLib_Origin_Retn * const retn)

{
	static _Bool registered = 0;


	/* Sanity checks. */
	if ( (this != Root) || (retn == NULL) )
		return false;

	/* Object allocation. */
	if ( (retn->object = malloc(retn->object_size)) == NULL )
		return false;

	/* Internal state allocation. */
	if ( (retn->state = malloc(retn->state_size)) == NULL ) {
		free(retn->object);
		return false;
	}

	/* Track object allocation count. */
	this->state->init_count += 1;
	if ( !registered ) {
		if ( atexit(_check_state) != 0 ) {
			fprintf(stderr, "%s[%s]: Failed atexit " \
				" registration.\n", __FILE__, __FUNCTION__);
		}
		else
			registered = 1;
	}

	return true;
}


/**
 * External public method. 
 *
 * This function provides a varargs based print function which prepends
 * the output with a depth classifier.
 *
 * \param object	A pointer to the encapsulation object.
 *
 * \param offset	The current depth of the dump.
 *
 * \param fmt		The printf format string.
 *
 * \return		No return value is defines
 */

static void iprint(const Origin this, int offset, char const * const fmt, ...)

{
	char bufr[BUFSIZ];

	va_list ap;


	while ( offset-- > 0 )
		fputc('|', stderr);

	memset(bufr, '\0', sizeof(bufr));
	va_start(ap, fmt);
	vsnprintf(bufr, BUFSIZ, fmt, ap);
	va_end(ap);

	ocall_print_string(bufr);
	return;
}


/**
 * External public method.
 *
 * This function implements a generic object destructor.  It releases
 * the memory allocated for the internal state and general object
 * description structure.  It also decrements the current allocated
 * object count.
 *
 * \param this		The object to be released/destroyed.
 *
 * \param object	A pointer to the public encapsulation object.
 *
 * \param state		A pointer to the internal object state.
 */

static void whack(const Origin const this, void * const object, \
		    void * const state)

{
	free(state);
	free(object);

	if ( this->state->init_count > 0 )
		this->state->init_count -= 1;

	return;
}

	
/**
 * External public function.
 *
 * The function implements the initialization call for the HurdLib
 * obect heirarchy.  It returns the top of the object tree for use
 * by an object wishing to derive functionality from the core object
 * management library.
 *
 * \return The function returns a pointer to the root object of the
 *	   tree.
 */

extern Origin HurdLib_Origin_Init(void)

{
	return Root;
}
