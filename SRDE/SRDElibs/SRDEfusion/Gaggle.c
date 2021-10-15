/** \file
 * This file contains the implementation of an object that manages
 * an array (gaggle) of other objects.
 */

/**************************************************************************
 * Copyright (c) 2021, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "HurdLib.h"
#include "Origin.h"
#include "Buffer.h"
#include "Gaggle.h"


/* State initialization macro. */
#define STATE(var) CO(Gaggle_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_Gaggle_OBJID)
#error Object identifier not defined.
#endif


/** Gaggle private state information. */
struct HurdLib_Gaggle_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Count of objects. */
	size_t size;

	/* Cursor position. */
	size_t cursor;

	/* Buffer object to hold objects. */
	Buffer gaggle;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the HurdLib_Gaggle_State
 * structure which holds state information for each instantiated object.
n *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(Gaggle_State, S)) {

	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_Gaggle_OBJID;

	S->poisoned = false;

	S->size	  = 0;
	S->cursor = 0;

	S->gaggle = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements adding an object to the Gaggle.
 *
 * \param this	A pointer to the object which is to have an object
 *		added to it.
 */

static _Bool add(CO(Gaggle, this), void *object)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		goto done;


	/* Add the object. */
	if ( !S->gaggle->add(S->gaggle, object, sizeof(object)) )
		goto done;
	++S->size;

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieving an object from the gaggle based
 * on the current cursor position.
 *
 * \param this	A pointer to the object which is to have an object
 *		added to it.
 */

static void * get(CO(Gaggle, this))

{
	STATE(S);

	void *retn = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		goto done;
	if ( S->size == 0 )
		goto done;


	/* Return null if we are at the end of the pack. */
	if ( S->cursor >= S->size )
		goto done;


	/* Return object pointer at the current cursor position. */
	retn  = S->gaggle->get(S->gaggle);
	retn += (S->cursor * sizeof(retn));

	++S->cursor;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieving the size of the object which is
 * the number of objects that have been added to it.
 *
 * \param this	A pointer to the object which is to have an object
 *		added to it.
 *
 * \return	The number of objects in the object.
 */

static size_t size(CO(Gaggle, this))

{
	STATE(S);


	/*
	 * Return a size of zero in case of a poisoned object, otherwise
	 * return the active size of the object.
	 */
	if ( S->poisoned )
		return 0;

	return S->size;
}


/**
 * External public method.
 *
 * This method resets the traversal cursor to zero for the object.
 *
 * \param this	A pointer to the object whose cursor is to be reset.
 */

static void reset(CO(Gaggle, this))

{
	STATE(S);

	S->cursor = 0;
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Gaggle object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Gaggle, this))

{
	STATE(S);


	WHACK(S->gaggle);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Gaggle object.
 *
 * \return	A pointer to the initialized Gaggle.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Gaggle HurdLib_Gaggle_Init(void)

{
	Origin root;

	Gaggle this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct HurdLib_Gaggle);
	retn.state_size   = sizeof(struct HurdLib_Gaggle_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_Gaggle_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->gaggle, goto fail);

	/* Method initialization. */
	this->add = add;
	this->get = get;

	this->size = size;

	this->reset = reset;
	this->whack = whack;

	return this;


fail:
	WHACK(this->state->gaggle);

	root->whack(root, this, this->state);
	return NULL;
}
