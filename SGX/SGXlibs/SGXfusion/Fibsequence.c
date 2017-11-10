/** \file
 * This file contains the implementation of a Fibonacci sequence object.
 * The data and methods in this library allow the generation and
 * sequencing of a series of numbers which follow a Fibonacci sequence.
 * Its primary use is to track memory allocations sizes, primarily in
 * the Buffer object.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "HurdLib.h"
#include "Origin.h"
#include "Fibsequence.h"


/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_Fibsequence_OBJID)
#error Object identifier not defined.
#endif


/** Fibsequence private state information. */
struct HurdLib_Fibsequence_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* The previous number in the sequence. */
	unsigned int previous;

	/* The current number in the sequence. */
	unsigned int current;
};


/**
 * Internal private function.
 *
 * This method is responsible for initializing the HurdLib_Fibsequence_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const Fibsequence_State const S) {

	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_Fibsequence_OBJID;

	S->previous = 0;
	S->current  = 1;

	return;
}




/**
 * External public method. 
 *
 * This method returns the current value of the sequence.  It does not
 * increment the state to the next sequence.  The <code>next</code>
 * implements returning the current step in the sequence with an
 * increment to the next step.
 *
 * \param this	A pointer to the Fibonacci sequence whose current value
 *		is to be returned.
 *
 * \return	An unsigned integer containing the current value of
 *		the Fibonacci sequence.
 */

static unsigned int get(const Fibsequence const this)

{
	return this->state->previous + this->state->current;
}


/**
 * External public method.
 *
 * This method implements incrementing the Fibonacci sequence to its
 * next state.
 *
 * \param this	A pointer to the Fibonacci sequence whose current value is
 *  to be returned.
 *
 * \return	An unsigned integer containing the next number in the
 *		sequence.
 */

static unsigned int next(const Fibsequence const this)

{
	auto unsigned int retn;

	auto Fibsequence_State const S = this->state;


	retn = S->previous + S->current;

	S->previous = S->current;
	S->current  = retn;

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning a sequence number larger than the
 * value specified as an arguement to the method.
 *
 * \param this	A pointer to the Fibonacci sequence which is to be
 *		incremented to the 'ceiling' value above the arguement.
 * 
 * \parm to	The ceiling value which the sequence is to be incremented
 *		beyond.
 *
 * \return	An unsigned integer containing the sequence value above
 *		the specified ceiling.
 */

static unsigned int getAbove(const Fibsequence const this, \
			     unsigned int const to)

{
	auto unsigned int retn,
		          next;


	while ( 1 ) {
		retn = this->get(this);
		if ( to <= retn )
			return(retn);
		this->next(this);
		next = this->get(this);
		if ( next < retn ) {
			this->state->previous = 0;
			this->state->current = UINT_MAX;
			return UINT_MAX;
		}
	}
}


/**
 * External public method.
 *&
 * This method implements resetting the Fibonacci sequence to its initial
 * starting state.
 *
 * \param this	A pointer to the sequence which is to be reset.
 */

static void reset(const Fibsequence const this)

{
	_init_state(this->state);
	return;
}


/**
 * External public method.
 *
 * This method implements printing of the current state of the
 * Fibonacci sequenc.
 *
 * \param this	A pointer to the Options object being operated on.
 */

static void print(const Fibsequence const this)

{
	printf("Fibonacci sequence element: %p\n", this);
	printf("\tCurrent:  %d\n", this->state->current);
	printf("\tPrevious: %d\n", this->state->previous);

	return;
}


/**
 * External public method.
 *
 * This method dumps the current internal state of the Fibonacci sequence.
 * 
 * \param this		The fibonacci sequence whose state information will
 *			be dumped.
 *
 * \param offset	The output display depth.
 */

static void dump(const Fibsequence const this, int const offset)

{
	auto Fibsequence_State S = this->state;

	S->root->iprint(S->root, offset, __FILE__ " dump: %p\n", this);
	S->root->iprint(S->root, offset, "\tCurrent:  %d\n", S->current);
	S->root->iprint(S->root, offset, "\tPrevious: %d\n", S->previous);

	return;
}


/**
 * External public method.
 *
 * This function implements a destructor for a Fibsequence object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const Fibsequence const this)

{
	auto Fibsequence_State S = this->state;

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Fibsequence object.
 *
 * \return	A pointer to the initialized Fibsequence object.
 */

extern Fibsequence HurdLib_Fibsequence_Init(void)

{
	auto Origin root;

	auto Fibsequence this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size   = sizeof(struct HurdLib_Fibsequence);
	retn.state_size    = sizeof(struct HurdLib_Fibsequence_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_Fibsequence_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->print	= print;
	this->get	= get;
	this->next	= next;
	this->getAbove	= getAbove;
	this->reset	= reset;
	this->dump	= dump;
	this->whack 	= whack;

	return this;
}
