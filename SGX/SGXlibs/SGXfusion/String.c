/** \file
 * This file contains the implementation of the String object.
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
#include <string.h>
#include <stdbool.h>

#include "HurdLib.h"
#include "Origin.h"
#include "Buffer.h"
#include "String.h"


/* Verify library/object header file inclusions. */
#if !defined(HurdLib_LIBID)
#error Library identifier not defined.
#endif

#if !defined(HurdLib_String_OBJID)
#error Object identifier not defined.
#endif


/** String private state information. */
struct HurdLib_String_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* The Buffer object which implements the string. */
	Buffer buffer;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the HurdLib_String_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(const String_State const S) {

	S->libid = HurdLib_LIBID;
	S->objid = HurdLib_String_OBJID;

	return;
}


/**
 * External public method.
 *
 * This method implements adding characters to the null-terminated string.
 * The underlying Buffer object will be dynamically sized to accomodate
 * the incoming characters unless a fixed size String has been selected.
 * In the latter case the addition of characters will occur up to the
 * limit of the previously specified size of the string.
 *
 * \param this A pointer to the String object which characters are to be
 * 	       added to.
 *
 * \param src	A pointer to the area from which the characters are to
 *		be copied from.
 *
 * \return	A boolean value is returned to indicate the status of
 *		adding characters to the string.  A true value indicates
 *		success.
 */

static _Bool add(const String const this, char const * const src)

{
	auto String_State S = this->state;


	if ( S->buffer->poisoned(S->buffer) )
		return false;

	S->buffer->shrink(S->buffer, 1);

	if ( !S->buffer->add(S->buffer, (unsigned char *) src, strlen(src)) )
		return false;
	if ( !S->buffer->add(S->buffer, (unsigned char *) "\0", 1) )
		return false;

	return true;
}


/**
 * External public method.
 *
 * This metehod implements returning a pointer to the null terminated
 * C string buffer which this object implements.
 *
 * \param this	A pointer to the String object whose character buffer
 *		is to be returned.
 *
 * \return 	A pointer to the buffer implemented by the Buffer
 *		object is returned to the caller.
 */

static char * get(const String const this)

{
	if ( this->state->buffer->poisoned(this->state->buffer) )
		return NULL;

	return (char *) this->state->buffer->get(this->state->buffer);
}


/**
 * External public method.
 *
 * This method implements returning the size of the String object.  The
 * size is equivalent to the result of calling strlen on the contents of
 * the Buffer object used to implement the String contents.
 *
 * \param this	A pointer to String object whose size is to be returned.
 *
 * \return	The size of the String.
 */

static size_t size(const String const this)

{
	auto String_State S = this->state;

	auto size_t size = S->buffer->size(S->buffer);


	if ( S->buffer->poisoned(S->buffer) )
		return 0;

	if ( size == 0 )
		return 0;
	else
		return --size;
}


/**
 * External public method.
 *
 * This method implements printing of the string.  The contents of the
 * internal buffer object is simply printed to the standard output
 * channel.
 *
 * \param this	A pointer to the string object which is to be printed.
 */

static void print(const String const this)

{
	auto String_State S = this->state;


	if ( S->buffer->poisoned(S->buffer) )
		fputs("* Poisoned *\n", stdout);
	else
		fprintf(stdout, "%s\n", S->buffer->get(S->buffer));

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a String object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static _Bool poisoned(const String const this)

{
	return this->state->buffer->poisoned(this->state->buffer);
}


/**
 * External public method.
 *
 * This method implements resetting of the String object back to its
 * zero length.  This is done by inheriting functionality from the
 * underying Buffer object.
 *
 * \param this	A point to the object which is to be reset.
 */

static void reset(CO(String, this))

{
	return this->state->buffer->reset(this->state->buffer);
}
	
	
/**
 * External public method.
 *
 * This method implements a destructor for a String object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const String const this)

{
	auto String_State S = this->state;


	S->buffer->whack(S->buffer);
	S->root->whack(S->root, this, S);

	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a String object.
 *
 * \return	A pointer to the initialized String object.  A null pointer
 *		indicates an error was encountered in object generation.
 */

extern String HurdLib_String_Init(void)

{
	auto Origin root;

	auto String this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct HurdLib_String);
	retn.state_size   = sizeof(struct HurdLib_String_State);
	if ( !root->init(root, HurdLib_LIBID, HurdLib_String_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->buffer = HurdLib_Buffer_Init()) == NULL ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->add	= add;
	this->get	= get;
	this->size	= size;
	this->print	= print;
	this->poisoned	= poisoned;

	this->reset	= reset;
	this->whack	= whack;

	return this;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a String object.  This
 * constructor initializes the String object with the contents of the
 * character buffer provided in the arguement to the call.
 *
 * \param cstr	A pointer to a null-terminated buffer containing the
 *		string to initialize the object with.
 *
 * \return	The initialized String object is returned to the call.  A
 *		NULL pointer indicate an error was encountered in object
 *		initialization.
 */

extern String HurdLib_String_Init_cstr(char const * const cstr)

{
	auto String this;


	if ( (this = HurdLib_String_Init()) == NULL )
		return NULL;

	if ( !this->add(this, cstr) ) {
		this->whack(this);
		return NULL;
	}

	return this;
}
