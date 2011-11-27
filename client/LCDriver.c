/** \file
 * This file contains the implementation of an object which controls
 * input and output to an Ituner LCD display.
 */

/*
 * (C)Copyright 2011, Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Length of display. */
#define DISPLAY_LENGTH 20


/* Include files. */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <usblcd.h>

#include <Origin.h>

#include "NAAAIM.h"
#include "LCDriver.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_LCDriver_OBJID)
#error Object identifier not defined.
#endif


/** LCDriver private state information. */
struct NAAAIM_LCDriver_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* LCD operations pointer. */
	usblcd_operations *lcd;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_LCDriver_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const LCDriver_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_LCDriver_OBJID;

	S->lcd = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements turning the LCD display on.
 *
 * \param this	A pointer to the display to be turned on.
 */

static void on(const LCDriver const this)

{
	const LCDriver_State const S = this->state;


	S->lcd->backlight(S->lcd, 1);
	return;
}


/**
 * External public method.
 *
 * This method implements turning the LCD display off.
 *
 * \param this	A pointer to the display to be turned on.
 */

static void off(const LCDriver const this)

{
	const LCDriver_State const S = this->state;


	S->lcd->backlight(S->lcd, 0);
	return;
}


/**
 * External public method.
 *
 * This method implements clearing of the display.
 *
 * \param this	A pointer to the display to be cleared.
 */

static void clear(const LCDriver const this)

{
	const LCDriver_State const S = this->state;


	S->lcd->clear(S->lcd);
	return;
}

	

/**
 * External public method.
 *
 * This method places text on the display screen at the specified
 * location
 *
 * \param this	A pointer to the object which is to have text display
 *		on it.
 *
 * \param row	The row on which the text is to be displayed.
 *
 * \param col	The column on which the text is to be displayed.
 *
 * \param text	A pointer to a null terminated buffer containing the
 *		text to be displayed.
 */

static void text(const LCDriver const this, unsigned int row, unsigned col, \
		 const char * const text)

{
	const LCDriver_State const S = this->state;


	S->lcd->settext(S->lcd, row, col, (char *) text);
	return;
}


/**
 * External public method.
 *
 * This method displays centered text on the display.
 *
 * \param this	A pointer to the object which is to have text display
 *		on it.
 *
 * \param row	The row on which the text is to be displayed.
 *
 * \param text	A pointer to a null terminated buffer containing the
 *		text to be centered and displayed.
 */

static void center(const LCDriver const this, unsigned const int row, \
		   const char * const text)

{
	const LCDriver_State const S = this->state;

	unsigned int col;


	col = (DISPLAY_LENGTH - strlen(text)) / 2;
	S->lcd->settext(S->lcd, row, col, (char *) text);
	return;
}


/**
 * External public method.
 *
 * This method reads a key from the display.
 *
 * \param this	A pointer to the object which is to have a key read from
 *		it.
 *
 * \return	One of the enumerated members of the LCDriver_key is
 *		returned.
 */

static LCDriver_key read_key(const LCDriver const this)

{
	const LCDriver_State const S = this->state;

	unsigned int lp,
		     elements;

	_Bool valid_key;

	unsigned char key[1];

	LCDriver_key retn;

	struct key_table {
		unsigned char code;
		LCDriver_key key;
	} translation[] = {
		{0, LCDriver_key_release},
		{3, LCDriver_key_F1}
	};


	S->lcd->keystate(S->lcd, &valid_key, key);
	fprintf(stderr, "status: %d, key: %0x\n", valid_key, key[0]);
	fprintf(stderr, "array size: %d\n", \
		sizeof(translation)/sizeof(struct key_table));

	if ( !valid_key )
		return LCDriver_key_error;

	elements = sizeof(translation)/sizeof(struct key_table);
	for (lp= 0; lp < elements; ++lp) {
		if ( key[0] == translation[lp].key ) {
			retn = translation[lp].key;
			break;
		}
	}
	S->lcd->keystate(S->lcd, &valid_key, key);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a LCDriver object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const LCDriver const this)

{
	const LCDriver_State const S = this->state;


	if ( S->lcd != NULL )
		S->lcd->close(S->lcd);

	S->root->whack(S->root, this, S);
	return;
}


	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a LCDriver object.
 *
 * \return	A pointer to the initialized LCDriver.  A null value
 *		indicates an error was encountered in object generation.
 */

extern LCDriver NAAAIM_LCDriver_Init(void)

{
	Origin root;

	LCDriver this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_LCDriver);
	retn.state_size   = sizeof(struct NAAAIM_LCDriver_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_LCDriver_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize internal state. */
	this->state->lcd = new_usblcd_operations();
	this->state->lcd->init(this->state->lcd);

	/* Method initialization. */
	this->on  = on;
	this->off = off;

	this->clear  = clear;
	this->text   = text;
	this->center = center;

	this->read_key = read_key;
	
	this->whack = whack;

	return this;
}
