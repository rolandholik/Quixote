/** \file
 * This file implements the methods for an object that implements
 * parsing of JSON documents.  It provides an object interface around
 * the cJSON API.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "Origin.h"
#include "HurdLib.h"
#include "Buffer.h"
#include "String.h"

#include "NAAAIM.h"
#include "JSONparser.h"

#include "cJSON.h"


/* State extraction macro. */
#define STATE(var) CO(JSONparser_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_JSONparser_OBJID)
#error Object identifier not defined.
#endif


/** JSONparser private state information. */
struct NAAAIM_JSONparser_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object state. */
	_Bool poisoned;

	/* JSON parser state. */
	cJSON *json;

	/* Selected object. */
	cJSON *selected;

	/* Selected array and size. */
	cJSON *array;
	int array_size;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_JSONparser_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(JSONparser_State, S))

{
	INIT_STATE(S, NAAAIM, JSONparser);
	return;
}


/**
 * External public method.
 *
 * This method initializes the object for parsing a JSON document.
 *
 * \param this	The object describing the JSON object to be parsed.
 *
 * \param bufr	The object that contains the JSON document to be
 *		parsed.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		initialization succeeded.  A false value indicates the
 *		initialized failed and the object cannot be used.
 */

static _Bool parse_Buffer(CO(JSONparser, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	char *p;


	/* Check object states. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);

	/* Parse using the known buffer size. */
	p = (char *) bufr->get(bufr);
	if ( (S->json = cJSON_ParseWithLength(p, bufr->size(bufr))) == NULL )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method selects a JSON object for subsequent parsing.
 *
 * \param this	The object describing the JSON object from which a
 *		subordinate object is to be selected.
 *
 * \param name	A pointer to a null-terminated character buffer
 *		containing the name of the object to select.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		object selection succeeded.  A true value indicates
 *		that an object is available for subsequent processing
 *		with a false value indicating that the selection
 *		failed.
 */

static _Bool select_object(CO(JSONparser, this), CO(char *, name))

{
	STATE(S);

	_Bool retn = false;

	cJSON *obj,
	      *selected;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;

	selected = cJSON_GetObjectItemCaseSensitive(obj, name);
	if ( !cJSON_IsObject(selected) )
		ERR(goto done);

	S->selected = selected;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method selects a JSON integer for subsequent extraction..
 *
 * \param this	The object describing the JSON object from which a
 *		an integer is to be selected.
 *
 * \param name	A pointer to a null-terminated character buffer
 *		containing the key name of the integer to select.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		integer selection succeeded.  A true value indicates
 *		that an integer is available for subsequent processing
 *		with a false value indicating that the selection
 *		failed.
 */

static _Bool select_integer(CO(JSONparser, this), CO(char *, name))

{
	STATE(S);

	_Bool retn = false;

	cJSON *obj,
	      *selected;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;

	selected = cJSON_GetObjectItemCaseSensitive(obj, name);
	if ( !cJSON_IsNumber(selected) )
		ERR(goto done);

	S->selected = selected;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the integer for a previously selected integer.
 *
 * \param this	The object describing the JSON object from which a
 *		integer value is to be selected.
 *
 * \param iptr	A pointer to the variable that will be loaded with
 *		the value of the selected integer.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		integer request succeeded.  A true value indicates
 *		that an integer is available in the location specified
 *		by the iptr arguement to the method.
 */

static _Bool get_integer(CO(JSONparser, this), int *iptr)

{
	STATE(S);

	_Bool retn = false;

	double value;

	cJSON *obj;


	/* Verify object state. */
	if ( S->poisoned )
		ERR(goto done);

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;
	if ( !cJSON_IsNumber(obj) )
		ERR(goto done);

	if ( (value = cJSON_GetNumberValue(obj)) == NAN )
		ERR(goto done);
	*iptr = (int) value;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method selects a JSON string for subsequent extraction..
 *
 * \param this	The object describing the JSON object from which a
 *		a string is to be selected.
 *
 * \param name	A pointer to a null-terminated character buffer
 *		containing the key name of the string to select.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		string selection succeeded.  A true value indicates
 *		that a string value is available for subsequent processing
 *		with a false value indicating that the selection failed.
 */

static _Bool select_string(CO(JSONparser, this), CO(char *, name))

{
	STATE(S);

	_Bool retn = false;

	cJSON *obj,
	      *selected;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;

	selected = cJSON_GetObjectItemCaseSensitive(obj, name);
	if ( !cJSON_IsString(selected) )
		ERR(goto done);

	S->selected = selected;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the string value from a previously selected
 * string key.
 *
 * \param this	The object describing the JSON object from which a
 *		string value is to be selected.
 *
 * \param str	The object that will be loaded with the selected string.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		string request succeeded.  A true value indicates
 *		that an string value has been loaded into the supplied
 *		object while a value value indicates the retrieval
 *		failed.
 */

static _Bool get_String(CO(JSONparser, this), CO(String, str))

{
	STATE(S);

	_Bool retn = false;

	char *p;

	cJSON *obj;


	/* Verify object state. */
	if ( S->poisoned )
		ERR(goto done);

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;
	if ( !cJSON_IsString(obj) )
		ERR(goto done);

	if ( (p = cJSON_GetStringValue(obj)) == NULL )
		ERR(goto done);
	if ( !str->add(str, p) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method selects a JSON array for subsequent parsing.
 *
 * \param this	The object describing the JSON object from which a
 *		subordinate array is to be selected.
 *
 * \param name	A pointer to a null-terminated character buffer
 *		containing the name of the array to select.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		array selection succeeded.  A true value indicates
 *		that an array is available for subsequent processing
 *		with a false value indicating that the selection
 *		failed.
 */

static _Bool select_array(CO(JSONparser, this), CO(char *, name))

{
	STATE(S);

	_Bool retn = false;

	cJSON *obj,
	      *selected;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;

	/* Select the object to be acted upon. */
	obj = S->selected == NULL ? S->json : S->selected;

	selected = cJSON_GetObjectItemCaseSensitive(obj, name);
	if ( !cJSON_IsArray(selected) )
		ERR(goto done);

	S->array = selected;
	S->array_size = cJSON_GetArraySize(S->array);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the size of a JSON array that has been previously
 * selected.
 *
 * \param this	The object describing the JSON object from which a
 *		subordinate array has been selected.
 *
 * \param size	A pointer to an integer value that will contain the
 *		size of the array.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		array size determination succeeded.  A true value indicates
 *		that the variable pointed to by size argument contains
 *		a valid array size.  A false value indicates that the
 *		determination of the array size failed.
 */

static _Bool get_array_size(CO(JSONparser, this), int *size)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;
	if ( S->array == NULL )
		goto done;

	*size = S->array_size;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method selects an object from an array element.
 *
 * \param this	The object describing the JSON object that has had an
 *		array selected.
 *
 * \param idx	The element of the array to be selected.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		object selection has succeeded.  A true value indicates
 *		that an object has been selected and is available for
 *		processing.  A false value indicates that the selection
 *		failed.
 */

static _Bool select_array_object(CO(JSONparser, this), int idx)

{
	STATE(S);

	_Bool retn = false;

	cJSON *obj;


	/* Verify object state. */
	if ( S->poisoned )
		goto done;
	if ( S->array == NULL )
		goto done;
	if ( S->array_size == 0 )
		goto done;


	/* Select and verify the object. */
	if ( (obj = cJSON_GetArrayItem(S->array, idx)) == NULL )
		ERR(goto done);
	if ( !cJSON_IsObject(obj) )
		ERR(goto done);

	S->selected = obj;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns a character representation of the currently selected
 * JSON object.
 *
 * \param this	The object describing the JSON object which has a selected
 *		object.
 *
 * \param str	The object into which the string representation is to
 *		be placed.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		retrieval of the ASCII representation of the selected
 *		object has succeeded.  A true value indicates that
 *		the provided object contains a string representation of
 *		the selected object.  A false value indicates that a
 *		failure has occurred.
 */

static _Bool get_object_String(CO(JSONparser, this), CO(String, str))

{
	STATE(S);

	_Bool retn = false;

	char *p;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->selected == NULL )
		ERR(goto done);

	if ( (p = cJSON_PrintUnformatted(S->selected)) == NULL )
		ERR(goto done);
	if ( !str->add(str, p) )
		ERR(goto done);

	free(p);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for printing a JSON document that
 * has been parsed.
 *
 * \param this	A pointer to the object describing the document to be
 *		printed.
 */

static void print(CO(JSONparser, this))

{
	STATE(S);

	char *p;

	cJSON *obj;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("* POISONED *\n", stdout);
		return;
	}

	if ( S->json == NULL ) {
		fputs("* NO DOCUMENT *\n", stdout);
		return;
	}

	/* Generate and print the document. */
	obj = S->selected != NULL ? S->selected : S->json;
	if ( (p = cJSON_Print(obj)) == NULL ) {
		fputs("* FAILED PRINT *\n", stdout);
		return;
	}

	fprintf(stdout, "%s\n", p);
	free(p);
	return;
}


/**
 * External public method.
 *
 * This method clears the current selection so that the next selection
 * starts from the root of the document tree.
 *
 * \param this	A pointer to the object which is to be reset.
 */

static void clear(CO(JSONparser, this))

{
	STATE(S);


	S->selected = NULL;
	return;
}


/**
 * External public method.
 *
 * This method resets the object to allow another parsing to occur.
 *
 * \param this	A pointer to the object which is to be reset.
 */

static void reset(CO(JSONparser, this))

{
	STATE(S);


	S->selected = NULL;

	S->array = NULL;
	S->array_size = 0;

	cJSON_Delete(S->json);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a JSONparser object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(JSONparser, this))

{
	STATE(S);


	cJSON_Delete(S->json);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a JSONparser object.
 *
 * \return	A pointer to the initialized JSONparser.  A null value
 *		indicates an error was encountered in object generation.
 */

extern JSONparser NAAAIM_JSONparser_Init(void)

{
	Origin root;

	JSONparser this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_JSONparser);
	retn.state_size   = sizeof(struct NAAAIM_JSONparser_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_JSONparser_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->parse_Buffer  = parse_Buffer;
	this->select_object = select_object;

	this->select_integer = select_integer;
	this->get_integer    = get_integer;

	this->select_array	  = select_array;
	this->get_array_size	  = get_array_size;
	this->select_array_object = select_array_object;

	this->select_string = select_string;
	this->get_String    = get_String;

	this->get_object_String = get_object_String;

	this->print = print;
	this->clear = clear;
	this->reset = reset;
	this->whack = whack;

	return this;
}
