/** \file
 * This file contains the implementation of an object that implements
 * parsing of a TSEM security state event description.
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
#include <errno.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "TSEMparser.h"


/* Object state extraction macro. */
#define STATE(var) CO(TSEMparser_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TSEMparser_OBJID)
#error Object identifier not defined.
#endif


/** TSEMparser private state information. */
struct NAAAIM_TSEMparser_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Object containing the field that will be parsed. */
	String field;

	/* Object that will hold extracted keys. */
	String key_value;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_ExhangeEvent_State structure which holds state information
 * for the model
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(TSEMparser_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TSEMparser_OBJID;

	S->poisoned = false;

	S->field = NULL;

	return;
}


/**
 * External public method.
 *
 * This method extracts a JSON encoded field definition from an event
 * description.
 *
 * \param this	A pointer to the object that is to hold the extracted
 *		field.
 *
 * \param str	The object containing the event description from which
 *		the field is to be extracted.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of extracting the field definition.  A false
 *		value indicates the field could not be extracted while
 *		a true value indicates the object has been populated
 *		with a field description.
 */

static _Bool extract_field(CO(TSEMparser, this), CO(String, event), \
			   CO(char *, field))

{
	STATE(S);

	_Bool retn = false;

	char *start,
	     *end,
	     in[2];

	int cnt = 1;


	/* Verify object and argument status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (event == NULL) || event->poisoned(event) )
		ERR(goto done);

	/* Verify this is a valid message. */
	start = event->get(event);
	end   = start + event->size(event) - 1;
	if ( (*start != '{') || (*end != '}') )
		ERR(goto done);

	/* Create the field specifier we will look for. */
	S->field->reset(S->field);
	if ( !S->field->add_sprintf(S->field, "\"%s\": {", field) )
		ERR(goto done);

	/* Locate the start and end of the field specifier. */
	if ( (start = strstr(start, S->field->get(S->field))) == NULL )
		ERR(goto done);
	start += S->field->size(S->field) - 1;

	end = start + 1;
	while ( (*end != '\0') && (cnt > 0) ) {
		if ( *end == '{' )
			++cnt;
		if ( *end == '}' )
			--cnt;
		++end;
	}
	if ( *end == '\0' )
		ERR(goto done);

	/* Copy the event field. */
	S->field->reset(S->field);

	in[1] = '\0';
	do {
		in[0] = *start;
		S->field->add(S->field, in);
	} while ( ++start < end );

	if ( S->field->poisoned(S->field) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is used to obtain a copy of the field that has been
 * extracted.
 *
 * \param this	A pointer to the object that holds the field to be
 *		returned.
 *
 * \param str	The object containing the object that the field is
 *		to be copied into.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of extracting the field definition.  A false
 *		value indicates the field could not be extracted while
 *		a true value indicates the object has been populated
 *		with a field description.
 */

static _Bool get_field(CO(TSEMparser, this), CO(String, str))

{
	STATE(S);

	_Bool retn  = false;


	/* Verify object and argument status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (str == NULL) || str->poisoned(str) )
		ERR(goto done);

	/* Copy the field definition into the supplied object. */
	if ( !str->add(str, S->field->get(S->field)) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal private method.
 *
 * This method locates the starting position of a key in an extracted
 * field.
 *
 * \param this	A pointer to the object containing the field whose
 *		key position is to be determined.
 *
 * \param key	The field key value to be used for the extraction.
 *
 * \return	A pointer to the starting position of the key is
 *		returned.  A NULL value is used to indicate the key
 *		was not found.
 */

static char * _find_key(CO(TSEMparser_State, S), CO(char *, key))

{
	char *p,
	     *type,
	     add[2];


	/* Create the key descriptor. */
	S->key_value->reset(S->key_value);
	if ( !S->key_value->add_sprintf(S->key_value, "\"%s\": ", key) )
		return NULL;

	/* Verify that the key is found and terminate it appropriately. */
	p = strstr(S->field->get(S->field), S->key_value->get(S->key_value));
	if ( p == NULL )
		return NULL;

	type = p + S->key_value->size(S->key_value);
	if ( *type == '\0' )
		return NULL;
	if ( (*type != '"') && (*type != '{') )
		return NULL;

	add[0] = *type;
	add[1] = '\0';
	if ( !S->key_value->add(S->key_value, add) )
		return NULL;

	return p;
}


/**
 * Internal private method.
 *
 * This method locates and extracts a key value from the field.
 *
 * \param this	A pointer to the object from which the field value
 *		is to be extracted.
 *
 * \param key	The field key value to be used for the extraction.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of extracting the key value.  A false
 *		value indicates an error was encountered while extracting
 *		the key value while a true value indicates the key_value
 *		String object was populated with the value of the key.
 */

static _Bool _get_key(CO(TSEMparser_State, S), CO(char *, key))

{
	_Bool retn = false;

	char *start,
	     *end,
	     in[2];


	/* Locate the start and end of the key. */
	if ( (start = _find_key(S, key)) == NULL )
		ERR(goto done);
	start += S->key_value->size(S->key_value);
	end    = start;

	if ( (end = strchr(start, '"')) == NULL )
		ERR(goto done);

	/* Copy the key value. */
	S->key_value->reset(S->key_value);

	in[1] = '\0';
	do {
		in[0] = *start;
		S->key_value->add(S->key_value, in);
	} while ( ++start < end );

	if ( S->key_value->poisoned(S->key_value) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the conversion of a field description to an
 * integer value.
 *
 * \param this	A pointer to the object from which the integer value
 *		will be extracted.
 *
 * \param key	The field key value to be used for the extraction.  A
 *		NULL value indicates the field value itself should be
 *		used.
 *
 * \param value	A pointer to the variable that the return value should
 *		be copied into.
 *
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of extracting the integer value.  A false
 *		value indicates an error was encountered while converting
 *		the field value to an integer.  The variable pointed
 *		to will not be modified.  A true value indicates the
 *		integer value was extracted and the variable pointed to
 *		was updated.
 */

static _Bool get_integer(CO(TSEMparser, this), CO(char *, key), \
			 long long int *vp)

{
	STATE(S);

	_Bool retn = false;

	long long int value;


	if ( key != NULL ) {
		if ( !_get_key(S, key) )
			ERR(goto done);
		value = strtoll(S->key_value->get(S->key_value), NULL, 0);
	}
	else
		value = strtoll(S->field->get(S->field), NULL, 0);

	if ( errno == ERANGE)
		ERR(goto done);
	*vp = value;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the extraction of the text value of an event
 * description.
 *
 * \param this	A pointer to the object from which the key value is
 *		to be extracted
 *
 * \param key	The field key value to be used for the extraction.  A
 *		NULL value indicates the field value itself should be
 *		used.
 *
 * \param value	A pointer to the object that the text is to be copied
 *		into.
 *
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of extraction of the text.  A false value indicates an
 *		error was encountered while extracting the text.
 */

static _Bool get_text(CO(TSEMparser, this), CO(char *, key), CO(String, text))

{
	STATE(S);

	_Bool retn = false;

	char *value;


	if ( key != NULL ) {
		if ( !_get_key(S, key) )
			ERR(goto done);
		value = S->key_value->get(S->key_value);
	}
	else
		value = S->field->get(S->field);

	if ( !text->add(text, value) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This method tests whether or not a key is present in an extracted
 * field.
 *
 * \param this	A pointer to the object that contains an extracted
 *		field that the presence of a key is to be detected.
 *
 * \param key	The field key value to be tested for.
 *
 * \return	A boolean value is used to indicate the presence of
 *		a key.  A false value indicates that the key is not
 *		present while a true value indicates the key is
 *		present.
 */

static _Bool has_key(CO(TSEMparser, this), CO(char *, key))

{
	STATE(S);

	_Bool retn = false;


	if ( S->field->size(S->field) == 0 )
		return retn;

	return _find_key(S, key) != NULL;
}


/**
 * External public method.
 *
 * This method implements printing of the event field from which
 * descriptions are being extracted.
 *
 * \param this	A pointer to the object whose event field is to
 *		be printed.
 */

static void print(CO(TSEMparser, this))

{
	STATE(S);

	S->field->print(S->field);
	return;
}


/**
 * External public method.
 *
 * This method implements the reset of the TSEMparser object in
 * order to support the extraction of an additional field
 *
 * \param this	A pointer to the object which is to be reset.
 */

static void reset(CO(TSEMparser, this))

{
	STATE(S);

	S->field->reset(S->field);
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an TSEMparser object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TSEMparser, this))

{
	STATE(S);


	WHACK(S->field);
	WHACK(S->key_value);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an TSEMparser object.
 *
 * \return	A pointer to the initialized interaction event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TSEMparser NAAAIM_TSEMparser_Init(void)

{
	Origin root;

	TSEMparser this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TSEMparser);
	retn.state_size   = sizeof(struct NAAAIM_TSEMparser_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TSEMparser_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, String, this->state->field, goto fail);
	INIT(HurdLib, String, this->state->key_value, goto fail);

	/* Method initialization. */
	this->extract_field = extract_field;

	this->get_field	  = get_field;
	this->get_integer = get_integer;
	this->get_text	  = get_text;

	this->has_key	  = has_key;

	this->print = print;
	this->reset = reset;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->field);

	root->whack(root, this, this->state);
	return NULL;
}
