/** \file
 * This file contains the implementation of an object that handles
 * parsing of security event descriptions from the Trusted Security
 * Event Model (TSEM) Linux LSM.
 */

/**************************************************************************
 * Copyright (c) 2023, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "TSEMparser.h"
#include "TSEMevent.h"


/* State extraction macro. */
#define STATE(var) CO(TSEMevent_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TSEMevent_OBJID)
#error Object identifier not defined.
#endif

/** Command definition structure. */
static struct cmd_definition {
	int command;
	char *syntax;
} TSEM_events[] = {
	{TSEM_EVENT_AGGREGATE,	"aggregate"},
	{TSEM_EVENT_EVENT,	"event"},
	{TSEM_EVENT_LOG,	"log" },
	{0,			NULL}
};

/** TSEMevent private state information. */
struct NAAAIM_TSEMevent_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object state. */
	_Bool poisoned;

	/* The current type of event. */
	enum TSEM_export_type type;

	/* Buffer object to hold the read of the event description. */
	Buffer bufr;

	/* String object holding the event description. */
	String event;

	/* String object holding an extracted field value. */
	String field;

	/* Event parsing object. */
	TSEMparser parser;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TSEMevent_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TSEMevent_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TSEMevent_OBJID;

	S->poisoned = false;

	S->type = TSEM_EVENT_UNKNOWN;

	return;
}


/**
 * External public method.
 *
 * This method implements setting an event description string.
 *
 * \param this	A pointer to the object which is to have its event
 *		field set.
 *
 * \param event	The String object containing the event description
 *		that is to be set.
 *
 * \return	A boolean value is used to indicate the state of the
 *		read.  A false value indicates the setting of the event
 *		field failed while a true value indicates the object has
 *		a valid event description.
 */

static _Bool set_event(CO(TSEMevent, this), CO(String, event))

{
	STATE(S);


	return S->event->add(S->event, event->get(event));
}


/**
 * External public method.
 *
 * This method implements reading an event description string.
 *
 * \param this	A pointer to the object which is to read the event
 *		description.
 *
 * \param fd	The file descriptor that the event is to be read
 *		from.
 *
 * \return	A boolean value is used to indicate the state of the
 *		read.  A false value indicates the read failed while
 *		a true value indicates the object has a valid event
 *		description.
 */

static _Bool read_event(CO(TSEMevent, this), const int fd)

{
	STATE(S);

	_Bool retn = false;

	char *p,
	     in[1];

	int available;


	if ( ioctl(fd, FIONREAD, &available) != 0 )
		ERR(goto done);

	/* Expand the input buffer to match the input size. */
	in[0] = '\0';
	while ( S->bufr->size(S->bufr) < available )
		S->bufr->add(S->bufr, (void *) in, 1);

	p = (char *) S->bufr->get(S->bufr);
	memset(S->bufr->get(S->bufr), '\0', S->bufr->size(S->bufr));

	/* Read the event string and convert the linefeed to a NULL. */
	if ( read(fd, p, available) < 0 )
		ERR(goto done);
	if ( (p = strchr(p, '\n')) == NULL )
		ERR(goto done);
	*p = '\0';

	/* Transfer event description to a String object. */
	S->event->reset(S->event);
	if ( !S->event->add(S->event, (char *) S->bufr->get(S->bufr)) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the initial parsing of the exported event
 * description.
 *
 * \param this	A pointer to the object whose export event is to
 *		be interrogated.
 *
 * \return	One of the values of the TSEM_export_type enumeration
 *		is returned to indicate the status of the event
 *		description held by the object.  A failure is
 *		indicated by a return of the TSEM_EVENT_UNKNOWN
 *		type.
 */

static enum TSEM_export_type extract_export(CO(TSEMevent, this))

{
	STATE(S);

	enum TSEM_export_type retn = TSEM_EVENT_UNKNOWN;

	struct cmd_definition *cp;


	S->parser->reset(S->parser);
	if ( !S->parser->extract_field(S->parser, S->event, "export") )
		goto done;
	if ( !S->parser->get_text(S->parser, "type", S->field) )
		goto done;

	for (cp= TSEM_events; cp->syntax != NULL; ++cp) {
		if ( strcmp(cp->syntax, S->field->get(S->field)) == 0 )
			break;
	}
	if ( cp->syntax == NULL )
		goto done;

	S->type = retn = cp->command;

	S->parser->reset(S->parser);
	if ( !S->parser->extract_field(S->parser, S->event, \
				       S->field->get(S->field)) )
		goto done;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the retrieval of the event description
 * from the object.  The TSEMevent->extract_export() method must have
 * been successfully called before this method will succeed.
 *
 * \param this	A pointer to the object which is to have a field
 *		description extracted.
 *
 * \param field	A pointer to a null-terminated string containing
 *		the name of the field to extract.
 *
 * \return	A boolean value is used to indicate the state of the
 *		fieldt extraction.  A false value indicates the
 *		extraction failed while a true value indicates the
 *		object can be queried for its field values.
 */

static _Bool extract_field(CO(TSEMevent, this), CO(char *, field))

{
	STATE(S);

	_Bool retn = false;


	if ( S->type == TSEM_EVENT_UNKNOWN )
		goto done;

	S->parser->reset(S->parser);
	if ( !S->parser->extract_field(S->parser, S->event, field) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method returns the text value of a key in an extracted field.
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
 * \return	A boolean value is used to indicate the success or failure
 *		of extraction of the text.  A false value indicates an
 *		error was encountered while extracting the text.
 */

static _Bool get_text(CO(TSEMevent, this), CO(char *, key), CO(String, text))

{
	STATE(S);


	if ( S->type == TSEM_EVENT_UNKNOWN )
		return false;

	return S->parser->get_text(S->parser, key, text);
}


/**
 * External public method.
 *
 * This method returns the extraction of an integer value from an
 * extracted field.
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
 * \return	A boolean value is used to indicate the success or failure
 *		of extraction of the text.  A false value indicates an
 *		error was encountered while extracting the text.
 */

static _Bool get_integer(CO(TSEMevent, this), CO(char *, key), \
			 long long int *vp)

{
	STATE(S);


	if ( S->type == TSEM_EVENT_UNKNOWN )
		return false;

	return S->parser->get_integer(S->parser, key, vp);
}


/**
 * Internal private function.
 *
 * This function is a helper function for the ->encode_event method.  This
 * function takes the name of a description in an event field and
 * adds it to the String object in which the output is being built.
 *
 * \param parser	A pointer to the object being used to parse
 *			the event.
 *
 * \param term		A character pointer to the termination string
 *			that is being used to encode the output.
 *
 * \param key		The key value to be encoded.
 *
 * \param str		The object that will be used to extract the
 *			event characteristic.
 *
 * \param output	The object that the encoded characteristic will
 *			be written to.
 *
 * \return		A boolean value is used to indicate the result
 *			of the translation.  A false value indicates a
 *			failure ocurred which a true value indicates
 *			the key/value pair has been successfully added
 *			to the output object.
 */

static _Bool _add_key(CO(TSEMparser, parser), CO(char *, term),
		      CO(char *, key), CO(String, str), CO(String, output))

{
	_Bool retn = false;


	str->reset(str);
	if ( !parser->get_text(parser, key, str) )
		ERR(goto done);
	if ( !output->add_sprintf(output, "%s=%s%s", key, str->get(str), \
				  term) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This function is a helper methodfor the ->encode_event method.
 * This function converts a field from JSON encoded form to
 * Quixote encoded form.
 *
 *
 * \param S		A pointer to the state object that the method
 *			is acting on.
 *
 * \param field		A pointer to a character encoded buffer containing
 *			the name of the field to convert.
 *
 * \param str		The object that will be used to extract the
 *			field.
 *
 * \param output	The object that the encoded characteristic will
 *			be written to.
 *
 * \return		A boolean value is used to indicate the result
 *			of the translation.  A false value indicates a
 *			failure ocurred which a true value indicates
 *			the key/value pair has been successfully added
 *			to the output object.
 */

static _Bool _convert_field(CO(TSEMevent_State, S), CO(char *, field), \
			    CO(String, str), CO(String, output))

{
	_Bool retn = false;

	char *p,
	     in[2];


       if ( !S->parser->extract_field(S->parser, S->event, field) )
	       ERR(goto done);

       str->reset(str);
       if ( !S->parser->get_field(S->parser, str) )
	       ERR(goto done);

       if ( !output->add_sprintf(output, "%s", field) )
	       ERR(goto done);

       p = str->get(str);
       in[1] = '\0';
       while ( *p != '\0' ) {
	       if ( *p == '"' ) {
		       ++p;
		       continue;
	       }
	       if ( (*p == ' ') && (*(p-1) == ':') ) {
		       ++p;
		       continue;
	       }
	       if ( *p == ':' )
		       in[0] = '=';
	       else
		       in[0] = *p;
	       if ( !output->add(output, in) )
		       ERR(goto done);
	       ++p;
       }

       retn = true;


 done:
       return retn;
}


/**
 * External public method.
 *
 * This method encodes a JSON encoded security field description into
 * a Quixote encoded field description that can be interpreted by
 * the EventParser object.
 *
 * \param this	A pointer to the object whose field is to be encoded.
 *
 * \param key	The key that specifies the field that will be encoded.
 *
 * \param str	A pointer to the object that the encoded field will
 *		be placed in.  The encoding is added to the existing
 *		contents of the object so the field can be iteratively
 *		into.
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of the encoding.  A false value indicates an error was
 *		encountered during the encoding while a true value
 *		indicates the supplied str object contains a validly
 *		encoded field.
 */

static _Bool encode_event(CO(TSEMevent, this), CO(String, output))

{
	STATE(S);

	_Bool have_file,
	      retn = false;

	char type[64];

	String str = NULL;


	if ( S->type != TSEM_EVENT_EVENT )
		ERR(goto done);

	/* Stash the type and filename status of the event. */
	INIT(HurdLib, String, str, ERR(goto done));
	if ( !S->parser->get_text(S->parser, "type", str) )
		ERR(goto done);
	if ( (str->size(str) + 1) > sizeof(type) )
		ERR(goto done);
	strcpy(type, str->get(str));

	str->reset(str);
	if ( !S->parser->get_text(S->parser, "filename", str) )
		ERR(goto done);
	have_file = strcmp(str->get(str), "none") != 0;

	if ( S->parser->has_key(S->parser, "pid") ) {
		str->reset(str);
		if ( !S->parser->get_text(S->parser, "pid", str) )
			ERR(goto done);
		if ( !output->add_sprintf(output, "pid{%s} ", str->get(str)) )
			ERR(goto done);
	}

	if ( !output->add(output, "event{") )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "process", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "filename", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "type", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, "} ", "task_id", str, output) )
		ERR(goto done);

	if ( !_convert_field(S, "COE", str, output) )
		ERR(goto done);

	str->reset(str);
	if ( !output->add(output, " ") )
		ERR(goto done);
	if ( strcmp(type, "file_open") == 0 )
		strcpy(type, "file");
	if ( !_convert_field(S, type, str, output) )
		ERR(goto done);

	if ( (strcmp(type, "mmap_file") == 0) && have_file ) {
		str->reset(str);
		if ( !output->add(output, " ") )
			ERR(goto done);
		if ( !_convert_field(S, "file", str, output) )
			ERR(goto done);
	}

       retn = true;


 done:
       memset(type, '\0', sizeof(type));
       WHACK(str);

       return retn;
}
	

/**
 * External public method.
 *
 * This method implements the reset of the TSEMevent object to prepare
 * it for another event description read.  The Buffer object is not
 * reset in order to preserve its size as it is being used as a
 * dynamically sized read buffer.
 *
 * \param this	A pointer to the object which is to bet reset.
 */

static void reset(CO(TSEMevent, this))

{
	STATE(S);

	S->type = TSEM_EVENT_UNKNOWN;

	S->event->reset(S->event);
	S->field->reset(S->field);
	S->parser->reset(S->parser);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TSEMevent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TSEMevent, this))

{
	STATE(S);


	WHACK(S->bufr);
	WHACK(S->event);
	WHACK(S->field);
	WHACK(S->parser);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a TSEMevent object.
 *
 * \return	A pointer to the initialized TSEMevent.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TSEMevent NAAAIM_TSEMevent_Init(void)

{
	Origin root;

	TSEMevent this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TSEMevent);
	retn.state_size   = sizeof(struct NAAAIM_TSEMevent_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TSEMevent_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->bufr, goto fail);
	INIT(HurdLib, String, this->state->event, goto fail);
	INIT(HurdLib, String, this->state->field, goto fail);
	INIT(NAAAIM, TSEMparser, this->state->parser, goto fail);

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->read_event = read_event;
	this->set_event	 = set_event;

	this->extract_export = extract_export;
	this->extract_field  = extract_field;

	this->get_text	    = get_text;
	this->get_integer   = get_integer;

	this->encode_event = encode_event;

	this->reset = reset;
	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->bufr);
	WHACK(this->state->event);
	WHACK(this->state->field);
	WHACK(this->state->parser);

	root->whack(root, this, this->state);
	return NULL;
}

