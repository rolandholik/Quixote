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
#include <errno.h>

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
	{TSEM_EVENT_AGGREGATE,		"aggregate"},
	{TSEM_EVENT_EVENT,		"event"},
	{TSEM_EVENT_ASYNC_EVENT,	"async_event"},
	{TSEM_EVENT_LOG,		"log" },
	{0,				NULL}
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

	/* Number of bytes in buffer. */
	size_t size;

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
	S->size = 0;

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


	S->event->reset(S->event);
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

	char *start,
	     in[1];

	int available;


	if ( ioctl(fd, FIONREAD, &available) != 0 )
		ERR(goto done);

	/* Expand the input buffer to match the input size. */
	in[0] = '\0';
	while ( S->bufr->size(S->bufr) < (available + S->size) )
		S->bufr->add(S->bufr, (void *) in, 1);

	start = (char *) (S->bufr->get(S->bufr) + S->size);
	memset(start, '\0', S->bufr->size(S->bufr) - S->size);

	/* Read the event string and convert the linefeed to a NULL. */
	if ( read(fd, start, available) < 0 )
		ERR(goto done);
	S->size += available;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements fetching an event description string from
 * the input buffer to the event object.
 *
 * \param this	A pointer to the object which is to fetch the event
 *		description.
 *
 * \param more	A pointer to a boolean variable that is used to
 *		indicate that an additional event description is
 *		available in the input queue.
 *
 * \return	A boolean value is used to indicate that an event
 *		has been fetched.  A false value indicates that an
 *		event is present while a true value indicates the
 *		object does not have an event description.
 */

static _Bool fetch_event(CO(TSEMevent, this), _Bool *more)

{
	STATE(S);

	_Bool retn = false;

	char *p,
	     *end,
	     *start = (char *) S->bufr->get(S->bufr);

	size_t amt;


	/* Check for the presence of an event description. */
	if ( (p = strchr(start, '\n')) == NULL ) {
		return false;
	}
	*p = '\0';

	/* Transfer event description to a String object. */
	S->event->reset(S->event);
	if ( !S->event->add(S->event, start) ) {
		*p = '\n';
		goto done;
	}

	/* Move remaining data to beginning of buffer. */
	amt = S->event->size(S->event) + 1;
	S->size -= amt;
	end = start + amt;
	if ( S->size > 0 ) {
		memcpy(S->bufr->get(S->bufr), end, S->size);
		memset(start + S->size, '\0', \
		       S->bufr->size(S->bufr) - S->size);
		if ( strchr(start, '\n') != NULL )
			*more = true;
	}
	else
		*more = false;

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements reading an event description from the
 * kernel export pseudo-file.
 *
 * \param this	A pointer to the object which is to read the event
 *		description.
 *
 * \param fd		The file descriptor that the event is to be read
 *			from.
 *
 * \param have_event	A pointer to a boolean variable used to indicate if
 *			the end of the event stream has been reeached.
 *
 * \return	A boolean value is used to indicate the state of the
 *		read.  A false value indicates the read failed while
 *		a true value indicates the object has a valid event
 *		description.
 */

static _Bool read_export(CO(TSEMevent, this), const int fd, _Bool *have_event)

{
	STATE(S);

	_Bool retn = false;

	char *p,
	     bufr[4096];

	int rc;


	/* Read up to a page size of the event. */
	*have_event = true;
	memset(bufr, '\0', sizeof(bufr));

	rc = read(fd, bufr, sizeof(bufr));
	if ( rc == 0 )
		ERR(goto done);
	if ( rc < 0 ) {
		if ( errno != ENODATA )
			ERR(goto done);

		retn = true;
		*have_event = false;
		goto done;
	}

	/* Null-terminate the value and save it in the String object. */
	if ( (p = strchr(bufr, '\n')) != NULL )
		*p = '\0';

	S->event->reset(S->event);
	if ( !S->event->add(S->event, bufr) )
		ERR(goto done);
	retn = true;


 done:
	if ( retn )
		lseek(fd, 0, SEEK_SET);
	return retn;
}


/**
 * External public method.
 *
 * This method implements returning a pointer to the character buffer
 * containing the ASCII representation of the event.
 *
 * \param this	A pointer to the object which is to fetch the event
 *		description.
 *
 * \return	A character pointer to the event string is returned.
 */

static char * get_event(CO(TSEMevent, this))

{
	STATE(S);

	return S->event->get(S->event);
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
	if ( S->type == TSEM_EVENT_ASYNC_EVENT ) {
		S->field->reset(S->field);
		if ( !S->field->add(S->field, "event") )
			goto done;
	}

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
 * This method implements setting up for the extraction of the event
 * description.  This allows the object to parse a security event
 * description that is output by an internally modeled domain in the
 * trajectory and forensics pseudo-files.
 *
 * \param this	A pointer to the object whose export event is to
 *		be interrogated.
 *
 * \return	A boolean value is used to indicate the status of
 *		the event extraction.  A false value indicates that
 *		an error occurred during the extraction of the event.
 *		A true value indicates the event description was
 *		extracted and the event can undergo further
 *		decoding.
 */

static _Bool extract_event(CO(TSEMevent, this))

{
	STATE(S);

	_Bool retn = true;

	S->parser->reset(S->parser);
	if ( !S->parser->extract_field(S->parser, S->event, "event") )
		ERR(goto done);

	S->type = TSEM_EVENT_EVENT;
	retn = true;


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
 * Internal private function.
 *
 * This function is a helper function for the convert_field method that
 * carries out the copying of a JSON encoded event description into
 * its Quixote encoded equivalent.
 *
 * \param S		A pointer to the state object that the method
 *			is acting on.
 *
 * \param in		The object containing the JSON encoded description.
 *
 * \param out		The object to which the encoded field will be
 *			copied to.
 *
 * \return		A boolean value is used to indicate the result
 *			of the copy.  A false value indicates a
 *			failure ocurred while a true value indicates the
 *			output object has a valid string.
 */

static _Bool _copy_field(CO(String, in), CO(String, out))

{
	_Bool retn = false;

	char *p,
	     str[2];

	p = in->get(in);
	str[1] = '\0';
	while ( *p != '\0' ) {
		if ( *p == '"' ) {
			++p;
			continue;
		}
		if ( (*p == ' ') && (*(p-1) == ':') ) {
			++p;
			continue;
	       }
	       if ( *p == ':' ) {
		       if ( *(p+2) == '{' )
			       break;
		       str[0] = '=';
	       }
	       else
		       str[0] = *p;
	       if ( !out->add(out, str) )
		       ERR(goto done);
	       ++p;
	}

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

	const char *outfield = strcmp(field, "file_open") ? field : "file";


       if ( !S->parser->extract_field(S->parser, S->event, field) )
	       ERR(goto done);

       str->reset(str);
       if ( !S->parser->get_field(S->parser, str) )
	       ERR(goto done);

       if ( !output->add_sprintf(output, "%s", outfield) )
	       ERR(goto done);

       if ( !_copy_field(str, output) )
	       ERR(goto done);
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

	_Bool retn = false;

	char *p,
	     type[64];

	String str = NULL;


	if ( S->type != TSEM_EVENT_EVENT && S->type != TSEM_EVENT_ASYNC_EVENT)
		ERR(goto done);

	/* Stash the type and filename status of the event. */
	INIT(HurdLib, String, str, ERR(goto done));
	if ( !S->parser->get_text(S->parser, "type", str) )
		ERR(goto done);
	if ( (str->size(str) + 1) > sizeof(type) )
		ERR(goto done);
	strcpy(type, str->get(str));

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
	if ( !_add_key(S->parser, ", ", "type", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "ttd", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "p_ttd", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "task_id", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "p_task_id", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, "} ", "ts", str, output) )
		ERR(goto done);

	if ( !_convert_field(S, "COE", str, output) )
		ERR(goto done);

	str->reset(str);
	if ( !output->add(output, " ") )
		ERR(goto done);

	if ( strcmp(type, "mmap_file") == 0 ) {
		if ( !S->parser->extract_field(S->parser, S->event, \
					       "mmap_file") )
			ERR(goto done);

		str->reset(str);
		if ( !S->parser->has_key(S->parser, "file") ) {
			if ( !_convert_field(S, type, str, output) )
				ERR(goto done);
		} else {
			if ( !S->parser->get_field(S->parser, str) )
				ERR(goto done);

			p = strstr(str->get(str), ", \"file\"");
			if ( p == NULL )
				ERR(goto done);
			*p = '\0';

			if ( !output->add(output, "mmap_file") )
				ERR(goto done);
			if ( !_copy_field(str, output) )
				ERR(goto done);

			str->reset(str);
			if ( !S->parser->get_field(S->parser, str) )
				ERR(goto done);

			S->parser->reset(S->parser);
			if ( !S->parser->extract_field(S->parser, str, \
						       "file") )
				ERR(goto done);

			str->reset(str);
			if ( !S->parser->get_field(S->parser, str) )
				ERR(goto done);

			if ( !output->add(output, "} file") )
				ERR(goto done);
			if ( !_copy_field(str, output) )
				ERR(goto done);
		}
	} else if ( strcmp(type, "inode_getattr") == 0 ) {
		if ( !S->parser->extract_field(S->parser, S->event, "file") )
			ERR(goto done);

		str->reset(str);
		if ( !S->parser->get_field(S->parser, str) )
			ERR(goto done);
		if ( !output->add(output, "file") )
			ERR(goto done);
		if ( !_copy_field(str, output) )
			ERR(goto done);
	}
	else {
		if ( !_convert_field(S, type, str, output) )
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
 * This method encodes a JSON encoded security violation description into
 * a Quixote encoded field description that can be interpreted by
 * the EventParser object.
 *
 * \param this	A pointer to the object whose field is to be encoded.
 *
 * \param str	A pointer to the object that the encoded field will
 *		be placed in.
 *
 * \return	A boolean value is used to indicate the success or failure
 *		of the encoding.  A false value indicates an error was
 *		encountered during the encoding while a true value
 *		indicates the supplied str object contains a validly
 *		encoded field.
 */

static _Bool encode_log(CO(TSEMevent, this), CO(String, output))

{
	STATE(S);

	_Bool retn = false;

	String str = NULL;


	if ( S->type != TSEM_EVENT_LOG )
		ERR(goto done);

	INIT(HurdLib, String, str, ERR(goto done));

	output->reset(output);
	if ( !output->add(output, "log{") )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "process", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, ", ", "event", str, output) )
		ERR(goto done);
	if ( !_add_key(S->parser, "}", "action", str, output) )
		ERR(goto done);

	retn = true;


 done:
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
	this->set_event	  = set_event;
	this->read_event  = read_event;
	this->fetch_event = fetch_event;
	this->read_export = read_export;
	this->get_event	  = get_event;

	this->extract_export = extract_export;
	this->extract_event  = extract_event;
	this->extract_field  = extract_field;

	this->get_text	    = get_text;
	this->get_integer   = get_integer;

	this->encode_event = encode_event;
	this->encode_log   = encode_log;

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

