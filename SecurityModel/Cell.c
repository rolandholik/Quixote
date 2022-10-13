/** \file
 * This file contains the implementation of an object which represents
 * a cell (data sync or source) in the Turing event modeling system.
 * The purpose of this object is to consolidate all of the characteristics
 * of a cell for the purposes of computing its value.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "tsem_event.h"

#include "NAAAIM.h"
#include "SHA256.h"
#include "Cell.h"

#if !defined(REG_OK)
#define REG_OK REG_NOERROR
#endif


/* Object state extraction macro. */
#define STATE(var) CO(Cell_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Cell_OBJID)
#error Object identifier not defined.
#endif


/** Variable to indicate the parsing expressions have been compiled. */
static _Bool File_Fields_compiled	   = false;
static _Bool Socket_Create_Fields_compiled = false;

/** Array of field descriptions and compiled regular expressions. */
struct regex_description {
	char *fd;
	regex_t regex;
};

struct regex_description File_Fields[10] = {
	{.fd="file\\{[^}]*\\}"},
	{.fd="uid=([^,]*)"},
	{.fd="gid=([^,]*)"},
	{.fd="mode=([^,]*)"},
	{.fd="name_length=([^,]*)"},
	{.fd="name=([^,]*)"},
	{.fd="s_id=([^,]*)"},
	{.fd="s_uuid=([^,]*)"},
	{.fd="digest=([^}]*)"},
	{.fd=NULL}
};

struct regex_description Socket_Create_Fields[10] = {
	{.fd="socket_create\\{[^}]*\\}"},
	{.fd="family=([^,]*)"},
	{.fd="type=([^,]*)"},
	{.fd="protocol=([^,]*)"},
	{.fd="kern=([^,]*)"},
	{.fd=NULL}
};


/* File characteristics. */
struct file_parameters {
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;

	uint32_t name_length;
	char name[NAAAIM_IDSIZE];

	char s_id[32];
	uint8_t s_uuid[16];

	char digest[NAAAIM_IDSIZE];
};

/* Socket create parameters. */
struct socket_create_parameters {
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint32_t kern;
};


/** Cell private state information. */
struct NAAAIM_Cell_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Type definition for cell contents. */
	enum tsem_event_type type;

	/* File characteristics. */
	struct file_parameters file;

	/* Socket creation parameters. */
	struct socket_create_parameters socket_create;

	/* Measured identity. */
	_Bool measured;
	Sha256 identity;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Cell_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(Cell_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Cell_OBJID;

	S->poisoned = false;

	memset(&S->file, '\0', sizeof(struct file_parameters));

	S->measured = false;
	S->identity = NULL;

	return;
}


/**
 * Internal private function.
 *
 * This method parses a single numeric entry specified by a regular
 * expression and returns the integer value of the field arguement.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
 *
 * \param field	A character pointer to the field which is to be
 *		parsed.
 *
 * \param value	A pointer to the variable which will be loaded with
 *		the parsed value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_field(regex_t *regex, CO(char *, field), uint32_t *value)

{
	_Bool retn = false;

	char match[32];

	long int vl;

	size_t len;

	regmatch_t regmatch[2];


	if ( regexec(regex, field, 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > sizeof(match) )
		ERR(goto done);
	memset(match, '\0', sizeof(match));
	memcpy(match, field + regmatch[1].rm_so, len);

	vl = strtol(match, NULL, 0);
	if ( errno == ERANGE )
		ERR(goto done);
	if ( vl > UINT32_MAX )
		ERR(goto done);

	*value = vl;
	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This method parses a digest field from a cell characteristic field.  A
 * digest field is assumed to have a size equal to the operative
 * identity size.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
 *
 * \param field	A character pointer to the field which is to be
 *		parsed.
 *
 * \param value	A pointer to the character area which the field
 *		will be loaded into.
 *
 * \param fb	A pointer to buffer that the field is to be copied
 *		into.
 *
 * \param size	The length of the digest field to be populated.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_digest(regex_t *regex, CO(char *, field), uint8_t *fb, \
			 size_t size)

{
	_Bool retn = false;

	size_t len;

	regmatch_t regmatch[2];

	Buffer bufr  = NULL,
	       match = NULL;


	if ( regexec(regex, field, 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	INIT(HurdLib, Buffer, match, ERR(goto done));
	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	match->add(match, (unsigned char *) (field + regmatch[1].rm_so), len);
	if ( !match->add(match, (unsigned char *) "\0", 1) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add_hexstring(bufr, (char *) match->get(match)) )
		ERR(goto done);
	if ( bufr->size(bufr) != size )
		ERR(goto done);
	memcpy(fb, bufr->get(bufr), bufr->size(bufr));

	retn = true;


 done:
	WHACK(bufr);
	WHACK(match);

	return retn;
}


/**
 * Internal private function.
 *
 * This method parses a test entry from a cell characteristic field.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
 *
 * \param field A pointer to the field that is to be parsed.
 *
 * \param fb	A pointer to the buffer area which is to be loaded
 *		with the text field.
 *
 * \param fblen	The length of the buffer area which is to be filled.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_text(regex_t *regex, CO(char *, field), uint8_t *fb, \
		       size_t fblen)

{
	_Bool retn = false;

	size_t len;

	regmatch_t regmatch[2];

	Buffer bufr = NULL;


	if ( regexec(regex, field, 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > (fblen - 1) )
		ERR(goto done);


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (unsigned char *) (field + regmatch[1].rm_so), len);
	if ( !bufr->add(bufr, (unsigned char *) "\0", 1) )
		ERR(goto done);
	memcpy(fb, bufr->get(bufr), bufr->size(bufr));

	retn = true;

 done:
	WHACK(bufr);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a file definition
 * of a security state event.
 *
 * \param S	The state information for the Cell that the file information
 *		is being parsed into.
 *
 * \param entry	The object containing the definition of the event that
 *		is to be parsed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool _parse_file(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	unsigned int cnt;

	uint32_t value;

	char *fp;

	regmatch_t regmatch;

	Buffer field = NULL;


	/* Compile the regular expressions once. */
	if ( !File_Fields_compiled ) {
		for (cnt= 0; File_Fields[cnt].fd != NULL; ++cnt) {
			if ( regcomp(&File_Fields[cnt].regex,
				     File_Fields[cnt].fd, REG_EXTENDED) != 0 )
				ERR(goto done);
		}
	}
	File_Fields_compiled = true;


	/* Extract the file field. */
	INIT(HurdLib, Buffer, field, ERR(goto done));

	fp = entry->get(entry);
	if ( regexec(&File_Fields[0].regex, fp, 1, &regmatch, 0) != REG_OK )
		ERR(goto done);

	field->add(field, (unsigned char *) (fp + regmatch.rm_so),
		   regmatch.rm_eo-regmatch.rm_so);
	if ( !field->add(field, (unsigned char *) "\0", 1) )
		ERR(goto done);


	/* Parse field entries. */
	fp = (char *) field->get(field);
	if ( !_get_field(&File_Fields[1].regex, fp, &S->file.uid) )
		ERR(goto done);

	if ( !_get_field(&File_Fields[2].regex, fp, &S->file.gid) )
		ERR(goto done);

	if ( !_get_field(&File_Fields[3].regex, fp, &value) )
		ERR(goto done);
	S->file.mode = value;

	if ( !_get_field(&File_Fields[4].regex, fp, &S->file.name_length) )
		ERR(goto done);

	if ( !_get_digest(&File_Fields[5].regex, fp, \
			  (uint8_t *) S->file.name, NAAAIM_IDSIZE) )
		ERR(goto done);

	if ( !_get_text(&File_Fields[6].regex, fp, (uint8_t *) S->file.s_id, \
			sizeof(S->file.s_id)) )
		ERR(goto done);

	if ( !_get_digest(&File_Fields[7].regex, fp, S->file.s_uuid, \
			  sizeof(S->file.s_uuid)) )
		ERR(goto done);

	if ( !_get_digest(&File_Fields[8].regex, fp, \
			  (uint8_t *) S->file.digest, NAAAIM_IDSIZE) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(field);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a socket creation
 * security event.
 *
 * \param S	The state information for the Cell that the socket creation
 *		information is being parsed into.
 *
 * \param entry	The object containing the definition of the event that
 *		is to be parsed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool _parse_socket_create(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	unsigned int cnt;

	char *fp;

	regmatch_t regmatch;

	Buffer field = NULL;


	/* Compile the regular expressions once. */
	if ( !Socket_Create_Fields_compiled ) {
		for (cnt= 0; Socket_Create_Fields[cnt].fd != NULL; ++cnt) {
			if ( regcomp(&Socket_Create_Fields[cnt].regex,
				     Socket_Create_Fields[cnt].fd,
				     REG_EXTENDED) != 0 )
				ERR(goto done);
		}
	}
	Socket_Create_Fields_compiled = true;


	/* Extract socket_create parameters. */
	INIT(HurdLib, Buffer, field, ERR(goto done));

	fp = entry->get(entry);
	if ( regexec(&Socket_Create_Fields[0].regex, fp, 1, &regmatch, 0) != \
	     REG_OK )
		ERR(goto done);

	field->add(field, (unsigned char *) (fp + regmatch.rm_so),
		   regmatch.rm_eo-regmatch.rm_so);
	if ( !field->add(field, (unsigned char *) "\0", 1) )
		ERR(goto done);


	/* Parse socket create parameters. */
	fp = (char *) field->get(field);
	if ( !_get_field(&Socket_Create_Fields[1].regex, fp,
			 &S->socket_create.family) )
		ERR(goto done);

	if ( !_get_field(&Socket_Create_Fields[2].regex, fp,
			 &S->socket_create.type) )
		ERR(goto done);

	if ( !_get_field(&Socket_Create_Fields[3].regex, fp,
			 &S->socket_create.protocol) )
		ERR(goto done);

	if ( !_get_field(&Socket_Create_Fields[4].regex, fp,
			 &S->socket_create.kern) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(field);

	return retn;
}


/**
 * External public method.
 *
 * This method implements parsing of a security state event for the
 * characteristics of a cell
 *
 * \param this	A pointer to the cell whose trajectory entry
 *		is to be parsed.
 *
 * \param entry	A pointer to the object which contains the trajectory
 *		step point which is to be parsed.
 *
 * \parm type	The type of the cell
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(Cell, this), CO(String, entry),
		   enum tsem_event_type type)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and caller state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( entry->poisoned(entry) )
		ERR(goto done);


	/* Select the type of parsing based on the event type. */
	S->type = type;

	switch ( S->type ) {
		case TSEM_FILE_OPEN:
		case TSEM_MMAP_FILE:
			if ( !_parse_file(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_CREATE:
			if ( !_parse_socket_create(S, entry) )
				ERR(goto done);
			break;

		default:
			break;
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements computing of the measurement of a cell that
 * incorporates a file description.
 *
 * \param S	The state information of the object whose file measurement
 *		is to be measured.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool _measure_file(CO(Cell_State, S))

{
	_Bool retn = false;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (void *) &S->file.uid, sizeof(S->file.uid));
	bufr->add(bufr, (void *) &S->file.gid, sizeof(S->file.gid));
	bufr->add(bufr, (void *) &S->file.mode, sizeof(S->file.mode));
	bufr->add(bufr, (void *) &S->file.name_length, \
		  sizeof(S->file.name_length));
	bufr->add(bufr, (void *) S->file.name, sizeof(S->file.name));
	bufr->add(bufr, (void *) S->file.s_id, sizeof(S->file.s_id));
	bufr->add(bufr, (void *) S->file.s_uuid, sizeof(S->file.s_uuid));
	if ( !bufr->add(bufr, (void *) S->file.digest, \
			sizeof(S->file.digest)) )
		ERR(goto done);

	if ( !S->identity->add(S->identity, bufr) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements computing of the measurement of a socket
 * creation cell.
 *
 * \param S	The state information of the object whose socket creation
 *		measurement is to be generated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool _measure_socket_create(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) &S->socket_create.family;
	size = sizeof(S->socket_create.family);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->socket_create.type;
	size = sizeof(S->socket_create.type);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->socket_create.protocol;
	size = sizeof(S->socket_create.protocol);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->socket_create.kern;
	size = sizeof(S->socket_create.kern);
	if ( !bufr->add(bufr, p, size) )
		ERR(goto done);

	if ( !S->identity->add(S->identity, bufr) )
		ERR(goto done);
	retn = true;

 done:
	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method implements computing of the measurement of a cell.
 * This involves the computation of the digest over the
 * structure which defines the characteristics of the cell.
 *
 * \param this	A pointer to the object which is to be measured.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool measure(CO(Cell, this))

{
	STATE(S);

	_Bool retn = false;


	/* Object verifications. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->measured )
		ERR(goto done);


	switch ( S->type ) {
		case TSEM_FILE_OPEN:
		case TSEM_MMAP_FILE:
			retn = _measure_file(S);
			break;

		case TSEM_SOCKET_CREATE:
			retn =_measure_socket_create(S);
			break;

		default:
			break;
	}

	if ( retn ) {
		if ( !S->identity->compute(S->identity) )
			ERR(goto done);
		S->measured = true;
	}


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor function for retrieving the
 * measurement of a cell object.  It is considered to be a terminal
 * error for this method function to be called without having previously
 * called the ->measurement method.
 *
 * \param this	A pointer to the object whose measurement is to be
 *		retrieved.
 *
 * \param bufr	The object which the measurement is to be loaded into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the supplied object has a valid measurement copied into
 *		it.  A false value indicates the object does not have
 *		a valid measurement and that the current object is now
 *		in a poisoned state.  A true value indicates the
 *		supplied object has a valid copy of this object's
 *		measurement.
 */

static _Bool get_measurement(CO(Cell, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( !S->measured )
		ERR(goto done);

	if ( !bufr->add_Buffer(bufr, S->identity->get_Buffer(S->identity)) )
		ERR(goto done);
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor function for retrieving the
 * pseudonym value of a cell object.  This value is composed of the
 * followin hash:
 *
 * pseudonym = SHA256(NAME_LENGTH || NAME)
 *
 * Where:
 *	NAME_LENGTH: The length of the name, not including a null byte
 *		     as a 32-bit unsigned integer (uint32_t).
 *
 *	NAME:	     The characters comprising the name of the
 *		     data sync/source that may have a measurement value
 *		     associated with it.
 *
 * \param this	A pointer to the object whose pseudonym is to be
 *		retrieved.
 *
 * \param bufr The object which the pseudonym value is to be loaded
 *	       into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the supplied object has a pseudonym value copied into
 *		it.  A false value indicates the object does not have
 *		a valid pseudonym and that the current object is now
 *		in a poisoned state.  A true value indicates the
 *		supplied object has a valid copy of this object's
 *		pseudonym.
 */

static _Bool get_pseudonym(CO(Cell, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	Buffer b;

	Sha256 pseudonym = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Collect the pseduonym components. */
	bufr->reset(bufr);

	bufr->add(bufr, (void *) &S->file.name_length, \
		  sizeof(S->file.name_length));
	if ( !bufr->add(bufr, (void *) S->file.name, sizeof(S->file.name)) )
		ERR(goto done);


	/* Hash the pseudonym components. */
	INIT(NAAAIM, Sha256, pseudonym, ERR(goto done));

	if ( !pseudonym->add(pseudonym, bufr) )
		ERR(goto done);
	if ( !pseudonym->compute(pseudonym) )
		ERR(goto done);
	b = pseudonym->get_Buffer(pseudonym);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, b) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(pseudonym);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the setting of the digest value of the
 * event to a given value.
 *
 * \param this		A pointer to the Cell whose digest value is
 *			to be set.

 * \param digest	The object containing the value which the
 *	       		digest value is to be set to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the digest value was successfully set.  A true value
 *		indicates it was set while a false value indicates
 *		the digest value is in potentially indeterminate state.
 */

static _Bool set_digest(CO(Cell, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status and argument. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->size(bufr) != sizeof(S->file.digest) )
		ERR(goto done);


	/* Update the digest value. */
	memcpy(S->file.digest, bufr->get(bufr), sizeof(S->file.digest));

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements the output of the characteristics of a cell
 * that has a file definition.
 *
 * \param S	A pointer to the state of the object being output.
 *
 * \parm str	The object into which the formatted output is to
 *		be placed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the output was properly formatted.  A true value
 *		indicates formatting was successful while a false
 *		value indicates an error occurred.
 */

static _Bool _format_file(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;

	unsigned int lp;


	/* Write the formatted string to the String object. */
	if ( !str->add_sprintf(str, "file{uid=%lu, gid=%lu, mode=0%lo, name_length=%lu, name=",					       \
			(unsigned long int) S->file.uid,	\
			(unsigned long int) S->file.gid,	\
			(unsigned long int) S->file.mode,	\
			       (unsigned long int) S->file.name_length) )
		ERR(goto done);


	/* name=%*phN, s_id=%s */
	for (lp= 0; lp < sizeof(S->file.name); ++lp) {
		if ( !str->add_sprintf(str, "%02x", \
				       (unsigned char) S->file.name[lp]) )
		     ERR(goto done);
	}

	/* , s_uuid=%*phN */
	if ( !str->add_sprintf(str, ", s_id=%s, s_uuid=", S->file.s_id) )
		ERR(goto done);

	for (lp= 0; lp < sizeof(S->file.s_uuid); ++lp) {
		if ( !str->add_sprintf(str, "%02x",
				       (unsigned char) S->file.s_uuid[lp]) )
		     ERR(goto done);
	}

	/* , digest=%*phN */
	if ( !str->add_sprintf(str, "%s", ", digest=") )
		ERR(goto done);

	for (lp= 0; lp < sizeof(S->file.digest); ++lp) {
		if ( !str->add_sprintf(str, "%02x",
				       (unsigned char) S->file.digest[lp]) )
		     ERR(goto done);
	}

	/* } */
	if ( !str->add_sprintf(str, "}") )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements the output of the characteristics of a cell
 * for a socket creation security event.
 *
 * \param S	A pointer to the state of the object being output.
 *
 * \parm str	The object into which the formatted output is to
 *		be placed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the output was properly formatted.  A true value
 *		indicates formatting was successful while a false
 *		value indicates an error occurred.
 */

static _Bool _format_socket_create(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;


	if ( !str->add_sprintf(str, "socket_create{family=%u, type=%u, " \
			       "protocol=%u, kern=%u}",
			       S->socket_create.family,
			       S->socket_create.type,
			       S->socket_create.protocol,
			       S->socket_create.kern) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the generation of an ASCII formatted
 * representation of the characteristics of a call.  The string
 * generated is in the same format that is interpreted by the
 * ->parse method.
 *
 * \param this	A pointer to the object containing the characteristics
 *		which are to be formatted.
 *
 * \param event	The object into which the formatted string is to
 *		be copied.
 */

static _Bool format(CO(Cell, this), CO(String, event))
{
	STATE(S);

	_Bool retn = false;


	switch ( S->type ) {
		case TSEM_FILE_OPEN:
		case TSEM_MMAP_FILE:
			retn = _format_file(S, event);
			break;

		case TSEM_SOCKET_CREATE:
			retn = _format_socket_create(S, event);
			break;

		default:
			break;
	}

	return retn;
}


/**
 * External public method.
 *
 * This method implements the reset of the Cell object to a state
 * which would allow the generation of a new set of cell characteritics.
 *
 * \param this	A pointer to the object which is to be reset.
 */

static void reset(CO(Cell, this))

{
	STATE(S);

	S->poisoned = false;
	S->measured = false;

	memset(&S->file, '\0', sizeof(struct file_parameters));

	S->identity->reset(S->identity);

	return;
}


/**
 * Internal public method.
 *
 * This method implements output of the characteristics of a cell
 * that has a file definition.
 *
 * \param S	A pointer to the state of the object being output.
 */

void _dump_file(CO(Cell_State, S))

{
	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	fprintf(stdout, "uid:  %lu\n", (unsigned long int) S->file.uid);
	fprintf(stdout, "gid:  %lu\n", (unsigned long int) S->file.gid);
	fprintf(stdout, "mode: 0%lo\n",(unsigned long int) S->file.mode);
	fprintf(stdout, "name length: %lu\n", \
		(unsigned long int) S->file.name_length);

	if ( !bufr->add(bufr, (unsigned char *) S->file.name, \
			sizeof(S->file.name)) )
		ERR(goto done);
	fputs("name digest: ", stdout);
	bufr->print(bufr);
	bufr->reset(bufr);

	fprintf(stdout, "s_id:   %s\n", S->file.s_id);

	if ( !bufr->add(bufr, (unsigned char *) S->file.s_uuid,
			sizeof(S->file.s_uuid)) )
		ERR(goto done);
	fputs("s_uuid: ", stdout);
	bufr->print(bufr);
	bufr->reset(bufr);

	if ( !bufr->add(bufr, (unsigned char *) S->file.digest,
			sizeof(S->file.digest)) )
		ERR(goto done);
	fputs("subj digest: ", stdout);
	bufr->print(bufr);

	fputs("measurement: ", stdout);
	S->identity->print(S->identity);


 done:
	WHACK(bufr);

	return;
}


/**
 * Internal public method.
 *
 * This method implements output of the characteristics of a cell
 * that has a file definition.
 *
 * \param S	A pointer to the state of the object being output.
 */

void _dump_socket_create(CO(Cell_State, S))

{
	fprintf(stdout, "family: %u\n", S->socket_create.family);
	fprintf(stdout, "type:   %u\n", S->socket_create.type);
	fprintf(stdout, "type:   %u\n", S->socket_create.protocol);
	fprintf(stdout, "kern:   %u\n", S->socket_create.kern);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the characteristis of the cell
 * represented by the object.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump(CO(Cell, this))

{
	STATE(S);


	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);

	switch ( S->type ) {
		case TSEM_FILE_OPEN:
		case TSEM_MMAP_FILE:
			_dump_file(S);
			break;

		case TSEM_SOCKET_CREATE:
			_dump_socket_create(S);
			break;

		default:
			break;
	}


	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Cell object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Cell, this))

{
	STATE(S);

	WHACK(S->identity);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Cell object.
 *
 * \return	A pointer to the initialized Cell.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Cell NAAAIM_Cell_Init(void)

{
	Origin root;

	Cell this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Cell);
	retn.state_size   = sizeof(struct NAAAIM_Cell_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Cell_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(NAAAIM, Sha256, this->state->identity, ERR(goto fail));

	/* Method initialization. */
	this->parse		    = parse;
	this->measure		    = measure;
	this->get_measurement	    = get_measurement;

	this->get_pseudonym = get_pseudonym;

	this->set_digest = set_digest;

	this->format = format;
	this->reset  = reset;
	this->dump   = dump;
	this->whack  = whack;

	return this;

fail:
	WHACK(this->state->identity);

	root->whack(root, this, this->state);
	return NULL;
}
