/** \file
 * This file contains the implementation of an object which represents
 * a CELL (data sync or source) in Trusted Security Event Modeling system.
 * The purpose of this object is to consolidate all of the characteristics
 * of a CELL for the purposes of computing its value.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define AF_UNIX	 1
#define AF_INET	 2
#define AF_INET6 10

#define UNIX_PATH_MAX 108


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "tsem_event.h"

#include "NAAAIM.h"
#include "SHA256.h"
#include "EventParser.h"
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


/** Cell value for a generic security event. */
const char zero_message[NAAAIM_IDSIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};


/* File characteristics. */
struct file_parameters {
	uint32_t flags;

	uint32_t uid;
	uint32_t gid;
	uint16_t mode;

	String name;

	uint32_t s_magic;
	char s_id[32];
	uint8_t s_uuid[16];

	char digest[NAAAIM_IDSIZE];
};

/* File mmap parameters. */
struct mmap_file_parameters {
	uint32_t anonymous;
	uint32_t reqprot;
	uint32_t prot;
	uint32_t flags;
};

/* Socket create parameters. */
struct socket_create_parameters {
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint32_t kern;
};

/* Socket connect parameters. */
struct socket_connect_parameters {
	uint16_t family;
	uint16_t port;
	uint32_t flow;
	uint32_t scope;
	union {
		uint32_t ipv4_addr;
		uint8_t ipv6_addr[16];
		char unix_addr[UNIX_PATH_MAX + 1];
		uint8_t addr[32];
	} u;
};

/* Socket accept parameters. */
struct socket_accept_parameters {
	uint16_t family;
	uint16_t type;
	uint16_t port;
	union {
		uint32_t ipv4_addr;
		uint8_t ipv6_addr[16];
		char unix_addr[UNIX_PATH_MAX + 1];
		uint8_t addr[32];
	} u;
};

/* Task kill parameters. */
struct task_kill_parameters {
	uint32_t cross_model;
	uint32_t signal;
	uint8_t task_id[NAAAIM_IDSIZE];
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

	/* Event type definitions. */
	enum tsem_event_type type;

	/* Generic event description .*/
	String event;

	/* File characteristics. */
	struct file_parameters file;

	/* Memory map characteristics. */
	struct mmap_file_parameters mmap_file;

	/* Socket creation parameters. */
	struct socket_create_parameters socket_create;

	/* Socket connection parameters. */
	struct socket_connect_parameters socket_connect;

	/* Socket accept parameters. */
	struct socket_accept_parameters socket_accept;

	/* Task kill connection parameters. */
	struct task_kill_parameters task_kill;

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
	S->event    = NULL;
	S->identity = NULL;

	return;
}


/**
 * Internal private function.
 *
 * This method extracts a single numeric value from the COE description.
 *
 * \param parser	The parser object used to extract the field
 *			description.
 *
 * \param field		The description of the field parameter to extract.
 *
 * \param value		A pointer to the variable which will be loaded
 *			with the parsed value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of extraction of the value.  A false value is
 *		used to indicate a failure occurred during the
 *		extraction.  A true value indicates the value has
 *		been successfully extracted and contains a legitimate
 *		value.
 */

static _Bool _get_field(CO(EventParser, parser), CO(char *, field), \
			uint32_t *value)

{
	_Bool retn = false;

	long long int vl;


	if ( !parser->get_integer(parser, field, &vl) )
		ERR(goto done);
	if ( (unsigned long long int) vl > UINT32_MAX )
		ERR(goto done);

	*value = (uint32_t) vl;
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
 * \param parser	The parser object used to extract the field
 *			description.
 *
 * \param field		A character pointer to the characteristic that
 *			is to be parsed.
 *
 * \param fb		A pointer to buffer that the field is to be
 *			copied into.
 *
 * \param size		The length of the digest field to be populated.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the characteristic extraction.  A false value
 *		is used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_digest(CO(EventParser, parser), CO(char *, field),
			 uint8_t *fb, size_t size)

{
	_Bool retn = false;

	Buffer bufr  = NULL;

	String match = NULL;


	/* Get the ASCII hexadecimal value of the field itself. */
	INIT(HurdLib, String, match, ERR(goto done));
	if ( !parser->get_text(parser, field, match) )
		ERR(goto done);

	/* Convert the hexadecimal value to the binary value. */
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
 * This method parses a text value from a cell characteristic field.
 *
 * \param parser	The parser object used to extract the field
 *			description.
 *
 * \param field		A pointer to the field that is to be parsed.
 *
 * \param fb		A pointer to the buffer area which is to be
 *			loaded with the text field.
 *
 * \param fblen		The length of the buffer area which is to be
 *			filled.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the field extraction.  A false value is
 *		used to indicate a failure occurred during the field
 *		entry extraction.  A true value indicates the
 *		field has been successfully extracted and the value
 *		variable contains a legitimate value.
 */

static _Bool _get_text(CO(EventParser, parser), CO(char *, field), \
		       uint8_t *fb, size_t fblen)

{
	_Bool retn = false;

	String match = NULL;


	/* Get the field itself. */
	INIT(HurdLib, String, match, ERR(goto done));
	if ( !parser->get_text(parser, field, match) )
		ERR(goto done);

	/* Copy it to the destination. */
	if ( (match->size(match) + 1) > fblen )
		ERR(goto done);
	memcpy(fb, match->get(match), match->size(match) + 1);
	retn = true;


 done:
	WHACK(match);

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

	uint32_t value;

	EventParser parser = NULL;


	/* Extract the file field. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "file") )
		ERR(goto done);

	/* Parse field entries. */
	if ( !_get_field(parser, "flags", &value) )
		ERR(goto done);
	S->file.flags = value;

	if ( !_get_field(parser, "uid", &value) )
		ERR(goto done);
	S->file.uid = value;

	if ( !_get_field(parser, "gid", &value) )
		ERR(goto done);
	S->file.gid = value;

	if ( !_get_field(parser, "mode", &value) )
		ERR(goto done);
	S->file.mode = value;

	if ( !parser->get_text(parser, "path", S->file.name) )
		ERR(goto done);

	if ( !_get_field(parser, "s_magic", &value) )
		ERR(goto done);
	S->file.s_magic = value;

	if ( !_get_text(parser, "s_id", (uint8_t *) S->file.s_id, \
			sizeof(S->file.s_id)) )
		ERR(goto done);

	if ( !_get_digest(parser, "s_uuid", S->file.s_uuid, \
			  sizeof(S->file.s_uuid)) )
		ERR(goto done);

	if ( !_get_digest(parser, "digest", (uint8_t *) S->file.digest, \
			  NAAAIM_IDSIZE) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a memory
 * mapping security event.
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

static _Bool _parse_mmap_file(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	EventParser parser = NULL;


	/* Extract the field. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "mmap_file") )
		ERR(goto done);


	/* Parse field entries. */
	if ( !_get_field(parser, "type", &S->mmap_file.anonymous) )
		ERR(goto done);

	if ( !_get_field(parser, "reqprot", &S->mmap_file.reqprot) )
		ERR(goto done);

	if ( !_get_field(parser, "prot", &S->mmap_file.prot) )
		ERR(goto done);

	if ( !_get_field(parser, "flags", &S->mmap_file.flags) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(parser);

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

	EventParser parser = NULL;


	/* Extract the field itself. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "socket_create") )
		ERR(goto done);

	/* Parse socket create parameters. */
	if ( !_get_field(parser, "family", &S->socket_create.family) )
		ERR(goto done);

	if ( !_get_field(parser, "type", &S->socket_create.type) )
		ERR(goto done);

	if ( !_get_field(parser, "protocol", &S->socket_create.protocol) )
		ERR(goto done);

	if ( !_get_field(parser, "kern", &S->socket_create.kern) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of either s
 * socket connect or socket bind event.
 *
 * \param S	The state information for the Cell that the socket connect
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

static _Bool _parse_socket(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	unsigned int cnt;

	uint8_t *p;

	uint32_t value;

	String str = NULL;

	EventParser parser = NULL;

	static char *type[2] = {
		"socket_connect",
		"socket_bind"
	};


	/* Extract the field itself. */
	switch ( S->type ) {
		case TSEM_SOCKET_CONNECT:
			value = 0;
			break;
		case TSEM_SOCKET_BIND:
			value = 1;
			break;
		default:
			ERR(goto done);
			break;

	}
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, type[value]) )
		ERR(goto done);


	/* Parse socket family. */
	if ( !_get_field(parser, "family", &value) )
		ERR(goto done);
	S->socket_connect.family = value;

	/* Parse port number. */
	if ( (S->socket_connect.family == AF_INET) ||
	     (S->socket_connect.family == AF_INET6) ) {
		if ( !_get_field(parser, "port", &value) )
			ERR(goto done);
		S->socket_connect.port = value;
	}

	/* Extract protocol specific fields. */
	switch ( S->socket_connect.family ) {
		case AF_INET:
			if ( !_get_field(parser, "addr", &value) )
				ERR(goto done);
			S->socket_connect.u.ipv4_addr = value;
			break;

		case AF_INET6:
			if ( !_get_field(parser, "flow", &value) )
				ERR(goto done);
			S->socket_connect.flow = value;

			if ( !_get_field(parser, "scope", &value) )
				ERR(goto done);
			S->socket_connect.scope = value;

			p = S->socket_connect.u.ipv6_addr;
			cnt = sizeof(S->socket_connect.u.ipv6_addr);
			if ( !_get_digest(parser, "addr", p, cnt) )
				ERR(goto done);
			break;

		case AF_UNIX:
			cnt = sizeof(S->socket_connect.u.unix_addr);
			memset(S->socket_connect.u.unix_addr, '\0', cnt);

			INIT(HurdLib, String, str, ERR(goto done));
			if ( !parser->get_text(parser, "addr" ,str) )
				ERR(goto done);
			if ( str->size(str) >= cnt )
				ERR(goto done);

			memcpy(S->socket_connect.u.unix_addr, str->get(str), \
			       str->size(str));
			break;

		default:
			p = S->socket_connect.u.addr;
			cnt = sizeof(S->socket_connect.u.addr);
			if ( !_get_digest(parser, "addr", p, cnt) )
				ERR(goto done);
			break;
	}

	retn = true;


 done:
	WHACK(str);
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a socket accept
 * security event.
 *
 * \param S	The state information for the Cell that the socket accept
 *		parameters are being parsed into.
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

static _Bool _parse_socket_accept(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	uint8_t *p;

	uint32_t value;

	unsigned int cnt;

	String str = NULL;

	EventParser parser = NULL;


	/* Compile the regular expressions once. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "socket_accept") )
		ERR(goto done);

	/* Parse socket accept parameters. */
	if ( !_get_field(parser, "family", &value) )
		ERR(goto done);
	S->socket_accept.family = value;

	if ( !_get_field(parser, "type", &value) )
		ERR(goto done);
	S->socket_accept.type = value;

	if ( !_get_field(parser, "port", &value) )
		ERR(goto done);
	S->socket_accept.port = value;


	/* Extract protocol specific fields. */
	switch ( S->socket_accept.family ) {
		case AF_INET:
			if ( !_get_field(parser, "addr", &value) )
				ERR(goto done);
			S->socket_accept.u.ipv4_addr = value;
			break;

		case AF_INET6:
			p = S->socket_accept.u.ipv6_addr;
			cnt = sizeof(S->socket_accept.u.ipv6_addr);
			if ( !_get_digest(parser, "addr", p, cnt) )
				ERR(goto done);
			break;

		case AF_UNIX:
			cnt = sizeof(S->socket_accept.u.unix_addr);
			memset(S->socket_accept.u.unix_addr, '\0', cnt);

			INIT(HurdLib, String, str, ERR(goto done));
			if ( !parser->get_text(parser, "addr" ,str) )
				ERR(goto done);
			if ( str->size(str) >= cnt )
				ERR(goto done);

			memcpy(S->socket_accept.u.unix_addr, str->get(str), \
			       str->size(str));
			break;

		default:
			p = S->socket_accept.u.addr;
			cnt = sizeof(S->socket_accept.u.addr);
			if ( !_get_digest(parser, "addr", p, cnt) )
				ERR(goto done);
			break;
	}

	retn = true;


 done:
	WHACK(str);
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a task_kill
 * security event.
 *
 * \param S	The state information for the Cell that the task_kill
 *		parameters are being parsed into.
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

static _Bool _parse_task_kill(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	EventParser parser = NULL;


	/* Extract task_kill event. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "task_kill") )
		ERR(goto done);

	/* Parse task_kill parameters. */
	if ( !_get_field(parser, "cross", &S->task_kill.cross_model) )
		ERR(goto done);

	if ( !_get_field(parser, "signal", &S->task_kill.signal) )
		ERR(goto done);

	if ( !_get_digest(parser, "target", S->task_kill.task_id, \
			  NAAAIM_IDSIZE) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a generic
 * security event.
 *
 * \param S	The state information for the Cell that the generic
 *		parameters are being parsed into.
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

static _Bool _parse_generic_event(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	EventParser parser = NULL;


	/* Extract the generic event. */
	INIT(NAAAIM, EventParser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "generic_event") )
		ERR(goto done);

	/* Parse the generic event type parameter. */
	if ( !parser->get_text(parser, "type", S->event) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(parser);

	return retn;
}


/**
 * External public method.
 *
 * This method implements parsing of a security state event for the
 * characteristics of a cell
 *
 * \param this		A pointer to the cell whose trajectory entry
 *			is to be parsed.
 *
 * \param entry		A pointer to the object which contains the
 *			trajectory step point which is to be parsed.
 *
 * \param type		The type of the socket cell being parsed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(Cell, this), CO(String, entry), \
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
			if ( !_parse_file(S, entry) )
				ERR(goto done);
			break;

		case TSEM_MMAP_FILE:
			if ( !_parse_mmap_file(S, entry) )
				ERR(goto done);
			if ( !S->mmap_file.anonymous ) {
				if ( !_parse_file(S, entry) )
					ERR(goto done);
			}
			break;

		case TSEM_SOCKET_CREATE:
			if ( !_parse_socket_create(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
			if ( !_parse_socket(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_ACCEPT:
			if ( !_parse_socket_accept(S, entry) )
				ERR(goto done);
			break;

		case TSEM_TASK_KILL:
			if ( !_parse_task_kill(S, entry) )
				ERR(goto done);
			break;

		case TSEM_GENERIC_EVENT:
			if ( !_parse_generic_event(S, entry) )
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

	uint32_t name_length;

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;


	/* Compute digest of filename */
	name_length = S->file.name->size(S->file.name);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) S->file.name->get(S->file.name), \
			name_length) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	b = sha256->get_Buffer(sha256);

	/* Add the file characteristics. */
	bufr->reset(bufr);
	bufr->add(bufr, (void *) &S->file.flags, sizeof(S->file.flags));
	bufr->add(bufr, (void *) &S->file.uid, sizeof(S->file.uid));
	bufr->add(bufr, (void *) &S->file.gid, sizeof(S->file.gid));
	bufr->add(bufr, (void *) &S->file.mode, sizeof(S->file.mode));
	bufr->add(bufr, (void *) &name_length, sizeof(name_length));
	bufr->add(bufr, (void *) b->get(b), b->size(b));
	bufr->add(bufr, (void *) &S->file.s_magic, sizeof(S->file.s_magic));
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
	WHACK(sha256);

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements adding the parameters of a memory mapping
 * event to the measurement of the cell.
 *
 * \param S	The state information of the object whose memory
 *		mapping parameters are to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the addition of the parameters has succeeded.  A false
 *		value indicates failure while a true value indicates
 *		success.
 */

static _Bool _measure_mmap_file(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) &S->mmap_file.reqprot;
	size = sizeof(S->mmap_file.reqprot);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->mmap_file.prot;
	size = sizeof(S->mmap_file.prot);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->mmap_file.flags;
	size = sizeof(S->mmap_file.flags);
	bufr->add(bufr, p, size);

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
 * Internal private method.
 *
 * This method implements computing of the measurement of a socket
 * connect cell.
 *
 * \param S	The state information of the object whose socket connect
 *		measurement is to be generated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool _measure_socket_connect(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) &S->socket_connect.family;
	size = sizeof(S->socket_connect.family);
	bufr->add(bufr, p, size);

	if ( (S->socket_connect.family == AF_INET) ||
	     (S->socket_connect.family == AF_INET6) ) {
			p = (unsigned char *) &S->socket_connect.port;
			size = sizeof(S->socket_connect.port);
			bufr->add(bufr, p, size);
	}

	switch ( S->socket_connect.family ) {
		case AF_INET:
			p = (unsigned char *) &S->socket_connect.u.ipv4_addr;
			size = sizeof(S->socket_connect.u.ipv4_addr);
			bufr->add(bufr, p, size);
			break;

		case AF_INET6:
			p = (unsigned char *) &S->socket_connect.u.ipv6_addr;
			size = sizeof(S->socket_connect.u.ipv6_addr);
			bufr->add(bufr, p, size);

			p = (unsigned char *) &S->socket_connect.flow;
			size = sizeof(S->socket_connect.flow);
			bufr->add(bufr, p, size);

			p = (unsigned char *) &S->socket_connect.scope;
			size = sizeof(S->socket_connect.scope);
			bufr->add(bufr, p, size);
			break;

		case AF_UNIX:
			p = (unsigned char *) S->socket_connect.u.unix_addr;
			size = strlen(S->socket_connect.u.unix_addr);
			bufr->add(bufr, p, size);
			break;

		default:
			p = (unsigned char *) S->socket_connect.u.addr;
			size = sizeof(p);
			bufr->add(bufr, p, size);
			break;
	}

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
 * accept cell.
 *
 * \param S	The state information of the object whose socket accept
 *		measurement is to be generated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool _measure_socket_accept(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) &S->socket_accept.family;
	size = sizeof(S->socket_accept.family);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->socket_accept.type;
	size = sizeof(S->socket_accept.port);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->socket_accept.port;
	size = sizeof(S->socket_accept.port);
	bufr->add(bufr, p, size);


	switch ( S->socket_accept.family ) {
		case AF_INET:
			p = (unsigned char *) &S->socket_accept.u.ipv4_addr;
			size = sizeof(S->socket_accept.u.ipv4_addr);
			bufr->add(bufr, p, size);
			break;

		case AF_INET6:
			p = (unsigned char *) &S->socket_accept.u.ipv6_addr;
			size = sizeof(S->socket_accept.u.ipv6_addr);
			bufr->add(bufr, p, size);
			break;

		case AF_UNIX:
			p = (unsigned char *) S->socket_accept.u.unix_addr;
			size = strlen(S->socket_accept.u.unix_addr);
			bufr->add(bufr, p, size);
			break;

		default:
			p = (unsigned char *) S->socket_accept.u.addr;
			size = sizeof(S->socket_accept.u.addr);
			bufr->add(bufr, p, size);
			break;
	}

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
 * This method implements adding the parameters of a task kill
 * event to the measurement of the cell.
 *
 * \param S	The state information of the object whose task kill
 *		parameters are to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the addition of the parameters has succeeded.  A false
 *		value indicates failure while a true value indicates
 *		success.
 */

static _Bool _measure_task_kill(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) &S->task_kill.cross_model;
	size = sizeof(S->task_kill.cross_model);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->task_kill.signal;
	size = sizeof(S->task_kill.signal);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &S->task_kill.task_id;
	size = sizeof(S->task_kill.task_id);
	bufr->add(bufr, p, size);

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
 * This method implements adding the parameters of a generic security
 * event to the measurement of the cell.
 *
 * \param S	The state information of the object whose generic security
 *		parameters are to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the addition of the parameters has succeeded.  A false
 *		value indicates failure while a true value indicates
 *		success.
 */

static _Bool _measure_generic_event(CO(Cell_State, S))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	p = (unsigned char *) S->event->get(S->event);
	size = S->event->size(S->event);
	bufr->add(bufr, p, size);

	p = (unsigned char *) zero_message;
	size = sizeof(zero_message);
	bufr->add(bufr, p, size);

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
			retn = _measure_file(S);
			break;

		case TSEM_MMAP_FILE:
			retn = _measure_mmap_file(S);
			if ( !S->mmap_file.anonymous )
				retn = _measure_file(S);
			break;

		case TSEM_SOCKET_CREATE:
			retn =_measure_socket_create(S);
			break;

		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
			retn = _measure_socket_connect(S);
			break;

		case TSEM_SOCKET_ACCEPT:
			retn = _measure_socket_accept(S);
			break;

		case TSEM_TASK_KILL:
			retn = _measure_task_kill(S);
			break;

		case TSEM_GENERIC_EVENT:
			retn = _measure_generic_event(S);
			break;

		default:
			break;
	}

	if ( retn ) {
		if ( !S->identity->compute(S->identity) )
			ERR(goto done);
		S->measured = true;
	}
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

	uint32_t size;

	Buffer b;

	Sha256 pseudonym = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);


	/* Collect the pseduonym components. */
	bufr->reset(bufr);

	size = S->file.name->size(S->file.name);
	bufr->add(bufr, (void *) S->file.name->get(S->file.name), \
		  sizeof(size));
	if ( !bufr->add(bufr, (void *) S->file.name->get(S->file.name), size) )
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

	char *name;

	unsigned int lp;


	/* Write the formatted string to the String object. */
	name = S->file.name->get(S->file.name);
	if ( !str->add_sprintf(str, "file{flags=%lu, uid=%lu, gid=%lu, mode=0%lo, path=%s",						\
			       (unsigned long int) S->file.flags,	 \
			       (unsigned long int) S->file.uid,		 \
			       (unsigned long int) S->file.gid,		 \
			       (unsigned long int) S->file.mode,	 \
			       (unsigned long int) name) )
		ERR(goto done);


	/* , s_magic=%0x, s_id=%s, s_uuid=%*phN */
	if ( !str->add_sprintf(str, ", s_magic=0x%0x, s_id=%s, s_uuid=", \
			       S->file.s_magic, S->file.s_id) )
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
 * This method implements the output of the characteristics of a
 * memory mapping event.
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

static _Bool _format_mmap_file(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;


	if ( !str->add_sprintf(str, "mmap_file{type=%u, reqprot=%u, "	      \
			       "prot=%u, flags=%u} ", S->mmap_file.anonymous, \
			       S->mmap_file.reqprot, S->mmap_file.prot,	      \
			       S->mmap_file.flags) )
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
 * Internal public method.
 *
 * This method implements the output of the characteristics of a cell
 * for a socket connect security event.
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

static _Bool _format_socket_connect(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;

	char *type;

	unsigned char *p;

	unsigned int lp,
		     size;


	type = (S->type == TSEM_SOCKET_CONNECT) ? "socket_connect" : \
		"socket_bind";
	if ( !str->add_sprintf(str, "%s{family=%u, ", type, \
			       S->socket_connect.family) )
		ERR(goto done);

	switch ( S->socket_connect.family ) {
		case AF_INET:
			if ( !str->add_sprintf(str, "port=%u, addr=%u",	   \
					       S->socket_connect.port,	   \
					       S->socket_connect.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			if ( !str->add_sprintf(str, "port=%u, flow=%u, "     \
					       "scope=%u, addr=",	     \
					       S->socket_connect.port,	     \
					       S->socket_connect.flow,	     \
					       S->socket_connect.scope) )
				ERR(goto done);

			p = S->socket_connect.u.ipv6_addr;
			size = sizeof(S->socket_connect.u.ipv6_addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}
			break;

		case AF_UNIX:
			if ( !str->add_sprintf(str, "addr=%s", \
					       S->socket_connect.u.unix_addr) )
				ERR(goto done);
			break;

		default:
			if ( !str->add_sprintf(str, "addr=") )
				ERR(goto done);

			p = S->socket_connect.u.addr;
			size = sizeof(S->socket_connect.u.addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}
			break;
	}

	if ( !str->add(str, "}") )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This method implements the output of the characteristics of a cell
 * for a socket accept security event.
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

static _Bool _format_socket_accept(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;

	unsigned char *p;

	unsigned int lp,
		     size;


	if ( !str->add_sprintf(str, "socket_accept{family=%u, type=%u, "  \
			       "port=%u, addr=", S->socket_accept.family, \
			       S->socket_accept.type, S->socket_accept.port) )
		ERR(goto done);

	switch ( S->socket_accept.family ) {
		case AF_INET:
			if ( !str->add_sprintf(str, "%u", \
					       S->socket_accept.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			p = S->socket_accept.u.ipv6_addr;
			size = sizeof(S->socket_accept.u.ipv6_addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}
			break;

		case AF_UNIX:
			if ( !str->add_sprintf(str, "addr=%s", \
					       S->socket_connect.u.unix_addr) )
				ERR(goto done);
			break;

		default:
			p = S->socket_accept.u.addr;
			size = sizeof(S->socket_accept.u.addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}
			break;
	}

	if ( !str->add(str, "}") )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This method implements the output of the characteristics of a
 * task kill security event.
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

static _Bool _format_task_kill(CO(Cell_State, S), CO(String, str))

{
	unsigned char *p;

	unsigned int size,
		     lp;

	_Bool retn = false;


	if ( !str->add_sprintf(str, "task_kill{cross=%u, signal=%u, "	\
			       "task_id=", S->task_kill.cross_model,	\
			       S->task_kill.signal) )
		ERR(goto done);

	p    = S->task_kill.task_id;
	size = sizeof(S->task_kill.task_id);
	for (lp= 0; lp < size; ++lp) {
		if ( !str->add_sprintf(str, "%02x", *p) )
			ERR(goto done);
		++p;
	}

	if ( !str->add(str, "}") )
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
			retn = _format_file(S, event);
			break;

		case TSEM_MMAP_FILE:
			retn = _format_mmap_file(S, event);
			if ( !S->mmap_file.anonymous )
				retn = _format_file(S, event);
			break;

		case TSEM_SOCKET_CREATE:
			retn = _format_socket_create(S, event);
			break;

		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
			retn = _format_socket_connect(S, event);
			break;

		case TSEM_SOCKET_ACCEPT:
			retn = _format_socket_accept(S, event);
			break;

		case TSEM_TASK_KILL:
			retn = _format_task_kill(S, event);
			break;

		case TSEM_GENERIC_EVENT:
			retn = event->add_sprintf(event,		    \
						  "generic_event{type=%s}", \
						  S->event->get(S->event));
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

	S->file.name->reset(S->file.name);

	S->event->reset(S->event);
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

	fprintf(stdout, "flags: %u\n", S->file.flags);

	fprintf(stdout, "uid:   %lu\n", (unsigned long int) S->file.uid);
	fprintf(stdout, "gid:   %lu\n", (unsigned long int) S->file.gid);
	fprintf(stdout, "mode:  0%lo\n",(unsigned long int) S->file.mode);
	fprintf(stdout, "name:  %s\n", S->file.name->get(S->file.name));

	fprintf(stdout, "s_magic: 0x%x\n", S->file.s_magic);
	fprintf(stdout, "s_id:    %s\n", S->file.s_id);

	if ( !bufr->add(bufr, (unsigned char *) S->file.s_uuid,
			sizeof(S->file.s_uuid)) )
		ERR(goto done);
	fputs("s_uuid:  ", stdout);
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
 * that has a socket create definition.
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
 * Internal public method.
 *
 * This method implements output of the characteristics of a cell
 * that has a socket connect definition.
 *
 * \param S	A pointer to the state of the object being output.
 */

void _dump_socket_connect(CO(Cell_State, S))

{
	char *type;

	unsigned char *p;

	unsigned int lp,
		     size;


	switch ( S->socket_connect.family ) {
		case AF_INET:
			type = "IPV4";
			break;
		case AF_INET6:
			type = "IPV6";
			break;
		case AF_UNIX:
			type = "UNIX";
			break;
		default:
			type = "OTHER";
			break;
	}
	fprintf(stdout, "family: %u / %s\n", S->socket_connect.family, type);

	if ( (S->socket_connect.family == AF_INET) ||
	     (S->socket_connect.family == AF_INET6) )
		fprintf(stdout, "port:   %u\n", S->socket_connect.port);


	switch ( S->socket_connect.family ) {
		case AF_INET:
			fprintf(stdout, "addr:   %u\n", \
				S->socket_connect.u.ipv4_addr);
			break;
		case AF_INET6:
			fprintf(stdout, "flow:   %u\n", \
				S->socket_connect.flow);
			fprintf(stdout, "scope:  %u\n", \
				S->socket_connect.scope);
			fputs("addr:   ", stdout);
			p = S->socket_connect.u.ipv6_addr;
			size = sizeof(S->socket_connect.u.ipv6_addr);
			for (lp= 0; lp < size; ++lp)
				fprintf(stdout, "%02x", *p++);
			fputs("\n", stdout);
			break;
		case AF_UNIX:
			fprintf(stdout, "path:   %s", \
				S->socket_connect.u.unix_addr);
			break;

		default:
			fputs("addr:   ", stdout);
			p = S->socket_connect.u.addr;
			size = sizeof(S->socket_connect.u.addr);
			for (lp= 0; lp < size; ++lp)
				fprintf(stdout, "%02x", *p++);
			fputs("\n", stdout);
			break;
	}


	return;
}


/**
 * Internal public method.
 *
 * This method implements output of the characteristics of a cell
 * that has a socket accept definition.
 *
 * \param S	A pointer to the state of the object being output.
 */

void _dump_socket_accept(CO(Cell_State, S))

{
	char *type;

	unsigned char *p;

	size_t size;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	switch ( S->socket_connect.family ) {
		case AF_INET:
			type = "IPV4";
			break;
		case AF_INET6:
			type = "IPV6";
			break;
		case AF_UNIX:
			type = "UNIX";
			break;
		default:
			type = "OTHER";
			break;
	}
	fprintf(stdout, "family: %u / %s\n", S->socket_accept.family, type);

	if ( (S->socket_accept.family == AF_INET) ||
	     (S->socket_accept.family == AF_INET6) )
		fprintf(stdout, "port:   %u\n", S->socket_accept.port);


	switch ( S->socket_accept.family ) {
		case AF_INET:
			fprintf(stdout, "addr:   %u\n", \
				S->socket_accept.u.ipv4_addr);
			break;
		case AF_INET6:
			fputs("addr:   ", stdout);
			p = S->socket_accept.u.ipv6_addr;
			size = sizeof(S->socket_accept.u.ipv6_addr);
			if ( !bufr->add(bufr, p, size) )
				goto done;
			bufr->print(bufr);
			fputs("\n", stdout);
			break;
		case AF_UNIX:
			fprintf(stdout, "path:   %s", \
				S->socket_accept.u.unix_addr);
			break;
		default:
			fputs("addr:   ", stdout);
			p = S->socket_accept.u.addr;
			size = sizeof(S->socket_accept.u.addr);
			if ( !bufr->add(bufr, p, size) )
				goto done;
			bufr->print(bufr);
			fputs("\n", stdout);
			break;
	}


 done:
	WHACK(bufr);
	return;
}


/**
 * Internal public method.
 *
 * This method implements output of the characteristics of a cell
 * involving a task kill event.
 *
 * \param S	A pointer to the state of the object being output.
 */

void _dump_task_kill(CO(Cell_State, S))

{
	Buffer bufr = NULL;

	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	fprintf(stdout, "cross model: %u\n", S->task_kill.cross_model);
	fprintf(stdout, "signal:      %u\n", S->task_kill.signal);

	if ( !bufr->add(bufr, S->task_kill.task_id, \
			sizeof(S->task_kill.task_id)) )
		ERR(goto done);
	fputs("task_id:     ", stdout);
	bufr->print(bufr);


 done:
	WHACK(bufr);

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

		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
			_dump_socket_connect(S);
			break;

		case TSEM_SOCKET_ACCEPT:
			_dump_socket_accept(S);
			break;

		case TSEM_TASK_KILL:
			_dump_task_kill(S);
			break;

		case TSEM_GENERIC_EVENT:
			fputs("type: ", stdout);
			S->event->print(S->event);
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


	WHACK(S->file.name);
	WHACK(S->event);
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
	INIT(HurdLib, String, this->state->file.name, ERR(goto fail));
	INIT(HurdLib, String, this->state->event, ERR(goto fail));
	INIT(NAAAIM, Sha256, this->state->identity, ERR(goto fail));

	/* Method initialization. */
	this->parse		    = parse;
	this->measure		    = measure;
	this->get_measurement	    = get_measurement;

	this->get_pseudonym = get_pseudonym;

	this->set_digest = set_digest;

	this->format	     = format;

	this->reset  = reset;
	this->dump   = dump;
	this->whack  = whack;

	return this;

fail:
	WHACK(this->state->file.name);
	WHACK(this->state->event);
	WHACK(this->state->identity);

	root->whack(root, this, this->state);
	return NULL;
}
