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

#define TMPFS_MAGIC 0x01021994


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
#include <TSEMparser.h>

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


/** Cell value for a generic security event. */
const char zero_message[NAAAIM_IDSIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};


/* Definition for an inode. */
struct inode {
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;

	uint32_t s_magic;
	char s_id[32];
	uint8_t s_uuid[16];
};

struct path {
	uint32_t major;
	uint32_t minor;
	String type;
	String pathname;

	uint64_t instance;
	char owner[NAAAIM_IDSIZE];
};

/* File characteristics. */
struct file_parameters {
	uint32_t flags;
	char digest[NAAAIM_IDSIZE];

	struct inode inode;
	struct path path;
};

/* File mmap parameters. */
struct mmap_file_parameters {
	bool have_file;
	uint32_t prot;
	uint32_t flags;
};

/* Socket parameters. */
struct sock {
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint8_t owner[NAAAIM_IDSIZE];
};

/* Socket creation parameters. */
struct socket_create_parameters {
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint32_t kern;
};

/* Socket connect parameters. */
struct socket_connect_parameters {
	struct sock sock;

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
	struct sock sock;

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

	S->measured	      = false;
	S->event	      = NULL;
	S->identity	      = NULL;
	S->file.path.pathname = NULL;

	return;
}


/**
 * Internal private function.
 *
 * This method extracts a 16 bit unsigned integer from a JSON field.
 *
 * \param parser	The parser object used to extract the field
 *			description.
 *
 * \param field		The description of the integer field to extract.
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

static _Bool _get_u16(CO(TSEMparser, parser), CO(char *, field), \
		      uint16_t *value)

{
	_Bool retn = false;

	long long int vl;


	if ( !parser->get_integer(parser, field, &vl) )
		ERR(goto done);
	if ( (unsigned long long int) vl > UINT16_MAX )
		ERR(goto done);

	*value = (uint16_t) vl;
	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This method extracts a 64 bit unsigned integer from a JSON field.
 *
 * \param parser	The parser object used to extract the field
 *			description.
 *
 * \param field		The description of the integer field to extract.
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

static _Bool _get_u64(CO(TSEMparser, parser), CO(char *, field), \
		      uint64_t *value)

{
	_Bool retn = false;

	long long int vl;


	if ( !parser->get_integer(parser, field, &vl) )
		ERR(goto done);
	if ( (unsigned long long int) vl > UINT64_MAX )
		ERR(goto done);

	*value = (uint64_t) vl;
	retn = true;


 done:
	return retn;
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

static _Bool _get_field(CO(TSEMparser, parser), CO(char *, field), \
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

static _Bool _get_digest(CO(TSEMparser, parser), CO(char *, field),
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

static _Bool _get_text(CO(TSEMparser, parser), CO(char *, field), \
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
 * Internal helper function.
 *
 * This function implements the parsing of a JSON file structure into
 * it the file_parameters structure.
 *
 * \param parser	The parser object used to parse the event
 *			description.
 *
 * \param event		The structure containing the JSON description
 *			that is holding a JSON file structure description.
 *
 * \param fp		A pointer to the file_parameters structure that
 *			file description parameters will be parsed into.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the parsing succeeded.  A false value
 *			indicates a parsing error while a true value
 *			indicates the structure pointed to by the fp
 *			argument was properly populated.
 */

static _Bool _parse_file(CO(TSEMparser, parser), CO(String, event), \
			 struct file_parameters *fp)

{
	_Bool retn = false;


	/* Extract the file field. */
	if ( !parser->extract_field(parser, event, "file") )
		ERR(goto done);

	event->reset(event);
	if ( !parser->get_field(parser, event) )
		ERR(goto done);

	/* Parse the native keys from the file{} structure.. */
	if ( !_get_field(parser, "flags", &fp->flags) )
		ERR(goto done);

	if ( !_get_digest(parser, "digest", (uint8_t *) fp->digest,
			  NAAAIM_IDSIZE) )
		ERR(goto done);

	/* Parse the inode structure. */
	if ( !parser->extract_field(parser, event, "inode") )
		ERR(goto done);

	if ( !_get_field(parser, "uid", &fp->inode.uid) )
		ERR(goto done);

	if ( !_get_field(parser, "gid", &fp->inode.gid) )
		ERR(goto done);

	if ( !_get_u16(parser, "mode", &fp->inode.mode) )
		ERR(goto done);

	if ( !_get_field(parser, "s_magic", &fp->inode.s_magic) )
		ERR(goto done);

	if ( !_get_text(parser, "s_id", (uint8_t *) fp->inode.s_id, \
			sizeof(fp->inode.s_id)) )
		ERR(goto done);

	if ( !_get_digest(parser, "s_uuid", fp->inode.s_uuid, \
			  sizeof(fp->inode.s_uuid)) )
		ERR(goto done);

	/* Parse the path description and extract pathname and instance. */
	if ( !parser->extract_field(parser, event, "path") )
		ERR(goto done);

	if ( !parser->get_text(parser, "type", fp->path.type) )
		ERR(goto done);

	if ( !parser->get_text(parser, "pathname", fp->path.pathname) )
		ERR(goto done);

	if ( !parser->has_key(parser, "instance") )
		fp->path.instance = 0;
	else {
		if ( !_get_u64(parser, "instance", &fp->path.instance) )
			ERR(goto done);
		if ( !_get_digest(parser, "owner", (uint8_t *) fp->path.owner,
				  NAAAIM_IDSIZE) )
			ERR(goto done);
	}

	/* Extract the device information. */
	if  ( !parser->has_key(parser, "dev") ) {
		fp->path.major = 0;
		fp->path.minor = 0; }
	else {
		if ( !parser->extract_field(parser, event, "dev") )
			ERR(goto done);
		if ( !_get_field(parser, "major", &fp->path.major) )
			ERR(goto done);
		if ( !_get_field(parser, "minor", &fp->path.minor) )
			ERR(goto done);
	}

	retn = true;


 done:
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
 * \param event	The object containing the definition of the event that
 *		is to be parsed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse_file_open(CO(Cell_State, S), CO(String, event))

{
	_Bool retn = false;

	TSEMparser parser = NULL;


	/* Extract the file_open and then the file field. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, event, "file_open") )
		ERR(goto done);

	/* Parse the file{} structure. */
	if ( !_parse_file(parser, event, &S->file) )
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

static _Bool parse_mmap_file(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	TSEMparser parser = NULL;


	/* Extract the field. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "mmap_file") )
		ERR(goto done);

	/* Parse mmap arguments. */
	if ( !_get_field(parser, "prot", &S->mmap_file.prot) )
		ERR(goto done);

	if ( !_get_field(parser, "flags", &S->mmap_file.flags) )
		ERR(goto done);

	/* Parse the file definition if this is a file based mapping. */
	S->mmap_file.have_file = parser->has_key(parser, "file");
	if ( !S->mmap_file.have_file ) {
		retn = true;
		goto done;
	}

	if ( !_parse_file(parser, entry, &S->file) )
		ERR(goto done);
	retn = true;


 done:
	WHACK(parser);

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a JSON encoded
 * sock structure.
 *
 * \param parser	The parser that will be used to extract the
 *			sock structure.
 *
 * \param entry		The object containing the security event description
 *			from which the sock structure will be extracted.
 *
 * \param sp		A pointer to the sock structure that will be
 *			populated from the JSON description.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool _parse_sock(CO(TSEMparser, parser), CO(String, entry), \
			struct sock *sp)

{
	_Bool retn;


	/* Extract the field itself. */
	if ( !parser->extract_field(parser, entry, "sock") )
		ERR(goto done);

	/* Parse socket parameters. */
	if ( !_get_field(parser, "family", &sp->family) )
		ERR(goto done);

	if ( !_get_field(parser, "type", &sp->type) )
		ERR(goto done);

	if ( !_get_field(parser, "protocol", &sp->protocol) )
		ERR(goto done);

	if ( !_get_digest(parser, "owner", sp->owner, sizeof(sp->owner)) )
		ERR(goto done);

	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This method implements parsing the characteristics of a JSON encoded
 * sock structure.
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

static _Bool parse_socket_create(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	TSEMparser parser = NULL;

	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "socket_create") )
		ERR(goto done);

	/* Parse socket parameters. */
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

static _Bool parse_socket_connect_bind(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	unsigned int cnt;

	uint8_t *p;

	uint32_t value;

	String str = NULL;

	TSEMparser parser = NULL;

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
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, type[value]) )
		ERR(goto done);

	entry->reset(entry);
	if ( !parser->get_field(parser, entry) )
		ERR(goto done);

	/* Parse socket information. */
	if ( !_parse_sock(parser, entry, &S->socket_connect.sock) )
		ERR(goto done);

	/* Scope parser to the addr{} field and address types. */
	if ( !parser->extract_field(parser, entry, "addr") )
		ERR(goto done);

	/* Extract protocol specific fields. */
	switch ( S->socket_connect.sock.family ) {
		case AF_INET:
			if ( !parser->extract_field(parser, entry, "af_inet") )
				ERR(goto done);
			if ( !_get_u16(parser, "port",
				       &S->socket_connect.port) )
				ERR(goto done);
			if ( !_get_field(parser, "address",
					 &S->socket_connect.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			if ( !parser->extract_field(parser, entry, \
						    "af_inet6") )
				ERR(goto done);

			if ( !_get_field(parser, "flow", \
					 &S->socket_connect.flow) )
				ERR(goto done);

			if ( !_get_field(parser, "scope", \
					 &S->socket_connect.scope) )
				ERR(goto done);

			p = S->socket_connect.u.ipv6_addr;
			cnt = sizeof(S->socket_connect.u.ipv6_addr);
			if ( !_get_digest(parser, "address", p, cnt) )
				ERR(goto done);
			break;

		case AF_UNIX:
			if ( !parser->extract_field(parser, entry, \
						    "af_unix") )
				ERR(goto done);

			INIT(HurdLib, String, str, ERR(goto done));
			if ( !parser->get_text(parser, "address", str) )
				ERR(goto done);
			cnt = sizeof(S->socket_connect.u.unix_addr);
			if ( str->size(str) >= cnt )
				ERR(goto done);

			memset(S->socket_connect.u.unix_addr, '\0', cnt);
			memcpy(S->socket_connect.u.unix_addr, str->get(str), \
			       str->size(str));
			break;

		default:
			if ( !parser->extract_field(parser, entry, \
						    "af_other") )
				ERR(goto done);

			p = S->socket_connect.u.addr;
			cnt = sizeof(S->socket_connect.u.addr);
			if ( !_get_digest(parser, "address", p, cnt) )
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

static _Bool parse_socket_accept(CO(Cell_State, S), CO(String, entry))

{
	_Bool retn = false;

	uint8_t *p;

	unsigned int cnt;

	String str = NULL;

	TSEMparser parser = NULL;


	/* Compile the regular expressions once. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "socket_accept") )
		ERR(goto done);

	entry->reset(entry);
	if ( !parser->get_field(parser, entry) )
		ERR(goto done);

	/* Parse socket information. */
	if ( !_parse_sock(parser, entry, &S->socket_accept.sock) )
		ERR(goto done);

	/* Scope parser to the addr{} field and address types. */
	if ( !parser->extract_field(parser, entry, "addr") )
		ERR(goto done);

	/* Extract protocol specific fields. */
	switch ( S->socket_accept.sock.family ) {
		case AF_INET:
			if ( !parser->extract_field(parser, entry, "af_inet") )
				ERR(goto done);
			if ( !_get_field(parser, "address", \
					 &S->socket_accept.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			if ( !parser->extract_field(parser, entry, \
						    "af_inet6") )
				ERR(goto done);

			p = S->socket_accept.u.ipv6_addr;
			cnt = sizeof(S->socket_accept.u.ipv6_addr);
			if ( !_get_digest(parser, "address", p, cnt) )
				ERR(goto done);
			break;

		case AF_UNIX:
			if ( !parser->extract_field(parser, entry, \
						    "af_unix") )
				ERR(goto done);

			INIT(HurdLib, String, str, ERR(goto done));
			if ( !parser->get_text(parser, "address", str) )
				ERR(goto done);
			cnt = sizeof(S->socket_accept.u.unix_addr);
			if ( str->size(str) >= cnt )
				ERR(goto done);

			memset(S->socket_accept.u.unix_addr, '\0', cnt);
			memcpy(S->socket_accept.u.unix_addr, str->get(str), \
			       str->size(str));
			break;

		default:
			if ( !parser->extract_field(parser, entry, \
						    "af_other") )
				ERR(goto done);

			p = S->socket_accept.u.addr;
			cnt = sizeof(S->socket_accept.u.addr);
			if ( !_get_digest(parser, "address", p, cnt) )
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

	TSEMparser parser = NULL;


	/* Extract task_kill event. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "task_kill") )
		ERR(goto done);

	/* Parse task_kill parameters. */
	if ( !_get_field(parser, "cross_ns", &S->task_kill.cross_model) )
		ERR(goto done);

	if ( !_get_field(parser, "sig", &S->task_kill.signal) )
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

	TSEMparser parser = NULL;


	/* Extract the generic event. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "event") )
		ERR(goto done);

	/* Parse the event type parameter. */
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
			if ( !parse_file_open(S, entry) )
				ERR(goto done);
			break;

		case TSEM_MMAP_FILE:
			if ( !parse_mmap_file(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_CREATE:
			if ( !parse_socket_create(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
			if ( !parse_socket_connect_bind(S, entry) )
				ERR(goto done);
			break;

		case TSEM_SOCKET_ACCEPT:
			if ( !parse_socket_accept(S, entry) )
				ERR(goto done);
			break;

		case TSEM_TASK_KILL:
			if ( !_parse_task_kill(S, entry) )
				ERR(goto done);
			break;

		default:
			if ( !_parse_generic_event(S, entry) )
				ERR(goto done);
			break;
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal helper function.
 *
 * This function adds the contents of a String object the input to a
 * measurement value.
 *
 * \param bufr	A pointer to the object that contains the contents of
 *		the measurement that will be generated.
 *
 * \param str	A pointer to the object whose string representation is
 *		to be added to the bufr object.
 *
 * \return	A boolean value is returned to indicate the status of
 *		adding the String object to the measurement.  A false
 *		value indicates the addition added while a true value
 *		indicates the contents was successfully added.
 */

static _Bool _add_String(CO(Buffer, bufr), CO(String, str))

{
	_Bool retn = false;

	uint32_t length = str->size(str);


	if ( !bufr->add(bufr, (void *) &length, sizeof(length)) )
		ERR(goto done);

	if ( !bufr->add(bufr, (void *) str->get(str), length) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal helper function.
 *
 * This method implements adding the path components for a temporary file
 * into the measurement.
 *
 * \param bufr	The object that will be extended with the measurement of
 *		the temporary file.
 *
 * \param pp	A pointer to the structure containing the information about
 *		the path to the temporary file.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the extension with the path information had succeeded or
 *		failed.  A false value indicates a failure while a true
 *		value indicates the object was successfully extended.
 */

static _Bool _add_temp_path(CO(Buffer, bufr), CO(struct path *, pp))

{
	_Bool retn = false;

	char *p, ch = '\0';

	uint32_t length;


	p = strrchr(pp->pathname->get(pp->pathname), '/');
	if ( p == NULL )
		ERR(goto done);
	++p;
	ch = *p;
	if (ch)
		*p = '\0';
	length = strlen(pp->pathname->get(pp->pathname));
	if (ch)
		*p = ch;

	if ( !bufr->add(bufr, (void *) &length, sizeof(length)) )
		ERR(goto done);
	if ( !bufr->add(bufr, (void *) pp->pathname->get(pp->pathname), \
		     length) )
		ERR(goto done);

	if ( !bufr->add(bufr, (void *) &pp->instance, sizeof(pp->instance)) )
		ERR(goto done);

	if ( !bufr->add(bufr, (void *) pp->owner, sizeof(pp->owner)) )
		ERR(goto done);

	retn = true;


 done:
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

	uint8_t null_uuid[16];

	struct inode *i;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) &S->file.flags, sizeof(S->file.flags)) )
		ERR(goto done);

	/* Add inode information .*/
	i = &S->file.inode;
	bufr->add(bufr, (void *) &i->uid, sizeof(i->uid));
	bufr->add(bufr, (void *) &i->gid, sizeof(i->gid));
	bufr->add(bufr, (void *) &i->mode, sizeof(i->mode));
	bufr->add(bufr, (void *) &i->s_magic, sizeof(i->s_magic));
	bufr->add(bufr, (void *) &i->s_id, sizeof(i->s_id));

	if ( i->s_magic == TMPFS_MAGIC ) {
		memset(null_uuid, '\0', sizeof(null_uuid));
		bufr->add(bufr, null_uuid, sizeof(null_uuid));
	} else
		bufr->add(bufr, i->s_uuid, sizeof(i->s_uuid));

	/* Add path information .*/
	if ( !_add_String(bufr, S->file.path.type) )
		ERR(goto done);

	if ( S->file.path.instance > 0 ) {
		if ( !_add_temp_path(bufr, &S->file.path) )
			ERR(goto done);
	} else {
		if ( !_add_String(bufr, S->file.path.pathname) )
			ERR(goto done);
	}

	/* Add the digest value of the file. */
	if ( !bufr->add(bufr, (void *) S->file.digest, \
			sizeof(S->file.digest)) )
		ERR(goto done);

	/* Add the parameter stream to the measurement. */
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


	/* Add file measurement if this is a non-anonymous mapping. */
	if ( S->mmap_file.have_file ) {
		if ( !_measure_file(S) )
			ERR(goto done);
	}

	/* Add the mapping protections and flags. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
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
 * description.
 *
 * \param sp	A pointer to the socket description structure that is
 *		to be measured.
 *
 * \param bufr	The object which the security coefficient stream is
 *		to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool _measure_sock(struct sock *sp, CO(Buffer, bufr))

{
	_Bool retn = false;

	unsigned char *p;

	size_t size;


	p = (unsigned char *) &sp->family;
	size = sizeof(sp->family);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &sp->type;
	size = sizeof(sp->type);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &sp->protocol;
	size = sizeof(sp->protocol);
	bufr->add(bufr, p, size);

	p = (unsigned char *) &sp->owner;
	size = sizeof(sp->owner);
	if ( !bufr->add(bufr, p, size) )
		ERR(goto done);

	retn = true;


 done:
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

	if ( !_measure_sock(&S->socket_connect.sock, bufr) )
		ERR(goto done);

	if ( (S->socket_connect.sock.family == AF_INET) ||
	     (S->socket_connect.sock.family == AF_INET6) ) {
			p = (unsigned char *) &S->socket_connect.port;
			size = sizeof(S->socket_connect.port);
			bufr->add(bufr, p, size);
	}

	switch ( S->socket_connect.sock.family ) {
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

	if ( !_measure_sock(&S->socket_accept.sock, bufr) )
		ERR(goto done);

	switch ( S->socket_accept.sock.family ) {
		case AF_INET:
			p = (unsigned char *) &S->socket_accept.port;
			size = sizeof(S->socket_accept.port);
			bufr->add(bufr, p, size);

			p = (unsigned char *) &S->socket_accept.u.ipv4_addr;
			size = sizeof(S->socket_accept.u.ipv4_addr);
			bufr->add(bufr, p, size);
			break;

		case AF_INET6:
			p = (unsigned char *) &S->socket_accept.port;
			size = sizeof(S->socket_accept.port);
			bufr->add(bufr, p, size);

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

		default:
			retn = _measure_generic_event(S);
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

	String pathname = S->file.path.pathname;

	Sha256 pseudonym = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bufr->poisoned(bufr) )
		ERR(goto done);
	if ( pathname->get(pathname) == NULL )
		return true;


	/* Hash the filename. */
	bufr->reset(bufr);
	size = pathname->size(pathname);
	if ( !bufr->add(bufr, (void *) &size, sizeof(size)) )
		ERR(goto done);

	if ( !bufr->add(bufr, (void *) pathname->get(pathname), size) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, pseudonym, ERR(goto done));
	if ( !pseudonym->add(pseudonym, bufr) )
		ERR(goto done);
	if ( !pseudonym->compute(pseudonym) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, pseudonym->get_Buffer(pseudonym)) )
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
 * This method implements the JSON formatting of a file structure definition.
 *
 * \param fp	A pointer to the file description that is to be
 *		formatted.
 *
 * \param str	The object the file description will be added to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the output was properly formatted.  A true value
 *		indicates formatting was successful while a false
 *		value indicates an error occurred.
 */

static _Bool _format_file(struct file_parameters *fp, CO(String, str))

{
	_Bool retn = false;

	char *name;

	unsigned int lp;

	struct inode *inode = &fp->inode;


	/* Write the formatted string to the String object. */
	name = fp->path.pathname->get(fp->path.pathname);
	if ( !str->add(str, "\"file\": {") )
		ERR(goto done);
	if ( !str->add_sprintf(str, "\"flags\": \"%lu\", ", fp->flags) )
		ERR(goto done);
	if ( !str->add_sprintf(str, "\"inode\": {\"uid\": \"%lu\", "	   \
			       "\"gid\": \"%lu\", \"mode\": \"0%lo\", "	   \
			       "\"s_magic\": \"0x%x\", \"s_id\": \"%s\", " \
			       "\"s_uuid\": \"",
			       (unsigned long int) inode->uid,
			       (unsigned long int) inode->gid,
			       (unsigned long int) inode->mode,
			       inode->s_magic, inode->s_id) )
		ERR(goto done);


	for (lp= 0; lp < sizeof(inode->s_uuid); ++lp) {
		if ( !str->add_sprintf(str, "%02x", \
				       (unsigned char) inode->s_uuid[lp]) )
		     ERR(goto done);
	}

	/* Path description. */
	if ( !str->add_sprintf(str, "\"}, \"path\": {\"dev\": {"	 \
			       "\"major\": \"%u\", \"minor\": \"%u\"}, ",
			       fp->path.major, fp->path.minor) )
		ERR(goto done);

	if ( fp->path.instance > 0 ) {
		if ( !str->add(str, "\"owner\": \"") )
			ERR(goto done);
		for (lp= 0; lp < sizeof(fp->path.owner); ++lp) {
			if ( !str->add_sprintf(str, "%02x",
				       (unsigned char) fp->path.owner[lp]) )
				ERR(goto done);
		}
		if ( !str->add(str, "\", ") )
			ERR(goto done);
		if ( !str->add_sprintf(str, "\"instance\": \"%lu\", ", \
				       fp->path.instance) )
			ERR(goto done);
	}

	if ( !str->add_sprintf(str, "\"type\": \"%s\", ",
			       fp->path.type->get(fp->path.type)) )
		ERR(goto done);

	if ( !str->add_sprintf(str, "\"pathname\": \"%s\"}, \"digest\": \"", \
			       name) )
		ERR(goto done);

	/* File digest. */
	for (lp= 0; lp < sizeof(fp->digest); ++lp) {
		if ( !str->add_sprintf(str, "%02x",
				       (unsigned char) fp->digest[lp]) )
		     ERR(goto done);
	}

	/* Ending squiggles. */
	if ( !str->add_sprintf(str, "\"}") )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal public method.
 *
 * This method implements the output of the description of a
 * file_open event.
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

static _Bool _format_file_open(CO(Cell_State, S), CO(String, str))

{
	_Bool retn = false;


	/* Write the formatted string to the String object. */
	if ( !str->add(str, "\"file_open\": {") )
		ERR(goto done);

	if ( !_format_file(&S->file, str) )
		ERR(goto done);

	if ( !str->add(str, "}") )
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


	if ( !str->add(str, "\"mmap_file\": {") )
		ERR(goto done);

	if ( S->mmap_file.have_file ) {
		if ( !_format_file(&S->file, str) )
			ERR(goto done);
		if ( !str->add(str, ", ") )
			ERR(goto done);
	}

	if ( !str->add_sprintf(str, "\"prot\": \"%u\", "		\
			       "\"flags\": \"%u\"}", S->mmap_file.prot, \
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
 * This method formats a JSON sock description.
 *
 * \param sp	A pointer containing the socket information to be
 *		formatted.
 *
 * \parm str	The object into which the formatted output is to
 *		be placed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the output was properly formatted.  A true value
 *		indicates formatting was successful while a false
 *		value indicates an error occurred.
 */

static _Bool _format_sock(CO(struct sock, *sp), CO(String, str))

{
	_Bool retn = false;

	unsigned int lp;

	if ( !str->add_sprintf(str, "\"sock\": {\"family\": \"%u\", "	     \
			       "\"type\": \"%u\", \"protocol\": \"%u\", ",   \
			       sp->family, sp->type,  sp->protocol) )
		ERR(goto done);

	if ( !str->add(str, "\"owner\": \"") )
		ERR(goto done);
	for (lp= 0; lp < sizeof(sp->owner); ++lp) {
		if ( !str->add_sprintf(str, "%02x", \
				       (unsigned char) sp->owner[lp]) )
			ERR(goto done);
	}
	if ( !str->add(str, "\"}") )
		ERR(goto done);

	retn = true;


 done:
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

	struct socket_create_parameters *sp = &S->socket_create;


	if ( !str->add_sprintf(str, "\"socket_create\": {"		  \
			       "\"family\": \"%u\", \"type\": \"%u\", " \
			       "\"protocol\": \"%u\", \"kern\": \"%u\"}", \
			       sp->family, sp->type, sp->protocol, sp->kern) )
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
	if ( !str->add_sprintf(str, "\"%s\": {", type, \
			       S->socket_connect.sock.family) )
		ERR(goto done);

	if ( !_format_sock(&S->socket_connect.sock, str) )
		ERR(goto done);
	if ( !str->add(str, ", \"addr\": {") )
		ERR(goto done);


	switch ( S->socket_connect.sock.family ) {
		case AF_INET:
			if ( !str->add_sprintf(str, "\"af_inet\": {"	   \
					       "\"port\": \"%u\", "	   \
					       "\"address\": \"%u\"}",	   \
					       S->socket_connect.port,	   \
					       S->socket_connect.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			if ( !str->add_sprintf(str, "\"af_inet6\": {"	     \
					       "\"port\": \"%u\", ",	     \
					       "\"flow\": \"%u\", "	     \
					       "\"scope\": \"%u\", "	     \
					       "\"address\": ",		     \
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

			if ( !str->add(str, "\"") )
				ERR(goto done);
			break;

		case AF_UNIX:
			if ( !str->add_sprintf(str, "\"af_unix\": {"	\
					       "\"address\": \"%s\"",   \
					       S->socket_connect.u.unix_addr) )
				ERR(goto done);
			break;

		default:
			if ( !str->add_sprintf(str, "\"af_other\": {", \
					       "\"address\": \"") )
				ERR(goto done);

			p = S->socket_connect.u.addr;
			size = sizeof(S->socket_connect.u.addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}

			if ( !str->add(str, "\"") )
				ERR(goto done);
			break;
	}

	if ( !str->add(str, "}}}") )
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


	if ( !str->add_sprintf(str, "\"socket_accept\": {\"family\": "	      \
			       "\"%u\", \"type\": \"%u\", \"port\": \"%u\""   \
			       "\"addr\": ", S->socket_accept.sock.family,    \
			       S->socket_accept.sock.type,		      \
			       S->socket_accept.port) )
		ERR(goto done);

	if ( !str->add(str, "\"socket_accept\": ") )
		ERR(goto done);

	if ( !_format_sock(&S->socket_accept.sock, str) )
		ERR(goto done);
	if ( !str->add(str, ", \"addr\": {") )
		ERR(goto done);

	switch ( S->socket_accept.sock.family ) {
		case AF_INET:
			if ( !str->add_sprintf(str, "\"af_inet\": {"	   \
					       "\"port\": \"%u\", "	   \
					       "\"address\": \"%u\"}",	   \
					       S->socket_accept.port,	   \
					       S->socket_accept.u.ipv4_addr) )
				ERR(goto done);

			if ( !str->add_sprintf(str, "%u", \
					       S->socket_accept.u.ipv4_addr) )
				ERR(goto done);
			break;

		case AF_INET6:
			p = S->socket_accept.u.ipv6_addr;
			if ( !str->add_sprintf(str, "\"af_inet6\": {"	     \
					       "\"port\": \"%u\", ",	     \
					       "\"address\": \"",	     \
					       S->socket_accept.port) )
				ERR(goto done);

			size = sizeof(S->socket_accept.u.ipv6_addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}

			if ( !str->add(str, "\"") )
				ERR(goto done);
			break;

		case AF_UNIX:
			if ( !str->add_sprintf(str, "\"af_unix\": {"	   \
					       "\"address\": \"%s\"",	   \
					       S->socket_accept.u.unix_addr) )
				ERR(goto done);
			break;

		default:
			if ( !str->add_sprintf(str, "\"af_other\": {"	   \
					       "\"address\": \"%s\"",	   \
					       S->socket_accept.u.addr) )
				ERR(goto done);

			p = S->socket_accept.u.addr;
			size = sizeof(S->socket_accept.u.addr);
			for (lp= 0; lp < size; ++lp) {
				if ( !str->add_sprintf(str, "%02x", *p) )
					ERR(goto done);
				++p;
			}
			break;
	}

	if ( !str->add(str, "}}}") )
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


	if ( !str->add(str, "\"task_kill\": {\"target\": \"") )
		ERR(goto done);

	p    = S->task_kill.task_id;
	size = sizeof(S->task_kill.task_id);
	for (lp= 0; lp < size; ++lp) {
		if ( !str->add_sprintf(str, "%02x", *p) )
			ERR(goto done);
		++p;
	}

	if ( !str->add_sprintf(str, "\", \"sig\": \"%u\", \"cross_ns\": " \
			       "\"%u\"}", S->task_kill.cross_model,	  \
			       S->task_kill.signal) )
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
			retn = _format_file_open(S, event);
			break;

		case TSEM_MMAP_FILE:
			retn = _format_mmap_file(S, event);
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

		default:
			retn = event->add_sprintf(event, "\"%s\": {}", \
						  S->event->get(S->event));
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

	S->file.path.type->reset(S->file.path.type);
	S->file.path.pathname->reset(S->file.path.pathname);

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
	struct inode *ip = &S->file.inode;

	struct path *pp = &S->file.path;

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	fprintf(stdout, "flags: %u\n", S->file.flags);

	fprintf(stdout, "uid:   %lu\n", (unsigned long int) ip->uid);
	fprintf(stdout, "gid:   %lu\n", (unsigned long int) ip->gid);
	fprintf(stdout, "mode:  0%lo\n",(unsigned long int) ip->mode);
	fprintf(stdout, "type:  %s\n", pp->pathname->get(pp->type));
	fprintf(stdout, "name:  %s\n", pp->pathname->get(pp->pathname));
	fprintf(stdout, "s_magic: 0x%x\n", ip->s_magic);
	fprintf(stdout, "s_id:    %s\n", ip->s_id);
	if ( !bufr->add(bufr, (unsigned char *) ip->s_uuid, \
			sizeof(ip->s_uuid)) )
		ERR(goto done);
	fputs("s_uuid:  ", stdout);
	bufr->print(bufr);
	bufr->reset(bufr);

	if ( pp->instance > 0 ) {
		fprintf(stdout, "instance: %lu\n", pp->instance);

		if ( !bufr->add(bufr, (void *) pp->owner, sizeof(pp->owner)) )
			ERR(goto done);
		fputs("owner:    ", stdout);
		bufr->print(bufr);
		bufr->reset(bufr);
	}

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


	switch ( S->socket_connect.sock.family ) {
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
	fprintf(stdout, "family: %u / %s\n", S->socket_connect.sock.family, \
		type);

	if ( (S->socket_connect.sock.family == AF_INET) ||
	     (S->socket_connect.sock.family == AF_INET6) )
		fprintf(stdout, "port:   %u\n", S->socket_connect.port);


	switch ( S->socket_connect.sock.family ) {
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

	switch ( S->socket_connect.sock.family ) {
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
	fprintf(stdout, "family: %u / %s\n", S->socket_accept.sock.family, \
		type);

	if ( (S->socket_accept.sock.family == AF_INET) ||
	     (S->socket_accept.sock.family == AF_INET6) )
		fprintf(stdout, "port:   %u\n", S->socket_accept.port);


	switch ( S->socket_accept.sock.family ) {
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
	fprintf(stdout, "sig:         %u\n", S->task_kill.signal);

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

		default:
			fputs("type: ", stdout);
			S->event->print(S->event);
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


	WHACK(S->file.path.type);
	WHACK(S->file.path.pathname);
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
	INIT(HurdLib, String, this->state->file.path.type, ERR(goto fail));
	INIT(HurdLib, String, this->state->file.path.pathname, ERR(goto fail));
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
	WHACK(this->state->file.path.type);
	WHACK(this->state->file.path.pathname);
	WHACK(this->state->event);
	WHACK(this->state->identity);

	root->whack(root, this, this->state);
	return NULL;
}
