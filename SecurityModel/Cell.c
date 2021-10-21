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


/* Cell characteristics. */
struct cell_characteristics {
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;

	uint32_t name_length;
	char name[NAAAIM_IDSIZE];

	char s_id[32];
	uint8_t s_uuid[16];

	char digest[NAAAIM_IDSIZE];
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

	/* Cell identity elements. */
	struct cell_characteristics character;

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

	memset(&S->character, '\0', sizeof(struct cell_characteristics));

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
 * \param fp	A character pointer to the field which is to be
 *		parsed.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
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

static _Bool _get_field(CO(char *, field), CO(char *, fd), uint32_t *value)

{
	_Bool retn       = false,
	      have_regex = false;

	char match[32];

	long int vl;

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	if ( regcomp(&regex, fd, REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field, 2, regmatch, 0) != REG_OK )
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
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private function.
 *
 * This method parses a digest field from a cell characteristic field.  A
 * digest field is assumed to have a size equal to the operative
 * identity size.
 *
 * \param fp	A character pointer to the field which is to be
 *		parsed.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
 *
 * \param value	A pointer to the character area which the field
 *		will be loaded into.
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

static _Bool _get_digest(CO(char *, field), CO(char *, fd), uint8_t *fb, \
			 size_t size)

{
	_Bool retn       = false,
	      have_regex = false;

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];

	Buffer bufr  = NULL,
	       match = NULL;


	if ( regcomp(&regex, fd, REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field, 2, regmatch, 0) != REG_OK )
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
	if ( have_regex )
		regfree(&regex);

	WHACK(bufr);
	WHACK(match);

	return retn;
}


/**
 * Internal private function.
 *
 * This method parses a test entry from a cell characteristic field.
 *
 * \param fp	A character pointer to the field which is to be
 *		parsed.
 *
 * \param regex	A regular expression which extracts the desired
 *		field.
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

static _Bool _get_text(CO(char *, field), CO(char *, fd), uint8_t *fb, \
		       size_t fblen)

{
	_Bool retn       = false,
	      have_regex = false;

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];

	Buffer bufr = NULL;


	if ( regcomp(&regex, fd, REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	if ( regexec(&regex, field, 2, regmatch, 0) != REG_OK )
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
	if ( have_regex )
		regfree(&regex);

	WHACK(bufr);

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
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(Cell, this), CO(String, entry))

{
	STATE(S);

	_Bool have_regex = false,
	      retn = false;

	uint32_t value;

	char *fp;

	regex_t regex;

	regmatch_t regmatch;

	Buffer field = NULL;


	/* Verify object and caller state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( entry->poisoned(entry) )
		ERR(goto done);

	/* Extract cell field. */
	INIT(HurdLib, Buffer, field, ERR(goto done));

	if ( regcomp(&regex, "cell\\{[^}]*\\}", REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	fp = entry->get(entry);
	if ( regexec(&regex, fp, 1, &regmatch, 0) != REG_OK )
		ERR(goto done);

	field->add(field, (unsigned char *) (fp + regmatch.rm_so),
		   regmatch.rm_eo-regmatch.rm_so);
	if ( !field->add(field, (unsigned char *) "\0", 1) )
		ERR(goto done);


	/* Parse field entries. */
	fp = (char *) field->get(field);
	if ( !_get_field(fp, "uid=([^,]*)", &S->character.uid) )
		ERR(goto done);

	if ( !_get_field(fp, "gid=([^,]*)", &S->character.gid) )

		ERR(goto done);

	if ( !_get_field(fp, "mode=([^,]*)", &value) )
		ERR(goto done);
	S->character.mode = value;

	if ( !_get_field(fp, "name_length=([^,]*)", &S->character.name_length) )
		ERR(goto done);

	if ( !_get_digest(fp, "name=([^,]*)", (uint8_t *) S->character.name, \
			  NAAAIM_IDSIZE) )
		ERR(goto done);

	if ( !_get_text(fp, "s_id=([^,]*)", (uint8_t *) S->character.s_id, \
			sizeof(S->character.s_id)) )
		ERR(goto done);

	if ( !_get_digest(fp, "s_uuid=([^,]*)", S->character.s_uuid, \
			sizeof(S->character.s_uuid)) )
		ERR(goto done);

	if ( !_get_digest(fp, "digest=([^}]*)", \
			  (uint8_t *) S->character.digest, NAAAIM_IDSIZE) )
		ERR(goto done);

	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);
	if ( !retn )
		S->poisoned = true;

	WHACK(field);

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

	Buffer bufr = NULL;


	/* Object verifications. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->measured )
		ERR(goto done);


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	bufr->add(bufr, (void *) &S->character.uid, sizeof(S->character.uid));
	bufr->add(bufr, (void *) &S->character.gid, sizeof(S->character.gid));
	bufr->add(bufr, (void *) &S->character.mode, sizeof(S->character.mode));
	bufr->add(bufr, (void *) &S->character.name_length, \
		  sizeof(S->character.name_length));
	bufr->add(bufr, (void *) S->character.name, sizeof(S->character.name));
	bufr->add(bufr, (void *) S->character.s_id, sizeof(S->character.s_id));
	bufr->add(bufr, (void *) S->character.s_uuid, \
		  sizeof(S->character.s_uuid));
	if ( !bufr->add(bufr, (void *) S->character.digest, \
			sizeof(S->character.digest)) )
		ERR(goto done);

	if ( !S->identity->add(S->identity, bufr) )
		ERR(goto done);
	if ( !S->identity->compute(S->identity) )
		ERR(goto done);

	S->measured = true;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;
	WHACK(bufr);

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

	char bufr[256];

	unsigned int lp;

	size_t used;

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Write the formatted string to the String object. */
	used = snprintf(bufr, sizeof(bufr), "cell{uid=%lu, gid=%lu, mode=0%lo, name_length=%lu, name=",				       \
			(unsigned long int) S->character.uid,	\
			(unsigned long int) S->character.gid,	\
			(unsigned long int) S->character.mode,	\
			(unsigned long int) S->character.name_length);
	if ( used >= sizeof(bufr) )
		ERR(goto done);
	if ( !event->add(event, bufr) )
		ERR(goto done);

	/* name=%*phN, s_id=%s */
	for (lp= 0; lp < sizeof(S->character.name); ++lp) {
		snprintf(bufr, sizeof(bufr), "%02x", \
			 (unsigned char) S->character.name[lp]);
		if ( !event->add(event, bufr) )
			ERR(goto done);
	}

	/* , s_uuid=%*phN */
	used = snprintf(bufr, sizeof(bufr), ", s_id=%s, s_uuid=", \
			S->character.s_id);
	if ( used >= sizeof(bufr) )
		ERR(goto done);
	if ( !event->add(event, bufr) )
		ERR(goto done);

	for (lp= 0; lp < sizeof(S->character.s_uuid); ++lp) {
		snprintf(bufr, sizeof(bufr), "%02x", \
			 (unsigned char) S->character.s_uuid[lp]);
		if ( !event->add(event, bufr) )
			ERR(goto done);
	}

	/* , digest=%*phN */
	used = snprintf(bufr, sizeof(bufr), "%s", ", digest=");
	if ( used >= sizeof(bufr) )
		ERR(goto done);
	if ( !event->add(event, bufr) )
		ERR(goto done);

	for (lp= 0; lp < sizeof(S->character.digest); ++lp) {
		snprintf(bufr, sizeof(bufr), "%02x",
			 (unsigned char) S->character.digest[lp]);
		if ( !event->add(event, bufr) )
			ERR(goto done);
	}

	/* } */
	if ( !event->add(event, "}") )
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

	memset(&S->character, '\0', sizeof(struct cell_characteristics));

	S->identity->reset(S->identity);

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

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);

	fprintf(stdout, "uid:  %lu\n", (unsigned long int) S->character.uid);
	fprintf(stdout, "gid:  %lu\n", (unsigned long int) S->character.gid);
	fprintf(stdout, "mode: 0%lo\n",(unsigned long int) S->character.mode);
	fprintf(stdout, "name length: %lu\n", \
		(unsigned long int) S->character.name_length);

	if ( !bufr->add(bufr, (unsigned char *) S->character.name,
			sizeof(S->character.name)) )
		ERR(goto done);
	fputs("name digest: ", stdout);
	bufr->print(bufr);
	bufr->reset(bufr);

	fprintf(stdout, "s_id:   %s\n", S->character.s_id);

	if ( !bufr->add(bufr, (unsigned char *) S->character.s_uuid,
			sizeof(S->character.s_uuid)) )
		ERR(goto done);
	fputs("s_uuid: ", stdout);
	bufr->print(bufr);
	bufr->reset(bufr);

	if ( !bufr->add(bufr, (unsigned char *) S->character.digest,
			sizeof(S->character.digest)) )
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