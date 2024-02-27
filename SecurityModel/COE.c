/** \file
 * This file contains the implementation of an object which manages the
 * parameters defining a context of execution in the Trusted Security
 * Event Model.
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
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <TSEMparser.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "COE.h"


/* Object state extraction macro. */
#define STATE(var) CO(COE_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_COE_OBJID)
#error Object identifier not defined.
#endif


/* COE identity elements. */
struct coe_characteristics {
	uint32_t uid;
	uint32_t euid;
	uint32_t suid;

	uint32_t gid;
	uint32_t egid;
	uint32_t sgid;

	uint32_t fsuid;
	uint32_t fsgid;

	uint64_t capeff;
};

/** COE private state information. */
struct NAAAIM_COE_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* COE characteristics. */
	struct coe_characteristics character;

	/* Measured identity. */
	_Bool measured;
	Sha256 identity;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_COE_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(COE_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_COE_OBJID;

	S->poisoned = false;

	memset(&S->character, '\0', sizeof(struct coe_characteristics));

	S->measured = false;
	S->identity = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements a method for setting all of the characteristics
 * of a context of execution.
 *
 * \param this	A pointer to the object whose identity elements are to
 *		bet set.
 */

static void set_characteristics(CO(COE, this), const uint32_t uid,	     \
				  const uint32_t euid, const uint32_t suid,  \
				  const uint32_t gid, const uint32_t egid,   \
				  const uint32_t sgid, const uint32_t fsuid, \
				  const uint32_t fsgid, 		     \
				  const uint64_t capeff)

{
	STATE(S);

	S->character.uid  = uid;
	S->character.euid = euid;
	S->character.suid = suid;

	S->character.gid  = gid;
	S->character.egid = egid;
	S->character.sgid = sgid;

	S->character.fsuid = fsuid;
	S->character.fsgid = fsgid;

	S->character.capeff = capeff;

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
 * This method parses the capability entry from the COE definition
 * field.  This is special cased since the capability field is a
 * 64-bit entry.
 *
 * \param parser	The object that contains the field description
 *			to be parsed.
 *
 * \param field		A character pointer to the event field that
 *			is to be extracted.
 *
 * \param value		A pointer to the variable that will be loaded
 *			with the capability value.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the capability extraction.  A false value is
 *		used to indicate a failure while a true value indicates
 *		the field entry has been successfully extracted.
 */

static _Bool _get_caps(CO(TSEMparser, parser), CO(char *, field), \
		       uint64_t *value)

{
	_Bool retn = false;

	long long int vl;


	if ( !parser->get_integer(parser, field, &vl) )
		ERR(goto done);

	*value = (uint64_t) vl;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements parsing of a trajectory entry for the
 * characteristics of a context of action
 *
 * \param this	A pointer to the object whose trajectory entry
 *		is to be parsed.
 *
 * \param entry	A pointer to the object which contains the template
 *		entry which is to be parsed.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(COE, this), CO(String, entry))

{
	STATE(S);

	_Bool retn = false;

	TSEMparser parser = NULL;


	/* Verify object and caller state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( entry->poisoned(entry) )
		ERR(goto done);


	/* Extract coe field. */
	INIT(NAAAIM, TSEMparser, parser, ERR(goto done));
	if ( !parser->extract_field(parser, entry, "COE") )
		ERR(goto done);


	/* Parse field entries. */
	if ( !_get_field(parser, "uid", &S->character.uid) )
		ERR(goto done);

	if ( !_get_field(parser, "euid", &S->character.euid) )
		ERR(goto done);

	if ( !_get_field(parser, "suid", &S->character.suid) )
		ERR(goto done);

	if ( !_get_field(parser, "gid", &S->character.gid) )
		ERR(goto done);

	if ( !_get_field(parser, "egid", &S->character.egid) )
		ERR(goto done);

	if ( !_get_field(parser, "sgid", &S->character.sgid) )
		ERR(goto done);

	if ( !_get_field(parser, "fsuid", &S->character.fsuid) )
		ERR(goto done);

	if ( !_get_field(parser, "fsgid", &S->character.fsgid) )
		ERR(goto done);

	if ( !_get_caps(parser, "capeff", &S->character.capeff) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(parser);

	return retn;
}


/**
 * External public method.
 *
 * This method implements computing of the measurement of the coe
 * characteristics.  This involves the computation of the digest over the
 * structure which defines the characteristics of the context of
 * execution.
 *
 * \param this	A pointer to the object that is to be measured.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool measure(CO(COE, this))

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
	bufr->add(bufr, (void *) &S->character.euid, \
		  sizeof(S->character.euid));
	bufr->add(bufr, (void *) &S->character.suid, \
		  sizeof(S->character.suid));
	bufr->add(bufr, (void *) &S->character.gid, sizeof(S->character.gid));
	bufr->add(bufr, (void *) &S->character.egid, \
		  sizeof(S->character.egid));
	bufr->add(bufr, (void *) &S->character.sgid, \
		  sizeof(S->character.sgid));
	bufr->add(bufr, (void *) &S->character.fsuid, \
		  sizeof(S->character.fsuid));
	bufr->add(bufr, (void *) &S->character.fsuid, \
		  sizeof(S->character.fsgid));
	if ( !bufr->add(bufr, (void *) &S->character.capeff, \
			sizeof(S->character.capeff)) )
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
 * measurement of the coe object.  It is considered to be a terminal
 * error for the object for this function to be called without
 * previously calling the ->measurement method.
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

static _Bool get_measurement(CO(COE, this), CO(Buffer, bufr))

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
 * representation of the characteristics of a context of execution.  The
 * string generated is in the same format that is interpreted by
 * the ->parse method.
 *
 * \param this	A pointer to the object containing the characteristics
 *		that are to be formatted.
 *
 * \param event	The object into which the formatted string is to
 *		be copied.
 */

static _Bool format(CO(COE, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Generate the COE string and add it. */
	retn = event->add_sprintf(event, "\"COE\": {\"uid\": \"%lu\", "	    \
				  "\"euid\": \"%lu\", \"suid\": \"%lu\", "  \
				  "\"gid\": \"%lu\", \"egid\": \"%lu\",  "  \
				  "\"sgid\": \"%lu\", \"fsuid\": \"%lu\", " \
				  "\"fsgid\": \"%lu\", \"capeff\": "	    \
				  "\"0x%llx\"}",			    \
		       (unsigned long int) S->character.uid,		    \
		       (unsigned long int) S->character.euid,		    \
		       (unsigned long int) S->character.suid,		    \
		       (unsigned long int) S->character.gid,		    \
		       (unsigned long int) S->character.egid,		    \
		       (unsigned long int) S->character.sgid,		    \
		       (unsigned long int) S->character.fsuid,		    \
		       (unsigned long int) S->character.fsgid,		    \
		       (unsigned long long int) S->character.capeff);
	if ( !retn )
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
 * This method implements the reset of the COE object to a state which
 * would allow the creation of a new set of characteristics.
 *
 * \param this	A pointer to the object which is to be reset.
 */

static void reset(CO(COE, this))

{
	STATE(S);

	S->poisoned = false;
	S->measured = false;

	memset(&S->character, '\0', sizeof(struct coe_characteristics));

	S->identity->reset(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the characteristics of a context
 * of execution.
 *
 * \param this	A pointer to the object whose characteristics are to be
 *		dumped.
 */

static void dump(CO(COE, this))

{
	STATE(S);


	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);
	fprintf(stdout, "uid:   %lu\n", (unsigned long int) S->character.uid);
	fprintf(stdout, "euid:  %lu\n", (unsigned long int) S->character.euid);
	fprintf(stdout, "suid:  %lu\n", (unsigned long int) S->character.suid);
	fprintf(stdout, "gid:   %lu\n", (unsigned long int) S->character.gid);
	fprintf(stdout, "egid:  %lu\n", (unsigned long int) S->character.egid);
	fprintf(stdout, "sgid:  %lu\n", (unsigned long int) S->character.sgid);
	fprintf(stdout, "fsuid: %lu\n", (unsigned long int) S->character.fsuid);
	fprintf(stdout, "fsgid: %lu\n", (unsigned long int) S->character.fsgid);
	fprintf(stdout, "capeff: %llx\n", \
		(unsigned long long int) S->character.capeff);

	fputs("measurement: ", stdout);
	S->identity->print(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a COE object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(COE, this))

{
	STATE(S);

	WHACK(S->identity);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a COE object.
 *
 * \return	A pointer to the initialized COE.  A null value
 *		indicates an error was encountered in object generation.
 */

extern COE NAAAIM_COE_Init(void)

{
	auto Origin root;

	auto COE this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_COE);
	retn.state_size   = sizeof(struct NAAAIM_COE_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_COE_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(NAAAIM, Sha256, this->state->identity, ERR(goto fail));

	/* Method initialization. */
	this->set_characteristics   = set_characteristics;
	this->parse		    = parse;
	this->measure		    = measure;
	this->get_measurement	    = get_measurement;

	this->format = format;
	this->reset = reset;
	this->dump  = dump;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->identity);

	root->whack(root, this, this->state);
	return NULL;
}
