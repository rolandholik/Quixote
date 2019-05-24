/** \file
 * This file contains the implementation of an object which represents
 * an actor identity in the Linux iso-identity modeling system.  The
 * purpose of this object is to consolidate all of the identity
 * characteristics of an actor process for the purposes of computing
 * its measured identity.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
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
#include "Actor.h"

#if !defined(REG_OK)
#define REG_OK REG_NOERROR
#endif


/* Object state extraction macro. */
#define STATE(var) CO(Actor_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Actor_OBJID)
#error Object identifier not defined.
#endif


/* Actor identity elements. */
struct actor_identity {
	uint32_t uid;
	uint32_t euid;
	uint32_t suid;

	uint32_t gid;
	uint32_t egid;
	uint32_t sgid;

	uint32_t fsuid;
	uint32_t fsgid;

	uint64_t capability;
} __attribute__((packed));

/** Actor private state information. */
struct NAAAIM_Actor_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Actor identity elements. */
	struct actor_identity elements;

	/* Measured identity. */
	_Bool measured;
	Sha256 identity;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Actor_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(Actor_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Actor_OBJID;

	S->poisoned = false;

	memset(&S->elements, '\0', sizeof(struct actor_identity));

	S->measured = false;
	S->identity = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements a method for setting all of the identity
 * characteristics for an actor identity.
 *
 * \param this	A pointer to the actor object whose identity elements
 *		are being set.
 */

static void set_identity_elements(CO(Actor, this), const uint32_t uid,	     \
				  const uint32_t euid, const uint32_t suid,  \
				  const uint32_t gid, const uint32_t egid,   \
				  const uint32_t sgid, const uint32_t fsuid, \
				  const uint32_t fsgid, 		     \
				  const uint64_t capability)

{
	STATE(S);

	S->elements.uid  = uid;
	S->elements.euid = euid;
	S->elements.suid = suid;

	S->elements.gid  = gid;
	S->elements.egid = egid;
	S->elements.sgid = sgid;

	S->elements.fsuid = fsuid;
	S->elements.fsgid = fsgid;

	S->elements.capability = capability;

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
 * This method parses the capability entry from the actor definition
 * field.  This is special cased since the capability field is a
 * 64-bit entry.
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

static _Bool _get_caps(CO(char *, field), CO(char *, fd), uint64_t *value)

{
	_Bool retn       = false,
	      have_regex = false;

	char match[32];

	long long int vl;

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

	vl = strtoll(match, NULL, 16);
	if ( errno == ERANGE )
		ERR(goto done);
	if ( vl > UINT64_MAX )
		ERR(goto done);

	*value = vl;
	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * External public method.
 *
 * This method implements parsing of a trajectory entry for the
 * characteristcis of a actor identity.
 *
 * \param this	A pointer to the actor object whose trajectory entry
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

static _Bool parse(CO(Actor, this), CO(String, entry))

{
	STATE(S);

	_Bool have_regex = false,
	      retn = false;

	char *fp;

	regex_t regex;

	regmatch_t regmatch;

	Buffer field = NULL;


	/* Verify object and caller state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( entry->poisoned(entry) )
		ERR(goto done);

	/* Extract actor field. */
	INIT(HurdLib, Buffer, field, ERR(goto done));

	if ( regcomp(&regex, "actor\\{[^}]*\\}", REG_EXTENDED) != 0 )
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
	if ( !_get_field(fp, "uid=([^,]*)", &S->elements.uid) )
		ERR(goto done);

	if ( !_get_field(fp, "euid=([^,]*)", &S->elements.euid) )
		ERR(goto done);

	if ( !_get_field(fp, "suid=([^,]*)", &S->elements.suid) )
		ERR(goto done);

	if ( !_get_field(fp, "gid=([^,]*)", &S->elements.gid) )
		ERR(goto done);

	if ( !_get_field(fp, "egid=([^,]*)", &S->elements.egid) )
		ERR(goto done);

	if ( !_get_field(fp, "sgid=([^,]*)", &S->elements.sgid) )
		ERR(goto done);

	if ( !_get_field(fp, "fsuid=([^,]*)", &S->elements.fsuid) )
		ERR(goto done);

	if ( !_get_field(fp, "fsgid=([^,]*)", &S->elements.fsgid) )
		ERR(goto done);

	if ( !_get_caps(fp, "cap=([^}]*)", &S->elements.capability) )
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
 * This method implements computing of the measurement of the actor
 * identity.  This involves the computation of the digest over the
 * structure which defines the identity characteristics of the actor
 * process.
 *
 * \param this	A pointer to the actor which is to be measured.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement has succeeded.  A false value
 *		indicates failure while a true value indicates success.
 */

static _Bool measure(CO(Actor, this))

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
	if ( !bufr->add(bufr, (void *) &S->elements, \
			sizeof(struct actor_identity)) )
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
 * measurement of the actor object.  It is considered to be a terminal
 * error for the object for this function to be called without
 * previously calling the ->measurement method.
 *
 * \param this	A pointer to the actor identity whose measurement is
 *		to be retrieved.
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

static _Bool get_measurement(CO(Actor, this), CO(Buffer, bufr))

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
 * representation of the identity elements.  The string generated
 * is in the same format that is interpreted by the ->parse method.
 *
 * \param this	A pointer to the actor object containing the
 *		identity elements which are to be formatted.
 *
 * \param event	The object into which the formatted string is to
 *		be copied.
 */

static _Bool format(CO(Actor, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;

	char bufr[256];

	size_t used;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Generate the actor string and add it. */
	used = snprintf(bufr, sizeof(bufr), "actor{uid=%d, euid=%d, suid=%d, gid=%d, egid=%d, sgid=%d, fsuid=%d, fsgid=%d, cap=0x%lx} ",
		       S->elements.uid, S->elements.euid, S->elements.suid, \
		       S->elements.gid, S->elements.egid, S->elements.sgid, \
		       S->elements.fsuid, S->elements.fsgid,		    \
		       S->elements.capability);
	if ( used >= sizeof(bufr) )
		ERR(goto done);

	if ( !event->add(event, bufr) )
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
 * This method implements the reset of the Actor object to a state which
 * would allow the generation of a new actor identity.
 *
 * \param this	A pointer to the actor object which is to be reset.
 */

static void reset(CO(Actor, this))

{
	STATE(S);

	S->poisoned = false;
	S->measured = false;

	memset(&S->elements, '\0', sizeof(struct actor_identity));

	S->identity->reset(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the characteristis of the actor
 * identity represented by the object.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump(CO(Actor, this))

{
	STATE(S);


	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);
	fprintf(stdout, "uid:   %u\n", S->elements.uid);
	fprintf(stdout, "euid:  %u\n", S->elements.euid);
	fprintf(stdout, "suid:  %u\n", S->elements.suid);
	fprintf(stdout, "gid:   %u\n", S->elements.gid);
	fprintf(stdout, "egid:  %u\n", S->elements.egid);
	fprintf(stdout, "sgid:  %u\n", S->elements.sgid);
	fprintf(stdout, "fsuid: %u\n", S->elements.fsuid);
	fprintf(stdout, "fsgid: %u\n", S->elements.fsgid);
	fprintf(stdout, "caps:  %lx\n", S->elements.capability);

	fputs("measurement: ", stdout);
	S->identity->print(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Actor object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Actor, this))

{
	STATE(S);

	WHACK(S->identity);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Actor object.
 *
 * \return	A pointer to the initialized Actor.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Actor NAAAIM_Actor_Init(void)

{
	auto Origin root;

	auto Actor this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Actor);
	retn.state_size   = sizeof(struct NAAAIM_Actor_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Actor_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(NAAAIM, Sha256, this->state->identity, ERR(goto fail));

	/* Method initialization. */
	this->set_identity_elements = set_identity_elements;
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
