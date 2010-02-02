/** \file
 * This file implements an object for manipulating IDfusion based
 * patient identity token.   The token is composed of two major
 * parts.  The first part is a user specific organizational identity with
 * the second portion being an RSA encrypted anonymized user identity
 * with a token specific key.
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Token delimiters. */
#define TOKEN_START "-----BEGIN IDENTITY TOKEN-----"
#define TOKEN_END   "-----END IDENTITY TOKEN-----"

#define ORGID_START "-----BEGIN ORGANIZATION IDENTITY-----"
#define ORGID_END   "-----END ORGANIZATION IDENTITY-----"

#define PTID_START  "-----BEGIN PATIENT IDENTITY-----"
#define PTID_END    "-----END PATIENT IDENTITY-----"

#define KEY_START   "-----BEGIN TOKEN KEY-----"
#define KEY_END	    "-----END TOKEN KEY-----"


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <Origin.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "IDtoken.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDtoken_OBJID)
#error Object identifier not defined.
#endif


/** IDtoken private state information. */
struct NAAAIM_IDtoken_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Organizational identity components. */
	Buffer orgkey;
	Buffer orgid;

	/* Patient identity. */
	Buffer ptid;

	/* Token key. */
	Buffer idkey;
};


/**
 * Internal private function.
 *
 * This function is used to automate input and processing of a line
 * of text from an input stream.  The linefeed in the input file if
 * any is converted to a NULL character.
 *
 * \param input		A pointer to the input stream to be read.
 *
 * \param bufr		A pointer to the buffer which the input line
 *			is to be read into.
 *
 * \param cnt		The maximum number of characters to bread.
 *
 * \return		A boolean value is used to indicate the status
 *			of the read.  A true value indicates the
 *			supplied buffer contains valid data.
 */

static _Bool _getline(FILE *input, char * const bufr, const size_t cnt)

{
	auto char *p;


	if ( fgets(bufr, cnt, input) == NULL )
		return false;
	if ( (p = strchr(bufr, '\n')) != NULL )
		*p = '\0';

	return true;
}
	

/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDtoken_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const IDtoken_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDtoken_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements parsing of an ASCII encoded identity token.  The
 * token consists of a guard pair of delimiters of the following form:
 *
 * -----BEGIN IDENTITY TOKEN-----
 * -----END IDENTITY TOKEN-----
 *
 * Detection of this pair starts the parser.  The patient specific
 * organizational identity is delimited by the following pair of
 * delimiters:
 *
 * -----BEGIN ORGANIZATION IDENTITY-----
 * -----END ORGANIZATION IDENTITY-----
 *
 * The patient identifier is then delimited by the following guard pair:
 *
 * -----BEGIN PATIENT IDENTITY-----
 * -----END PATIENT IDENTITY-----
 *
 * There may also be an optional data element delimited by the following
 * pair:
 *
 * -----BEGIN TOKEN KEY-----
 * -----END TOKEN KEY-----
 *
 * This latter pairing is designed to be parsed out and retained by
 * the organization issueing the identity.
 *
 * \param this	The object describing an identity token to be manipulated.
 *
 * \param input	The file stream to be parsed.
 *
 * \return	A boolean value is used to indicate the status of the
 *		parsing of the object.
 */

static _Bool parse(const IDtoken const this, FILE *input)

{
	auto char inbufr[80];


	while ( _getline(input, inbufr, sizeof(inbufr)) ) {
		if ( strcmp(inbufr, TOKEN_START) == 0 ) {
			fputs("Token start.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, TOKEN_END) == 0 ) {
			fputs("Token end.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, ORGID_START) == 0 ) {
			fputs("Org id start.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, ORGID_END) == 0 ) {
			fputs("org id end.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, PTID_START) == 0 ) {
			fputs("patient id start.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, PTID_END) == 0 ) {
			fputs("patient id end.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, KEY_START) == 0 ) {
			fputs("identity key start.\n", stdout);
			continue;
		}
		if ( strcmp(inbufr, KEY_END) == 0 ) {
			fputs("identity key end.\n", stdout);
			continue;
		}
	}

	return true;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDtoken object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const IDtoken const this)

{
	auto const IDtoken_State const S = this->state;


	S->orgkey->whack(S->orgkey);
	S->orgkey->whack(S->orgid);
	S->orgkey->whack(S->ptid);
	S->orgkey->whack(S->idkey);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a IDtoken object.
 *
 * \return	A pointer to the initialized IDtoken.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDtoken NAAAIM_IDtoken_Init(void)

{
	auto Origin root;

	auto IDtoken this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDtoken);
	retn.state_size   = sizeof(struct NAAAIM_IDtoken_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDtoken_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->orgkey = HurdLib_Buffer_Init()) == NULL )
		return NULL;
	if ( (this->state->orgid = HurdLib_Buffer_Init()) == NULL ) {
		this->state->orgkey->whack(this->state->orgkey);
		return NULL;
	}
	if ( (this->state->ptid = HurdLib_Buffer_Init()) == NULL ) {
		this->state->orgkey->whack(this->state->orgkey);
		this->state->orgid->whack(this->state->orgid);
		return NULL;
	}
	if ( (this->state->idkey = HurdLib_Buffer_Init()) == NULL ) {
		this->state->orgkey->whack(this->state->orgkey);
		this->state->orgid->whack(this->state->orgid);
		this->state->ptid->whack(this->state->ptid);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->parse = parse;
	this->whack = whack;

	return this;
}
