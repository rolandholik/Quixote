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
#include "SHA256_hmac.h"


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
 * Internal private function.
 *
 * This function implements verification that an input line is a valid
 * hexadecimal input string.  In order to fullfill the validity the
 * string has to be 64 characters in length and consist of only the
 * characters 0-9 and a-f.
 *
 * \param bufr	A pointer to the input buffer to be verified.
 *
 * \return	A return value of true indicated the buffer is
 *		acceptable, a false value indicates it failed to pass
 *		the concordance test.
 */

static _Bool _hex_string(const char * const bufr)

{
	auto const char *p = bufr;


	if ( strlen(bufr) != 64 )
		return false;

	while ( *p != '\0' )
		if ( strchr("0123456789abcdefABCDEF", *p++) == NULL )
			return false;

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
 * This method implements an accessor for obtaining the various identity
 * elements from this token.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed.
 *
 * \param this		The token whose elements are to be accessed.
 *
 * \param element	The element which is to be returned.
 *
 * \return		The Buffer object containing the desired element
 *			is returned.
 */

static Buffer get_element(const IDtoken const this, \
			  const IDtoken_element element)

{
	auto const IDtoken_State const S = this->state;


	if ( S->poisoned )
		return NULL;

	switch ( element ) {
		case IDtoken_orgkey:
			return S->orgkey;
			break;
		case IDtoken_orgid:
			return S->orgid;
			break;
		case IDtoken_id:
			return S->ptid;
			break;
		default:
			return NULL;
			break;
	}

	return NULL;
}


/**
 * External public method.
 *
 * This method implements an accessor for setting the various identity
 * elements in this token.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed to acces the
 * multiple elements in the object.
 *
 * \param this		The token whose elements are to be accessed.
 *
 * \param element	The identity component to be set.
 * 
 * \param bufr		The data to be used for setting the element.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of setting the identity component.  A true
 *			value is used to indicate success of the
 *			operation.  If a failure is detected in setting
 *			any component the object is poisoned.
 */

static _Bool set_element(const IDtoken const this,	\
			 const IDtoken_element const element, \
			 const Buffer const bufr)

{
	auto const IDtoken_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;

	switch ( element ) {
		case IDtoken_orgkey:
			if ( !S->orgkey->add_Buffer(S->orgkey, bufr) )
				goto done;
			break;
		case IDtoken_orgid:
			if ( !S->orgid->add_Buffer(S->orgid, bufr) )
				goto done;
			break;
		case IDtoken_id:
			if ( !S->ptid->add_Buffer(S->ptid, bufr) )
				goto done;
			break;
		default:
			goto done;
			break;
	}

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return retn;
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
	auto const IDtoken_State const S = this->state;

	auto _Bool token_started = false,
		   ptid_started  = false,
		   key_started   = false;

	auto char inbufr[80];

	auto unsigned int orgid_cnt = 0;


	while ( _getline(input, inbufr, sizeof(inbufr)) ) {
		/* Parse identity token start/stop pairs. */
		if ( strcmp(inbufr, TOKEN_START) == 0 )
			token_started = true;
		if ( !token_started )
			continue;
		if ( strcmp(inbufr, TOKEN_END) == 0 ) {
			if ( ptid_started || key_started || (orgid_cnt > 0) )
				return false;
			return true;
		}


		/* Parse organizational identity pairs. */
		if ( strcmp(inbufr, ORGID_START) == 0 ) {
			++orgid_cnt;
			continue;
		}
		if ( strcmp(inbufr, ORGID_END) == 0 ) {
			orgid_cnt = 0;
			if ( S->orgkey->size(S->orgkey) != 32 )
				goto err;
			if ( S->orgid->size(S->orgid) != 32 )
				goto err;
			continue;
		}
		if ( orgid_cnt > 0 ) {
			if ( !_hex_string(inbufr) )
				continue;
			if ( orgid_cnt == 1 ) {
				S->orgkey->add_hexstring(S->orgkey, inbufr);
				++orgid_cnt;
				continue;
			}
			if ( orgid_cnt == 2 ) {
				S->orgid->add_hexstring(S->orgid, inbufr);
				++orgid_cnt;
			}
		}


		/* Parse patient identity pairs. */
		if ( strcmp(inbufr, PTID_START) == 0 ) {
			ptid_started = true;
			continue;
		}
		if ( strcmp(inbufr, PTID_END) == 0 ) {
			ptid_started = false;
			if ( S->ptid->size(S->ptid) != 256 )
				goto err;
			continue;
		}
		if ( ptid_started ) {
			if ( !_hex_string(inbufr) )
				continue;
			S->ptid->add_hexstring(S->ptid, inbufr);
		}


		/* Parse optional key identity pairs. */
		if ( strcmp(inbufr, KEY_START) == 0 ) {
			key_started = true;
			continue;
		}
		if ( strcmp(inbufr, KEY_END) == 0 ) {
			key_started = false;
			if ( S->idkey->size(S->idkey) != 32 )
				goto err;
			continue;
		}
		if ( key_started ) {
			if ( !_hex_string(inbufr) )
				continue;
			S->idkey->add_hexstring(S->idkey, inbufr);
		}
	}


 err:
	this->state->poisoned = true;
	return false;
}


/**
 * External public method.
 *
 * This method tests whether or not the identity token was generated by
 * the organization with the specified identity.
 *
 * \param this	The identity token to be tested.
 *
 * \param id	A Buffer object containing the binary representation of
 *		the identity to be tested.
 *
 * \return	A boolean value indicating whether or not the token
 *		was generated by the specified identity.  A false
 *		value may also be returned if the object is dysfunctional.
 */

static _Bool matches(const IDtoken const this, const Buffer const id)

{
	auto const IDtoken_State const S = this->state;

	auto _Bool retn = false;

	auto SHA256_hmac hmac = NULL;


	/* 
	 * Activate a hashed messaging object and hash the organizational
	 * identity against the key specified with the user specific
	 * organizational identity.
	 */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(S->orgkey)) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	hmac->add_Buffer(hmac, id);
	if ( !hmac->compute(hmac) )
		goto done;

	/*
	 * Verify the computed organizational identity against the
	 * identity supplied in the token.
	 */
	if ( memcmp(S->orgid->get(S->orgid), hmac->get(hmac), \
		    S->orgid->size(S->orgid) ) == 0 )
		retn = true;


 done:
	if ( hmac != NULL )
		hmac->whack(hmac);

	return retn;
}


/**
 * External public method.
 *
 * This method prints out the identity token in ASCII delimited format.
 * The output format will be in the format described in the parse
 * method.
 *
 * \param this	The object defining the identity token to be printed.
 */

static void print(const IDtoken const this)

{
	auto const IDtoken_State const S = this->state;

	auto unsigned char *p;

	auto unsigned int lp;

	
	/* Sanity check for a dysfunctional object. */
	if ( this->state->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}


	/* Output the ASCII delimited components of the token. */
	fputs("-----BEGIN IDENTITY TOKEN-----\n", stdout);

	fputs("-----BEGIN ORGANIZATION IDENTITY-----\n", stdout);
	S->orgkey->print(S->orgkey);
	S->orgid->print(S->orgid);
	fputs("-----END ORGANIZATION IDENTITY-----\n", stdout);

	fputs("-----BEGIN PATIENT IDENTITY-----\n", stdout);
	p = S->ptid->get(S->ptid);
	for (lp= 1; lp <= S->ptid->size(S->ptid); ++lp) {
		fprintf(stdout, "%02x", *(p + lp - 1));
		if ( ((lp % 32) == 0) )
			fputc('\n', stdout);
	}
	fputs("-----END PATIENT IDENTITY-----\n", stdout);

	if ( S->idkey->size(S->idkey) > 0 ) {
		fputs("-----BEGIN TOKEN KEY-----\n", stdout);
		S->idkey->print(S->idkey);
		fputs("-----END TOKEN KEY-----\n", stdout);
	}

	fputs("-----END IDENTITY TOKEN-----\n", stdout);

	return;
}


/**
 * External public method.
 *
 * This method implements resetting of an identity token object.  It
 * is typically used to allow parsing of multiple identity files.
 *
 * \param this	The object to be reset.
 */

static void reset(const IDtoken const this)

{
	auto const IDtoken_State const S = this->state;


	if ( S->poisoned )
		return;

	S->orgkey->reset(S->orgkey);
	S->orgid->reset(S->orgid);
	S->ptid->reset(S->ptid);
	S->idkey->reset(S->idkey);

	return;
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
	S->orgid->whack(S->orgid);
	S->ptid->whack(S->ptid);
	S->idkey->whack(S->idkey);

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
	this->get_element = get_element;
	this->set_element = set_element;
	this->parse	  = parse;
	this->matches	  = matches;
	this->print	  = print;
	this->reset	  = reset;
	this->whack	  = whack;

	return this;
}
