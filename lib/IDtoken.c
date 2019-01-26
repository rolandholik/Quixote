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
#define TOKEN_START		"-----BEGIN IDENTITY TOKEN-----"
#define TOKEN_END		"-----END IDENTITY TOKEN-----"

#define ASSERTION_START		"-----BEGIN ASSERTION-----"
#define ASSERTION_END		"-----END ASSERTION-----"

#define IMPLEMENTATION_START	"-----BEGIN IMPLEMENTATION-----"
#define IMPLEMENTATION_END	"-----END IMPLEMENTATION-----"

#define AUTHENTICATION_START	"-----BEGIN AUTHENTICATION-----"
#define AUTHENTICATION_END	"-----END AUTHENTICATION-----"


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "IDtoken.h"
#include "SHA256.h"
#include "SHA256_hmac.h"

/* Object state extraction macro. */
#define STATE(var) CO(IDtoken_State, var) = this->state

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
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of an identity.
 * the wire.
 */
typedef struct {
	ASN1_OCTET_STRING *assertion_key;
	ASN1_OCTET_STRING *assertion_id;
	ASN1_OCTET_STRING *implementation;
	ASN1_OCTET_STRING *authentication;
} asn1_identity;

ASN1_SEQUENCE(asn1_identity) = {
	ASN1_SIMPLE(asn1_identity, assertion_key,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_identity, assertion_id,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_identity, implementation,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_identity, authentication,	ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(asn1_identity)

IMPLEMENT_ASN1_FUNCTIONS(asn1_identity)

#define ASN1_BUFFER_ENCODE(b, e, err) \
	if ( ASN1_OCTET_STRING_set(e, b->get(b), b->size(b)) != 1 ) \
		err

#define ASN1_BUFFER_DECODE(b, e, err) \
	if ( !b->add(b, ASN1_STRING_get0_data(e), ASN1_STRING_length(e)) ) \
 		err


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
	char *p;


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

static _Bool _hex_string(CO(char *, bufr))

{
	const char *p = bufr;


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

static void _init_state(CO(IDtoken_State, S)) {

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

static Buffer get_element(CO(IDtoken, this), CO(IDtoken_element, element))

{
	STATE(S);


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
		case IDtoken_key:
			return S->idkey;
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

static _Bool set_element(CO(IDtoken, this), CO(IDtoken_element, element), \
			 CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


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
		case IDtoken_key:
			if ( !S->idkey->add_Buffer(S->idkey, bufr) )
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
 * This method implements a method for encoding an identity in
 * ASN1 format.  The ->decode method reciprocates this operation.
 *
 * \param this		The token holding the identity which is to be
 *			encoded.
 *
 * \param output	A Buffer object which holds the encoding of
 *			the identity.
 * 
 * \return		A boolean value is used to indicate the success or
 *			failure of identity encoding.  A true
 *			value is used to indicate the identity was
 *			successfuly encoded.  A failure is indicated by
 *			a false value.
 */

static _Bool encode(CO(IDtoken, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int asn_size;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	asn1_identity *identity = NULL;


	if ( (identity = asn1_identity_new()) == NULL )
		goto done;

	/* Encode the identity assertion. */
	ASN1_BUFFER_ENCODE(S->orgkey, identity->assertion_key, goto done);
	ASN1_BUFFER_ENCODE(S->orgid, identity->assertion_id, goto done);

	/* Encode the identity implementation .*/
	ASN1_BUFFER_ENCODE(S->ptid, identity->implementation, goto done);

	/* Encode the identity key. */
	ASN1_BUFFER_ENCODE(S->idkey, identity->authentication, goto done);

	/* Load the ASN1 encoding into the supplied buffer. */
        asn_size = i2d_asn1_identity(identity, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( identity != NULL )
		asn1_identity_free(identity);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for decoding an identity which
 * has been encoded by the ->encode method in ASN1 format.
 *
 * \param this		The token which is to be loaded with the decoded
 *			identity information.
 *
 * \param output	A Buffer object which holds the ASN1 encoded
 *			identity information.
 * 
 * \return		A boolean value is used to indicate the success or
 *			failure of the identity decoding.  A true
 *			value is used to indicate the identity was
 *			successfuly decoded.  A failure is indicated by
 *			a false value.
 */

static _Bool decode(CO(IDtoken, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	asn1_identity *identity = NULL;


	p = bufr->get(bufr);
        if ( !d2i_asn1_identity(&identity, &p, bufr->size(bufr)) )
                goto done;

	/* Unpack the identity assertion. */
	ASN1_BUFFER_DECODE(S->orgkey, identity->assertion_key, goto done);
	ASN1_BUFFER_DECODE(S->orgid, identity->assertion_id, goto done);

	/* Unpack the identity implementation. */
	ASN1_BUFFER_DECODE(S->ptid, identity->implementation, goto done);

	/* Unpack the identity key. */
	ASN1_BUFFER_DECODE(S->idkey, identity->authentication, goto done);

	retn = true;


 done:
	if ( identity != NULL )
		asn1_identity_free(identity);
	return retn;
}


/**
 * External public method.
 *
 * This method implements the conversion of the identity token into
 * identity verified format.  This conversion involves hashing the
 * identity implementation into a 256 bit representation of that
 * identity.
 *
 * \param this		The token which is to be loaded with the decoded
 *			identity information.
 *
 * \return		A boolean value is used to indicate the success
 *			or ailure of the converion.  A true value is used
 *			value is used to indicate the identity was
 *			successfuly converted.  A failure is indicated by
 *			a false value.
 */

static _Bool to_verifier(CO(IDtoken, this))

{
	STATE(S);

	_Bool retn = false;

	Sha256 mac = NULL;


	if ( S->poisoned )
		goto done;
	if ( S->ptid->size(S->ptid) != 256 )
		goto done;

	INIT(NAAAIM, Sha256, mac, goto done);
	mac->add(mac, S->ptid);
	if ( !mac->compute(mac) )
		goto done;

	S->ptid->reset(S->ptid);
	if ( !S->ptid->add_Buffer(S->ptid, mac->get_Buffer(mac)) )
		goto done;

	retn = true;

 done:
	WHACK(mac);

	if ( !retn )
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
 * -----BEGIN ASSERTION-----
 * -----END ASSERTION-----
 *
 * The patient identifier is then delimited by the following guard pair:
 *
 * -----BEGIN IMPLEMENTATION-----
 * -----END IMPLEMENTATION-----
 *
 * There may also be an optional data element delimited by the following
 * pair:
 *
 * -----BEGIN AUTHENTICATION-----
 * -----END AUTHENTICATION-----
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
	STATE(S);

	_Bool token_started = false,
		   ptid_started  = false,
		   key_started   = false;

	char inbufr[80];

	unsigned int orgid_cnt = 0;


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
		if ( strcmp(inbufr, ASSERTION_START) == 0 ) {
			++orgid_cnt;
			continue;
		}
		if ( strcmp(inbufr, ASSERTION_END) == 0 ) {
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
		if ( strcmp(inbufr, IMPLEMENTATION_START) == 0 ) {
			ptid_started = true;
			continue;
		}
		if ( strcmp(inbufr, IMPLEMENTATION_END) == 0 ) {
			ptid_started = false;
			if ( (S->ptid->size(S->ptid) != 256) &&
			     (S->ptid->size(S->ptid) != 32) )
			continue;
		}
		if ( ptid_started ) {
			if ( !_hex_string(inbufr) )
				continue;
			S->ptid->add_hexstring(S->ptid, inbufr);
		}


		/* Parse optional key identity pairs. */
		if ( strcmp(inbufr, AUTHENTICATION_START) == 0 ) {
			key_started = true;
			continue;
		}
		if ( strcmp(inbufr, AUTHENTICATION_END) == 0 ) {
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

static _Bool matches(CO(IDtoken, this), CO(Buffer, id))

{
	STATE(S);

	_Bool retn = false;

	SHA256_hmac hmac = NULL;


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
	WHACK(hmac);

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
	STATE(S);

	unsigned char *p;

	unsigned int lp;

	
	/* Sanity check for a dysfunctional object. */
	if ( S->poisoned ) {
		fputs("* POISONED *\n", stderr);
		return;
	}


	/* Output the ASCII delimited components of the token. */
	fprintf(stdout, "%s\n", TOKEN_START);

	fprintf(stdout, "%s\n", ASSERTION_START);
	S->orgkey->print(S->orgkey);
	S->orgid->print(S->orgid);
	fprintf(stdout, "%s\n", ASSERTION_END);

	fprintf(stdout, "%s\n", IMPLEMENTATION_START);
	p = S->ptid->get(S->ptid);
	for (lp= 1; lp <= S->ptid->size(S->ptid); ++lp) {
		fprintf(stdout, "%02x", *(p + lp - 1));
		if ( ((lp % 32) == 0) )
			fputc('\n', stdout);
	}
	fprintf(stdout, "%s\n", IMPLEMENTATION_END);

	if ( S->idkey->size(S->idkey) > 0 ) {
		fprintf(stdout, "%s\n", AUTHENTICATION_START);
		S->idkey->print(S->idkey);
		fprintf(stdout, "%s\n", AUTHENTICATION_END);
	}

	fprintf(stdout, "%s\n", TOKEN_END);

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

static void reset(CO(IDtoken, this))

{
	STATE(S);


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

static void whack(CO(IDtoken, this))

{
	STATE(S);


	WHACK(S->orgkey);
	WHACK(S->orgid);
	WHACK(S->ptid);
	WHACK(S->idkey);

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
		WHACK(this->state->orgkey);
		return NULL;
	}
	if ( (this->state->ptid = HurdLib_Buffer_Init()) == NULL ) {
		WHACK(this->state->orgkey);
		WHACK(this->state->orgid);
		return NULL;
	}
	if ( (this->state->idkey = HurdLib_Buffer_Init()) == NULL ) {
		WHACK(this->state->orgkey);
		WHACK(this->state->orgid);
		WHACK(this->state->ptid);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->get_element = get_element;
	this->set_element = set_element;

	this->encode = encode;
	this->decode = decode;

	this->to_verifier = to_verifier;

	this->parse	= parse;
	this->matches	= matches;
	this->print	= print;

	this->reset = reset;
	this->whack = whack;

	return this;
}
