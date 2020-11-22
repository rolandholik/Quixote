/** \file
 * This file contains the implementation of an object which manages
 * identity verification objects.
 *
 * An identify verification object contains the information which is
 * needed to verify the status of a remote host which is requesting
 * machine status verification.
 *
 * The following data elements are incorporated in an identity
 * verification data structure:
 *
 *	Identity token
 *	Identity attestation public key
 *	Software status
 *	Machine status reference
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "IDtoken.h"
#include "Ivy.h"

/* Object state extraction macro. */
#define STATE(var) CO(Ivy_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Ivy_OBJID)
#error Object identifier not defined.
#endif


/** Ivy private state information. */
struct NAAAIM_Ivy_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Identity token. */
	Buffer id;

	/* Attestation identity public key. */
	Buffer pubkey;

	/* Software status. */
	Buffer software;

	/* Machine status reference. */
	Buffer reference;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of an identity.
 * the wire.
 */
typedef struct {
	ASN1_OCTET_STRING *id;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *software;
	ASN1_OCTET_STRING *reference;
} asn1_ivy;

ASN1_SEQUENCE(asn1_ivy) = {
	ASN1_SIMPLE(asn1_ivy, id,		ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_ivy, pubkey,		ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_ivy, software,		ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_ivy, reference,	ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(asn1_ivy)

IMPLEMENT_ASN1_FUNCTIONS(asn1_ivy)

#define ASN1_BUFFER_ENCODE(b, e, err) \
	if ( ASN1_OCTET_STRING_set(e, b->get(b), b->size(b)) != 1 ) \
		err

#define ASN1_BUFFER_DECODE(b, e, err) \
	if ( !b->add(b, ASN1_STRING_get0_data(e), ASN1_STRING_length(e)) ) \
 		err


/**
 * External public method.
 *
 * This method implements an accessor for obtaining the various verifier
 * elements from this object.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed.
 *
 * \param this		The verifier whose elements are to be accessed.
 *
 * \param element	The element which is to be returned.
 *
 * \return		The Buffer object containing the desired element
 *			is returned.
 */

static Buffer get_element(CO(Ivy, this), CO(Ivy_element, element))

{
	STATE(S);


	if ( S->poisoned )
		return NULL;

	switch ( element ) {
		case Ivy_id:
			return S->id;
			break;
		case Ivy_pubkey:
			return S->pubkey;
			break;
		case Ivy_software:
			return S->software;
			break;
		case Ivy_reference:
			return S->reference;
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
 * This method implements an accessor for setting the various verifier
 * elements in this token.  A multiplexed accessor is used in order
 * diminish the number of separate methods needed to set the
 * multiple elements in the object.
 *
 * \param this		The verifier whose elements are to be set.
 *
 * \param element	The identity component to be set.
 * 
 * \param bufr		The data to be used for setting the element.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of setting the verifier element.  A true
 *			value is used to indicate success of the
 *			operation.  If a failure is detected in setting
 *			any component the object is poisoned.
 */

static _Bool set_element(CO(Ivy, this), CO(Ivy_element, element), \
			 CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	switch ( element ) {
		case Ivy_id:
			if ( !S->id->add_Buffer(S->id, bufr) )
				goto done;
			break;
		case Ivy_pubkey:
			if ( !S->pubkey->add_Buffer(S->pubkey, bufr) )
				goto done;
			break;
		case Ivy_software:
			if ( !S->software->add_Buffer(S->software, bufr) )
				goto done;
			break;
		case Ivy_reference:
			if ( !S->reference->add_Buffer(S->reference, bufr) )
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
 * This method implements adding an identity to the verification object.
 *
 * \param this		The verifier whose identity is to be set.
 *
 * \param identity	The identity token containg the device identity.
 *
 * \return		A boolean value is used to indicate the success or
 *			failure of setting the identity.  A true
 *			value indicates the identity was set.  A failure
 *			is indicated by returning a false value which
 *			also poisons the object.
 */

static _Bool set_identity(CO(Ivy, this), CO(IDtoken, identity))

{
	STATE(S);

	_Bool retn = false;

	Buffer b,
	       bufr = NULL;


	if ( S->poisoned )
		goto done;
	if ( identity == NULL )
		goto done;


	/* Convert identity and add the reduced identity to this object. */
	INIT(HurdLib, Buffer, bufr, goto done);

	if ( (b = identity->get_element(identity, IDtoken_id)) == NULL )
		goto done;
	if ( b->size(b) != NAAAIM_IDSIZE )
		identity->to_verifier(identity);

	if ( !identity->encode(identity, bufr) )
		goto done;
	if ( !set_element(this, Ivy_id, bufr) )
		goto done;

	retn = true;
	

 done:
	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the encoding of an identity verification object
 * into ASN1 format.
 *
 * \param this		The verifier which is to be encoded.
 *
 * \param output	A Buffer object which holds the encoding of
 *			the verifier.
 * 
 * \return		A boolean value is used to indicate the success or
 *			failure of verifier encoding.  A true
 *			value is used to indicate the identity was
 *			successfuly encoded.  A failure is indicated by
 *			a false value.
 */

static _Bool encode(CO(Ivy, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int asn_size;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	asn1_ivy *verifier = NULL;


	if ( (verifier = asn1_ivy_new()) == NULL )
		goto done;

	/* Encode the identity. */
	ASN1_BUFFER_ENCODE(S->id, verifier->id, goto done);

	/* Encode the public key .*/
	ASN1_BUFFER_ENCODE(S->pubkey, verifier->pubkey, goto done);

	/* Encode the software status. */
	ASN1_BUFFER_ENCODE(S->software, verifier->software, goto done);

	/* Encode the machine reference. */
	ASN1_BUFFER_ENCODE(S->reference, verifier->reference, goto done);

	/* Load the ASN1 encoding into the supplied buffer. */
        asn_size = i2d_asn1_ivy(verifier, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( verifier != NULL )
		asn1_ivy_free(verifier);

	return retn;
}


/**
 * External public method.
 *
 * This method implements a method for decoding an ientity verifier
 * which has been encoded by the ->encode method in ASN1 format.
 *
 * \param this		The token which is to be loaded with the decoded
 *			verifier components.
 *
 * \param output	A Buffer object which holds the ASN1 encoded
 *			verifier information.
 * 
 * \return		A boolean value is used to indicate the success or
 *			failure of the verifier decoding.  A true
 *			value is used to indicate the verifier was
 *			successfuly decoded.  A failure is indicated by
 *			a false value.
 */

static _Bool decode(CO(Ivy, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	asn1_ivy *verifier = NULL;


	p = bufr->get(bufr);
        if ( !d2i_asn1_ivy(&verifier, &p, bufr->size(bufr)) )
                goto done;

	/* Unpack the identity token. */
	ASN1_BUFFER_DECODE(S->id, verifier->id, goto done);

	/* Unpack the attestation identity key. */
	ASN1_BUFFER_DECODE(S->pubkey, verifier->pubkey, goto done);

	/* Unpack the software reference. */
	ASN1_BUFFER_DECODE(S->software, verifier->software, goto done);

	/* Unpack the software reference. */
	ASN1_BUFFER_DECODE(S->reference, verifier->reference, goto done);

	retn = true;


 done:
	if ( verifier != NULL )
		asn1_ivy_free(verifier);
	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Ivy_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(Ivy_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Ivy_OBJID;

	S->poisoned = false;

	S->id	     = NULL;
	S->pubkey    = NULL;
	S->software  = NULL;
	S->reference = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements printing out the various elements in the
 * identity verification file.
 *
 * \param this	A pointer to the object whose contents are to be
 *		printed.
 */

static void print(CO(Ivy, this))

{
	STATE(S);


	if ( S->poisoned ) {
		fputs("* POISONED *\n", stdout);
		return;
	}

	fputs("Identity token:\n", stdout);
	S->id->print(S->id);

	fputs("\nAttestation key:\n", stdout);
	S->pubkey->print(S->pubkey);

	fputs("\nSoftware status:\n", stdout);
	S->software->print(S->software);

	fputs("\nMachine reference:\n", stdout);
	S->reference->print(S->reference);

	return;
}


/**
 * External public method.
 *
 * This method implements the reset of an identity verification object.
 * It encapsulates the issuance of ->reset calls to the underlying
 * Buffer objects which contain the various identity verification
 * elements.
 *
 * \param this	A pointer to the object which is to be reset.
 *
 * \return	No return value is defined.
 */

static void reset(CO(Ivy, this))

{
	STATE(S);


	if ( S->poisoned )
		return;

	S->id->reset(S->id);
	S->pubkey->reset(S->pubkey);
	S->software->reset(S->software);
	S->reference->reset(S->reference);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Ivy object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Ivy, this))

{
	STATE(S);


	WHACK(S->id);
	WHACK(S->pubkey);
	WHACK(S->software);
	WHACK(S->reference);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a Ivy object.
 *
 * \return	A pointer to the initialized Ivy.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Ivy NAAAIM_Ivy_Init(void)

{
	auto Origin root;

	auto Ivy this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Ivy);
	retn.state_size   = sizeof(struct NAAAIM_Ivy_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Ivy_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->id, goto fail);
	INIT(HurdLib, Buffer, this->state->pubkey, goto fail);
	INIT(HurdLib, Buffer, this->state->software, goto fail);
	INIT(HurdLib, Buffer, this->state->reference, goto fail);

	/* Method initialization. */
	this->get_element  = get_element;
	this->set_element  = set_element;
	this->set_identity = set_identity;

	this->encode = encode;
	this->decode = decode;

	this->print = print;
	this->reset = reset;
	this->whack = whack;

	return this;


 fail:
	WHACK(this->state->id);
	WHACK(this->state->pubkey);
	WHACK(this->state->software);
	WHACK(this->state->reference);

	root->whack(root, this, this->state);
	return NULL;
}
