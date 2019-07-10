/** \file
 *
  */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define AUTHENREPLY_MAGIC 0x2019C3

/* Include files. */
#include <stdint.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <HurdLib.h>

#include "NAAAIM.h"
#include "AuthenReply.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_AuthenReply_OBJID)
#error Object identifier not defined.
#endif


/** AuthenReply private state information. */
struct NAAAIM_AuthenReply_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Identity elements. */
	Buffer elements;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the authenticator which will be transmitted over
 * the wire.
 */
typedef struct {
	ASN1_INTEGER *magic;
	ASN1_OCTET_STRING *elements;
} authenreply_payload;

ASN1_SEQUENCE(authenreply_payload) = {
	ASN1_SIMPLE(authenreply_payload, magic,	   ASN1_INTEGER),
	ASN1_SIMPLE(authenreply_payload, elements, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(authenreply_payload)

IMPLEMENT_ASN1_FUNCTIONS(authenreply_payload)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_AuthenReply_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const AuthenReply_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_AuthenReply_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements adding one or more identity elements to the
 * authentication reply.
 *
 * \param this	The authentication reply which is to have the identity
 *		elements added to it.
 *
 * \param bufr	The elements to be added to the authenticator.
 *
 * \return	A boolean value is used to indicate whether or not
 *		adding the identity elements was successful.  A true
 *		value is used to indicate success.  On failure the
 *		object is poisoned for further use.
 */

static _Bool add_elements(const AuthenReply const this,
			  const Buffer const bufr)

{
	auto const AuthenReply_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( !S->elements->add_Buffer(S->elements, bufr) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return true;
}


/**
 * External public method.
 *
 * This method implements retrieval of the identity elements.
 *
 * \param this	The authentication reply whose identity elements is to
 *		be returned.
 *
 * \param bufr	The buffer object which the identity elements are to
 *		be loaded into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		adding the identity elements was successful.  A true
 *		value is used to indicate success.  On failure the
 *		object is poisoned for further use.
 */

static _Bool get_elements(const AuthenReply const this,
			  const Buffer const bufr)

{
	auto const AuthenReply_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( !bufr->add_Buffer(bufr, S->elements) )
		goto done;

	retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	return true;
}


/**
 * External public method.
 *
 * This method implements encoding of an authentication reply into a
 * DER blob.
 *
 * \param this	The authentication reply to be encoded.
 *
 * \param bufr	The Buffer into which the DER output is to be placed.
 *
 * \return	A boolean value is used to return success or failure of
 *		the encoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool encode(const AuthenReply const this, const Buffer const bufr)

{
	auto const AuthenReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto unsigned int magic = AUTHENREPLY_MAGIC;

	auto authenreply_payload *payload = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;

	if ( (payload = authenreply_payload_new()) == NULL )
		goto done;

        if ( ASN1_INTEGER_set(payload->magic, magic) != 1 )
                goto done;
        if ( ASN1_OCTET_STRING_set(payload->elements, \
				   S->elements->get(S->elements), \
                                   S->elements->size(S->elements)) != 1 )
                goto done;


        asn_size = i2d_authenreply_payload(payload, p);
        if ( asn_size < 0 )
                goto done;

	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( retn == false )
		S->poisoned = true;
	if ( payload != NULL )
		authenreply_payload_free(payload);

	return retn;
}


/**
 * External public method.
 *
 * This method implements decoding the contents of a DER encoded ASN1
 * structure into an authentication reply object.  The binary encoding is
 * provided by a Buffer supplied by the caller.
 *
 * \param this	The authentication response which is to receive the
 *		encoded object.
 *
 * \param bufr	A buffer object containing the encoded structure to
 *		loaded.
 *
 * \return	A boolean value is used to return success or failure of
 *		the decoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool decode(const AuthenReply const this, const Buffer const bufr)

{
	auto const AuthenReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto int asn_size;

	auto unsigned int magic;

	auto authenreply_payload *payload = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_authenreply_payload(&payload, &p, asn_size) )
                goto done;

	magic = ASN1_INTEGER_get(payload->magic);
	if ( magic != AUTHENREPLY_MAGIC )
		goto done;

	S->elements->add(S->elements,				   \
			 ASN1_STRING_get0_data(payload->elements), \
			 ASN1_STRING_length(payload->elements));
	if ( S->elements->poisoned(S->elements) )
		goto done;

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( payload != NULL )
		authenreply_payload_free(payload);

	return retn;
}


/**
 * External public method.
 *
 * This method implements printing the contents of an authentication
 * reply.
 *
 * \param this	A pointer to the object which is to be printed.
 */

static void print(const AuthenReply const this)

{
	auto const AuthenReply_State const S = this->state;


	if ( S->poisoned )
		fputs("* POISONED *\n", stderr);
	else
		S->elements->print(S->elements);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a AuthenReply object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const AuthenReply const this)

{
	auto const AuthenReply_State const S = this->state;


	if ( S->elements != NULL )
		S->elements->whack(S->elements);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a AuthenReply object.
 *
 * \return	A pointer to the initialized AuthenReply.  A null value
 *		indicates an error was encountered in object generation.
 */

extern AuthenReply NAAAIM_AuthenReply_Init(void)

{
	auto Origin root;

	auto AuthenReply this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_AuthenReply);
	retn.state_size   = sizeof(struct NAAAIM_AuthenReply_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_AuthenReply_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->elements = HurdLib_Buffer_Init()) == NULL ) {
                root->whack(root, this, this->state);
                return NULL;
        }

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->add_elements = add_elements;
	this->get_elements = get_elements;
	this->encode	   = encode;
	this->decode	   = decode;
	this->print	   = print;
	this->whack	   = whack;

	return this;
}
