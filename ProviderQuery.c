/** \file
 * This file contains the method implementations for the object which
 * manages the queries and replies to and from the identity provider
 * server.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define PROVIDERQUERY_MAGIC 0x7001cc51


/* Include files. */
#include <stdint.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <HurdLib.h>
#include <String.h>

#include "NAAAIM.h"
#include "ProviderQuery.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ProviderQuery_OBJID)
#error Object identifier not defined.
#endif


/** ProviderQuery private state information. */
struct NAAAIM_ProviderQuery_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Type of protocol object. */
	ProviderQuery_type type;

	/* Patient identity. */
	Buffer payload;
};


/**
 * The following definitions define outer ASN1 encoding sequence for
 * the query reply.
 */
typedef struct {
	ASN1_INTEGER *magic;
	ASN1_ENUMERATED *type;
	ASN1_OCTET_STRING *payload;
} provider_query;

ASN1_SEQUENCE(provider_query) = {
	ASN1_SIMPLE(provider_query, magic,   ASN1_INTEGER),
	ASN1_SIMPLE(provider_query, type,    ASN1_ENUMERATED),
	ASN1_SIMPLE(provider_query, payload, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(provider_query)

IMPLEMENT_ASN1_FUNCTIONS(provider_query)


/**
 * The following definitions define the inner ASN1 encoding sequence
 * for a simple clinical information query.
 */
typedef struct {
	ASN1_OCTET_STRING *ptid;
} simple_query;

ASN1_SEQUENCE(simple_query) = {
	ASN1_SIMPLE(simple_query, ptid, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(simple_query)

IMPLEMENT_ASN1_FUNCTIONS(simple_query)


/**
 * The following definitions define the inner ASN1 encoding sequence
 * for a simple clinical information query.
 */
typedef struct {
	ASN1_OCTET_STRING *ptid;
	ASN1_PRINTABLESTRING *address;
	ASN1_INTEGER *verifier;
} simple_query_sms;

ASN1_SEQUENCE(simple_query_sms) = {
	ASN1_SIMPLE(simple_query_sms, ptid,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(simple_query_sms, address,	ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(simple_query_sms, verifier,	ASN1_INTEGER),
	
} ASN1_SEQUENCE_END(simple_query_sms)

IMPLEMENT_ASN1_FUNCTIONS(simple_query_sms)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_ProviderQuery_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const ProviderQuery_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_ProviderQuery_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method initializes and encodes a request for a simple query
 * for patient clinical information.
 *
 * \param this		The inquiry which is to be initialized.
 *
 * \param ptid		A buffer containing the patient identity for
 *			which the query is requested.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the encoding was successful.  A true
 *			value indicates success.
 */

static _Bool set_simple_query(const ProviderQuery const this, \
			      const Buffer const ptid)

{
	auto const ProviderQuery_State const S = this->state;

	auto char *err = NULL;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto simple_query *query = NULL;


	if ( S->poisoned || ptid->poisoned(ptid) ) {
		err = "Component elements are poisoned.";
		goto done;
	}


	if ( (query = simple_query_new()) == NULL ) {
		err = "Query initialized failed.";
		goto done;
	}

        if ( ASN1_OCTET_STRING_set(query->ptid, ptid->get(ptid), \
				   ptid->size(ptid)) != 1 )  {
		err = "Error setting patient identity.";
                goto done;
	}

        asn_size = i2d_simple_query(query, p);
        if ( asn_size < 0 ) {
		err = "Error in DER encoding.";
                goto done;
	}
	
	if ( !S->payload->add(S->payload, asn, asn_size) ) {
		err = "Error setting payload.";
		goto done;
	}

	S->type = PQquery_simple;
	

 done:
	if ( query != NULL )
		simple_query_free(query);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		return false;
	}

	return true;
}


/**
 * External public method.
 *
 * This method decodes and returns a patient identity encoded in a
 * simple provider query.
 *
 * \param this		The query which is to be decoded.
 *
 * \param ptid		A buffer which will be loaded with the patient
 *			identity.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the decoding was successful.  A true
 *			value indicates success.
 */

static _Bool get_simple_query(const ProviderQuery const this, \
			      const Buffer const ptid)

{
	auto const ProviderQuery_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto int asn_size;

	auto simple_query *query = NULL;


	if ( S->poisoned || ptid->poisoned(ptid) )
		goto done;


	p = S->payload->get(S->payload);
	asn_size = S->payload->size(S->payload);
        if ( !d2i_simple_query(&query, &p, asn_size) )
                goto done;	

	if ( !ptid->add(ptid, ASN1_STRING_get0_data(query->ptid), \
			ASN1_STRING_length(query->ptid)) ) {
		goto done;
	}

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( query != NULL )
		simple_query_free(query);

	return retn;

}


/**
 * External public method.
 *
 * This method initializes and encodes a request for a clinical
 * information query which is to also have an SMS message sent to the
 * provider.
 *
 * \param this		The inquiry which is to be initialized.
 *
 * \param ptid		A buffer containing the patient identity for
 *			which the query is requested.
 *
 * \param address	A pointer to a null-terminated character
 *			containing the address to which an SMS
 *			message is to be sent.
 *
 * \param verifier	The verifier code to be used in the SMS
 *			message.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the encoding was successful.  A true
 *			value indicates success.
 */

static _Bool set_simple_query_sms(const ProviderQuery const this, \
				  const Buffer const ptid,	  \
				  const char * const address,	  \
				  int const verifier)
				  
{
	auto const ProviderQuery_State const S = this->state;

	auto char *err = NULL;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto simple_query_sms *query = NULL;


	if ( S->poisoned || ptid->poisoned(ptid) ) {
		err = "Component elements are poisoned.";
		goto done;
	}


	if ( (query = simple_query_sms_new()) == NULL ) {
		err = "Query initialized failed.";
		goto done;
	}

        if ( ASN1_OCTET_STRING_set(query->ptid, ptid->get(ptid), \
				   ptid->size(ptid)) != 1 )  {
		err = "Error setting patient identity.";
                goto done;
	}

        if ( ASN1_STRING_set(query->address, address, strlen(address) + 1) \
			     != 1 ) {
		err = "Error setting sms address.";
                goto done;
	}

	if ( ASN1_INTEGER_set(query->verifier, verifier) != 1 ) {
		err = "Error setting verifier.";
		goto done;
	}

        asn_size = i2d_simple_query_sms(query, p);
        if ( asn_size < 0 ) {
		err = "Error in DER encoding.";
                goto done;
	}
	
	if ( !S->payload->add(S->payload, asn, asn_size) ) {
		err = "Error setting payload.";
		goto done;
	}

	S->type = PQquery_simple_sms;
	

 done:
	if ( query != NULL )
		simple_query_sms_free(query);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		return false;
	}

	return true;
}


/**
 * External public method.
 *
 * This method decodes and returns a patient identity encoded in a
 * simple provider query.
 *
 * \param this		The query which is to be decoded.
 *
 * \param ptid		A buffer which will be loaded with the patient
 *			identity.
 *
 * \param address	The object which is to contain the SMS address
 *			to which the patient information is to be
 *			sent.
 *
 * \param verifier	The numeric verifier which is to be included with
 *			the SMS message.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the decoding was successful.  A true
 *			value indicates success.
 */

static _Bool get_simple_query_sms(const ProviderQuery const this, \
				  const Buffer const ptid,	  \
				  const String const address,	  \
				  int * const verifier)

{
	auto const ProviderQuery_State const S = this->state;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto char *err = NULL;

	auto int asn_size;

	auto simple_query_sms *query = NULL;


	if ( S->poisoned || ptid->poisoned(ptid) ) {
		err = "Component objects are poisoned.";
		goto done;
	}


	p = S->payload->get(S->payload);
	asn_size = S->payload->size(S->payload);
        if ( !d2i_simple_query_sms(&query, &p, asn_size) ) {
		err = "Error during DER decoding.";
                goto done;
	}

	if ( !ptid->add(ptid, ASN1_STRING_get0_data(query->ptid), \
			ASN1_STRING_length(query->ptid)) ) {
		err = "Unable to load patient identity.";
		goto done;
	}

	if ( !address->add(address, \
			   (char *) ASN1_STRING_get0_data(query->address)) ) {
		err = "Unable to load SMS address.";
		goto done;
	}

	*verifier = ASN1_INTEGER_get(query->verifier);

	
 done:
	if ( query != NULL )
		simple_query_sms_free(query);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		S->poisoned = true;
		return false;
	}

	return true;
}


/**
 * External public method.
 *
 * This method implements outer encoding of the query reply.  It produces
 * the DER encoding of the on wire reply.
 *
 * \param this		The reply which is to be encoded.
 *
 * \param bufr		The Buffer object which is to be loaded with
 *			the DER encoding of the reply.
 *
 * \return		A boolen value is used to indicate whether or not
 *			the encoding was successful.  A true value indicates
 *			a successful encoding.
 */

static _Bool encode(const ProviderQuery const this, const Buffer const bufr)

{
	auto const ProviderQuery_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto provider_query *query = NULL;


	if ( S->poisoned )
		goto done;


	if ( (query = provider_query_new()) == NULL )
		goto done;

	if ( ASN1_INTEGER_set(query->magic, PROVIDERQUERY_MAGIC) != 1 )
		goto done;

	if ( ASN1_ENUMERATED_set(query->type, S->type) != 1 )
		goto done;

        if ( ASN1_OCTET_STRING_set(query->payload,		\
				   S->payload->get(S->payload),	\
				   S->payload->size(S->payload)) != 1 )
                goto done;

        asn_size = i2d_provider_query(query, p);
        if ( asn_size < 0 ) {
                goto done;
	}

	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( retn == false )
		S->poisoned = true;

	if ( query != NULL )
		provider_query_free(query);

	return retn;
}


/**
 * External public method.
 *
 * This method implements outer decoding of the provider query
 * protocol.  The on the wire DER representation is decoded into a
 * payload descriptor and a DER encoding of the protocol payload.
 *
 * \param this		The query which is to be decoded.
 *
 * \param bufr		The Buffer object containing the DER representation
 *			of the query protocol.
 *
 * \return		A boolaen value is used to indicate whether or not
 *			the decoding was successful.  A true value indicates
 *			a successful encoding.
 */

static _Bool decode(const ProviderQuery const this, const Buffer const bufr)

{
	auto const ProviderQuery_State const S = this->state;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto char *err = NULL;

	auto int asn_size;

	auto unsigned int magic;

	auto provider_query *query = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) ) {
		err = "Component objects are poisoned.";
		goto done;
	}


	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_provider_query(&query, &p, asn_size) ) {
		err = "Failed DER decoding.";
                goto done;
	}

	magic = ASN1_INTEGER_get(query->magic);
	if ( magic != PROVIDERQUERY_MAGIC ) {
		err = "Query magic number not valid.";
		goto done;
	}

	S->type = ASN1_ENUMERATED_get(query->type);

	S->payload->add(S->payload, ASN1_STRING_get0_data(query->payload), \
			 ASN1_STRING_length(query->payload));
	if ( S->payload->poisoned(S->payload) ) {
		err = "Failed to load patient identity.";
		goto done;
	}


 done:
	if ( query != NULL )
		provider_query_free(query);

	if ( err != NULL ) {
		fprintf(stderr, "!%s\n", err);
		S->poisoned = true;
		return false;
	}

	return true;
}


/**
 * External public method.
 *
 * This method implements the ability to determine what type of query
 * is being requested.
 *
 * \param this		The query which is to be decoded.
 *
 * \return		The enumerated query type is returned to the
 *			caller.
 */

static ProviderQuery_type type(const ProviderQuery const this)

{
	return this->state->type;
}


/**
 * External public method.
 *
 * This method implements a destructor for a ProviderQuery object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const ProviderQuery const this)

{
	auto const ProviderQuery_State const S = this->state;


	if ( S->payload != NULL )
		S->payload->whack(S->payload);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a ProviderQuery object.
 *
 * \return	A pointer to the initialized ProviderQuery.  A null value
 *		indicates an error was encountered in object generation.
 */

extern ProviderQuery NAAAIM_ProviderQuery_Init(void)

{
	auto Origin root;

	auto ProviderQuery this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ProviderQuery);
	retn.state_size   = sizeof(struct NAAAIM_ProviderQuery_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ProviderQuery_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */
	if ( (this->state->payload = HurdLib_Buffer_Init()) == NULL ) {
		whack(this);
		return NULL;
	}

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->set_simple_query = set_simple_query;
	this->get_simple_query = get_simple_query;

	this->set_simple_query_sms = set_simple_query_sms;
	this->get_simple_query_sms = get_simple_query_sms;

	this->encode = encode;
	this->decode = decode;

	this->type = type;

	this->whack = whack;

	return this;
}
