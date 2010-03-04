/** \file
 * This file implements an object for managing replies from the
 * identity broker servers.
 *
 * The reply from the identity broker is a DER encoded structure
 * consisting of two parts.  The first component is an enumerated type
 * which describes the type of response such as an IP response etc.
 * The second component is a DER encoded structure which is specific
 * to the type of response described by the enumeration type.
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define IDQUERYREPLY_MAGIC 0xce6f1557

/* Include files. */
#include <stdint.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include "NAAAIM.h"
#include "IDqueryReply.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDqueryReply_OBJID)
#error Object identifier not defined.
#endif


/** IDqueryReply private state information. */
struct NAAAIM_IDqueryReply_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Type of reply. */
	IDqueryReply_type type;

	/* The buffer containing the internal DER payload. */
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
} query_reply;

ASN1_SEQUENCE(query_reply) = {
	ASN1_SIMPLE(query_reply, magic,	  ASN1_INTEGER),
	ASN1_SIMPLE(query_reply, type,	  ASN1_ENUMERATED),
	ASN1_SIMPLE(query_reply, payload, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(query_reply)

IMPLEMENT_ASN1_FUNCTIONS(query_reply)


/**
 * The following defines the inner ASN1 encoding sequence for a reply
 * directing the client to execute an IP query to a host which will
 * provide additional information about the patient.
 */
typedef struct {
	ASN1_PRINTABLESTRING *hostname;
	ASN1_INTEGER *port;
} ip_reply;

ASN1_SEQUENCE(ip_reply) = {
	ASN1_SIMPLE(ip_reply, hostname,	ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(ip_reply, port,	ASN1_INTEGER),
} ASN1_SEQUENCE_END(ip_reply)

IMPLEMENT_ASN1_FUNCTIONS(ip_reply)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDqueryReply_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(const IDqueryReply_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDqueryReply_OBJID;

	S->poisoned = false;
	S->type	    = IDQreply_notfound;

	return;
}


/**
 * External public method.
 *
 * This method initializes and encodes an IP redirect reply.
 *
 * \param this		The reply which is to be initialized.
 *
 * \param hostname	A pointer to a null-terminated buffer containing
 *			the name of the host to initiate a connection to.
 *
 * \param port		The port number to be used for the conection.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the encoding was successful.  A true
 *			value indicates success.
 */

static _Bool set_ip_reply(const IDqueryReply const this, \
			  const char * const hostname, int const port)

{
	auto const IDqueryReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto ip_reply *reply = NULL;


	if ( S->poisoned )
		goto done;


	if ( (reply = ip_reply_new()) == NULL )
		goto done;

        if ( ASN1_STRING_set(reply->hostname, hostname, strlen(hostname)) \
	     != 1 )
                goto done;

	if ( ASN1_INTEGER_set(reply->port, port) != 1 )
		goto done;


        asn_size = i2d_ip_reply(reply, p);
        if ( asn_size < 0 )
                goto done;

	if ( !S->payload->add(S->payload, asn, asn_size) )
		goto done;

	retn	= true;
	S->type = IDQreply_ipredirect;
	

 done:
	if ( retn == false )
		S->poisoned = true;

	if ( reply != NULL )
		ip_reply_free(reply);

	return retn;
}


/**
 * External public method.
 *
 * This method decodes and returns information for an IP address
 * referral.  This reply indicates the client should contact the
 * named site for additional information on th client identity.
 *
 * \param this		The reply which is to be initialized.
 *
 * \param hostname	The Buffer object to be loaded with the name
 *			of the host to which a connection is to be
 *			made.
 *
 * \param port		A pointer to the variable which is to be
 *			loaded with the port number for the
 *			connection.
 *
 * \return		A boolean value is used to indicate whether or
 *			not the decoding was successful.  A true
 *			value indicates success.
 */

static _Bool get_ip_reply(const IDqueryReply const this, \
			  const Buffer const bufr, int * const port)

{
	auto const IDqueryReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto int asn_size;

	auto ip_reply *reply = NULL;


	if ( S->poisoned )
		goto done;


	p = S->payload->get(S->payload);
	asn_size = S->payload->size(S->payload);
        if ( !d2i_ip_reply(&reply, &p, asn_size) )
                goto done;	

	bufr->reset(bufr);
	bufr->add(bufr, ASN1_STRING_data(reply->hostname), \
		  ASN1_STRING_length(reply->hostname));
	fprintf(stdout, "%s[%s]: hostname size = %d\n", __FILE__, __func__, \
		ASN1_STRING_length(reply->hostname));

	*port = ASN1_INTEGER_get(reply->port);

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( reply != NULL )
		ip_reply_free(reply);

	return retn;

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

static _Bool encode(const IDqueryReply const this, const Buffer const bufr)

{
	auto const IDqueryReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned char **p = &asn;

	auto int asn_size;

	auto query_reply *reply = NULL;


	if ( S->poisoned )
		goto done;


	if ( (reply = query_reply_new()) == NULL )
		goto done;

	if ( ASN1_INTEGER_set(reply->magic, IDQUERYREPLY_MAGIC) != 1 )
		goto done;

	if ( ASN1_ENUMERATED_set(reply->type, S->type) != 1 )
		goto done;

        if ( ASN1_OCTET_STRING_set(reply->payload,		\
				   S->payload->get(S->payload),	\
				   S->payload->size(S->payload)) != 1 )
                goto done;

        asn_size = i2d_query_reply(reply, p);
        if ( asn_size < 0 )
                goto done;

	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;
	

 done:
	if ( retn == false )
		S->poisoned = true;

	if ( reply != NULL )
		query_reply_free(reply);

	return retn;
}


/**
 * External public method.
 *
 * This method implements outer decoding of the query reply.  The
 * on the wire DER representation is decoded into a payload descriptor
 * and a DER encoding of the response type indicated by the payload
 * descriptor.
 *
 * \param this		The reply which is to be decoded.
 *
 * \param bufr		The Buffer object containing the DER representation
 *			of the reply.
 *
 * \return		A boolen value is used to indicate whether or not
 *			the encoding was successful.  A true value indicates
 *			a successful encoding.
 */

static _Bool decode(const IDqueryReply const this, const Buffer const bufr)

{
	auto const IDqueryReply_State const S = this->state;

	auto _Bool retn = false;

        auto unsigned char *asn = NULL;

        auto unsigned const char *p = asn;

	auto int asn_size;

	auto unsigned int magic;

	auto query_reply *reply = NULL;


	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;


	p = bufr->get(bufr);
	asn_size = bufr->size(bufr);
        if ( !d2i_query_reply(&reply, &p, asn_size) )
                goto done;

	magic = ASN1_INTEGER_get(reply->magic);
	if ( magic != IDQUERYREPLY_MAGIC )
		goto done;

	S->type = ASN1_ENUMERATED_get(reply->type);

	S->payload->add(S->payload, ASN1_STRING_data(reply->payload), \
			 ASN1_STRING_length(reply->payload));
	if ( S->payload->poisoned(S->payload) )
		goto done;

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;

	if ( reply != NULL )
		query_reply_free(reply);

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor function for determining the
 * type of reply represented by the object.
 *
 * \param this		The reply which is to be queried.
 *
 * \param type		The type which is to be checked.
 *
 * \return		A boolen value is used to indicate whether or not
 *			the object matches the type specified.  A true
 *			value indicates a match.
 */

static _Bool is_type(const IDqueryReply const this, \
		     IDqueryReply_type const type)

{
	return this->state->type == type;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDqueryReply object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const IDqueryReply const this)

{
	auto const IDqueryReply_State const S = this->state;


	S->payload->whack(S->payload);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a IDqueryReply object.
 *
 * \return	A pointer to the initialized IDqueryReply.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDqueryReply NAAAIM_IDqueryReply_Init(void)

{
	auto Origin root;

	auto IDqueryReply this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDqueryReply);
	retn.state_size   = sizeof(struct NAAAIM_IDqueryReply_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDqueryReply_OBJID, \
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
	this->set_ip_reply = set_ip_reply;
	this->get_ip_reply = get_ip_reply;

	this->encode = encode;
	this->decode = decode;

	this->is_type = is_type;

	this->whack = whack;

	return this;
}
