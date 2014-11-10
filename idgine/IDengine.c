/** \file
 * This file implements the methods for implementing transactions
 * against the identity generation daemon.  Communications is carried
 * out through a POSIX shared memory region.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "IPC.h"
#include "OrgID.h"
#include "Identity.h"
#include "IDengine.h"


/* State definition macro. */
#define STATE(var) CO(IDengine_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_IDengine_OBJID)
#error Object identifier not defined.
#endif


/** IDengine private state information. */
struct NAAAIM_IDengine_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Query status. */
	_Bool query_failed;

	/* Identity manager IPC object.*/
	IPC ipc;
};


/* Structure for the shared memory region. */
struct IDengine_ipc
{
	pid_t pid;

	_Bool valid;

	_Bool error;

	IDengine_identity idtype;

	char name[80];

	char identifier[80];

	unsigned char identity[NAAAIM_IDSIZE];
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of an identity.
 * the wire.
 */
typedef struct {
	ASN1_INTEGER *error;
	ASN1_ENUMERATED *idtype;
	ASN1_OCTET_STRING *name;
	ASN1_OCTET_STRING *identifier;
	ASN1_OCTET_STRING *identity;
} asn1_ipc;

ASN1_SEQUENCE(asn1_ipc) = {
	ASN1_SIMPLE(asn1_ipc, error,		ASN1_INTEGER),
	ASN1_SIMPLE(asn1_ipc, idtype,		ASN1_ENUMERATED),
	ASN1_SIMPLE(asn1_ipc, name,		ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_ipc, identifier,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(asn1_ipc, identity,		ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(asn1_ipc)

IMPLEMENT_ASN1_FUNCTIONS(asn1_ipc)

#define ASN1_BUFFER_ENCODE(b, e, err) \
	if ( ASN1_OCTET_STRING_set(e, b->get(b), b->size(b)) != 1 ) \
		err

#define ASN1_BUFFER_DECODE(b, e, err) \
	if ( !b->add(b, ASN1_STRING_data(e), ASN1_STRING_length(e)) ) \
 		err


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_IDengine_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(IDengine_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_IDengine_OBJID;

	S->poisoned	= false;
	S->query_failed = false;

	S->ipc = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the setup of the server side of the identity
 * manager.  The IPC object is created and initialized and within
 * the defined shared memory region the process communications
 * structure is initialized.
 *
 * \param this	A pointer to the identity manager object which is
 *		being created.
 *
 * \return	If the identity manager is successfully created and
 *		initialized a true value is returned.  If a failure
 *		occurs during the setup a false value is returned.
 */

static _Bool setup(CO(IDengine, this))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *idipc;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->create(S->ipc, "IDengine", sizeof(struct IDengine_ipc)) )
		goto done;

	idipc = S->ipc->get(S->ipc);
	memset(idipc, '\0', sizeof(struct IDengine_ipc));

	idipc->pid = getpid();
	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements attachment to the identity manager by
 * a client.
 *
 * \param this	A pointer to the identity manager object which is
 *		to be attached to the identity manager.
 *
 * \return	If the attachment is successfully created a true value
 *		is returned.  If a failure occurs during the setup a
 &		false value is returned.
 */

static _Bool attach(CO(IDengine, this))

{
	STATE(S);

	_Bool retn = false;


	INIT(NAAAIM, IPC, S->ipc, goto done);
	if ( !S->ipc->attach(S->ipc, "IDengine") )
		goto done;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor method for obtaining an identity
 * from the identity generator.
 *
 * \param this		A pointer to the identity generation object which
 *			is requesting the identity.
 *
 * \param type		The type of identity which is being requested.
 *
 * \param name		A String object containing the identifier which
 *			will be used to create the identity.
 *
 * \param identifier	A String object containing the identifier which
 *			will be used to create the identity.
 *
 * \param identity	A Buffer object which will be loaded with the
 *			identity which has been retrieved from the IPC
 *			object.
 *
 * \return		A true value is returned if the query for the
 *			identity was successful.  A false value indicated
 *			the request failed.
 */

static _Bool get_identity(CO(IDengine, this), const IDengine_identity type, \
			  CO(String, name), CO(String, identifier),	    \
			  CO(Buffer, identity))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc;

	Buffer b = NULL;


	if ( S->poisoned )
		goto done;

	/* Lock the IPC area and get the shared structure. */
	if ( !S->ipc->lock(S->ipc) )
		goto done;
	ipc = S->ipc->get(S->ipc);

	/* Set the identity request parameters. */
	ipc->idtype = IDengine_device;

	if ( name->size(name) > sizeof(ipc->name) )
		goto done;

	memset(ipc->name, '\0', sizeof(ipc->name));
	memcpy(ipc->name, name->get(name), name->size(name));

	memset(ipc->identifier, '\0', sizeof(ipc->identifier));
	memcpy(ipc->identifier, identifier->get(identifier), \
	       identifier->size(identifier));

	memset(ipc->identity, '\0', sizeof(ipc->identity));

	/* Request processing of the structure. */
	ipc->valid = false;
	ipc->error = false;

	kill(ipc->pid, SIGUSR1);
	while ( !ipc->valid )
		continue;

	/* Unlock the processing area. */
	if ( !S->ipc->unlock(S->ipc) )
		goto done;

	/* Return the identity if it is valid. */
	if ( ipc->error ) {
		S->query_failed = true;
		retn = true;
		goto done;
	}

	if ( !identity->add(identity, ipc->identity, sizeof(ipc->identity)) )
		goto done;
	S->query_failed = false;
	retn = true;
	

 done:
	memset(ipc->name,	'\0', sizeof(ipc->name));
	memset(ipc->identifier, '\0', sizeof(ipc->identifier));
	memset(ipc->identity,   '\0', sizeof(ipc->identity));

	WHACK(b);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements setting the the shared memory area with the
 * value of the generated identity.
 *
 * \param this		A pointer to the identity generation object which
 *			is setting the identity
 *
 * \param id		The Buffer object which contains the generated
 *			identity to be returned to the caller.
 *
 * \return		A true value is returned if the identity was
 *			successfully set.  A false value indicates that
 *			setting the identity failed.
 */

static _Bool set_identity(CO(IDengine, this), CO(Identity, identity))

{

	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc;

	Buffer id = identity->get_identity(identity);


	if ( S->poisoned )
		goto done;

	ipc = S->ipc->get(S->ipc);

	memcpy(ipc->identity, id->get(id), sizeof(ipc->identity));
	ipc->valid = true;

	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements setting an indication that an error occurred
 * while generating the requested identity.
 *
 * \param this		A pointer to the identity generation object which
 *			is setting the identity
 *
 * \return		A true value is returned if the identity was
 *			successfully set.  A false value indicates that
 *			setting the identity failed.
 */

static _Bool set_error(CO(IDengine, this))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc;


	if ( S->poisoned )
		goto done;

	ipc = S->ipc->get(S->ipc);

	ipc->valid = true;
	ipc->error = true;

	retn = true;

	
 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements obtaining the parameters for the identity
 * which will be generated.
 *
 * \param this		A pointer to the identity generation object which
 *			is setting the identity
 *
 * \param type		A pointer to the enumerated type which will be
 *			loaded with the type of identity being requested.
 *
 * \param name		A String object containing the name of the identity
 *			within the selected identity class type.
 *
 * \param identifier	A String object containing the identifier which
 *			will be used to generate the identity.
 *
 * \return		A true value is returned if the identity was
 *			successfully set.  A false value indicates that
 *			setting the identity failed.
 */

static _Bool get_id_info(CO(IDengine, this), IDengine_identity *type, \
			 CO(String, name), CO(String, identifier))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipc = S->ipc->get(S->ipc);


	*type = ipc->idtype;

	if ( !name->add(name, ipc->name) )
		goto done;

	if ( !identifier->add(identifier, ipc->identifier) )
		goto done;

	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This functions encodes the structure used for IPC communications
 * with the identity generation into ASN1 format.
 *
 * \param ipc		The pointer to the IPC structure to be
 *			encoded.
 *
 * \param bufr		The Buffer object which the encoded output is
 *			to be placed in.
 *
 * \return		A true value is returned if the encoding was
 *			successful.  A fale value indicated the
 *			encoding failed.
 */

static _Bool _encode_ipc(CO(struct IDengine_ipc *, ipc), CO(Buffer, bufr))

{
	_Bool retn = false;

	int error,
	    asn_size;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	asn1_ipc *idreq = NULL;


	/* Arguement validation. */
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	/* Encode the request. */
	if ( (idreq = asn1_ipc_new()) == NULL )
		goto done;

	error = ipc->error ? 1 : 0;
	if ( ASN1_INTEGER_set(idreq->error, error) != 1 )
		goto done;

	if ( ASN1_ENUMERATED_set(idreq->idtype, ipc->idtype) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(idreq->name, (unsigned char *) ipc->name, \
				   sizeof(ipc->name)) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(idreq->identifier,		     \
				   (unsigned char * )ipc->identifier, \
				   sizeof(ipc->identifier)) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(idreq->identity, ipc->identity, \
				   sizeof(ipc->identity)) != 1 )
		goto done;


	/* Load the ASN1 encoding into the supplied buffer. */
        asn_size = i2d_asn1_ipc(idreq, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	retn = true;


 done:
	if ( idreq == NULL )
		asn1_ipc_free(idreq);

	return retn;
}


/**
 * Internal private function.
 *
 * This functions decodes the structure used for IPC generation which
 * has been previously encoded in ASN1 format.
 *
 * \param ipc		The pointer to the IPC structure which will
 *			hold the decoded information
 *
 * \param bufr		The Buffer object which holds the encoded
 *			structure.
 *
 * \return		A true value is returned if the decoding was
 *			successful.  A fale value indicated the
 *			decoding failed.
 */

static _Bool _decode_ipc(struct IDengine_ipc * const ipc, CO(Buffer, bufr))

{
	_Bool retn = false;

	int error;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	asn1_ipc *idreq = NULL;


	/* Arguement validation. */
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	p = bufr->get(bufr);
        if ( !d2i_asn1_ipc(&idreq, &p, bufr->size(bufr)) )
                goto done;

	/* Lock the IPC area and get the shared structure. */
	error = ASN1_INTEGER_get(idreq->error);
	ipc->error = (error == 0) ? false : true;

	ipc->idtype = ASN1_ENUMERATED_get(idreq->idtype);

	memset(ipc->name, '\0', sizeof(ipc->name));
	memcpy(ipc->name, ASN1_STRING_data(idreq->name), \
	       ASN1_STRING_length(idreq->name));

	memset(ipc->identifier, '\0', sizeof(ipc->identifier));
	memcpy(ipc->identifier, ASN1_STRING_data(idreq->identifier), \
	       ASN1_STRING_length(idreq->identifier));

	memset(ipc->identity, '\0', sizeof(ipc->identity));
	memcpy(ipc->identity, ASN1_STRING_data(idreq->identity), \
	       ASN1_STRING_length(idreq->identity));

	retn = true;


 done:
	if ( idreq != NULL )
		asn1_ipc_free(idreq);

	return retn;
}


/**
 * External public method.
 *
 * This method encodes an identity generation request in ASN1
 * format for transmission to a remote identity generator.
 *
 * \param this		A pointer to the identity generation object which
 *			is requesting the identity.
 *
 * \param type		The type of identity which is being requested.
 *
 * \param name		A String object containing the identifier which
 *			will be used to create the identity.
 *
 * \param identifier	A String object containing the identifier which
 *			will be used to create the identity.
 *
 * \param bufr		A Buffer object which will be loaded with the
 *			encoded identity request.
 *
 * \return		A true value is returned if the encoding was
 *			successful.  A fale value indicated the
 *			encoding failed.
 */

static _Bool encode_get_identity(CO(IDengine, this),			     \
			     const IDengine_identity type, CO(String, name), \
			     CO(String, identifier), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc ipc;


	/* Object and arguement verification. */
	if ( S->poisoned )
		goto done;
	if ( (name == NULL) || name->poisoned(name) )
		goto done;
	if ( (identifier == NULL) || identifier->poisoned(identifier) )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	/* Set the identity request parameters. */
	ipc.error  = false;
	ipc.idtype = IDengine_device;

	if ( name->size(name) > sizeof(ipc.name) )
		goto done;
	memset(ipc.name, '\0', sizeof(ipc.name));
	memcpy(ipc.name, name->get(name), name->size(name));

	if ( identifier->size(identifier) > sizeof(ipc.identifier) )
		goto done;
	memset(ipc.identifier, '\0', sizeof(ipc.identifier));
	memcpy(ipc.identifier, identifier->get(identifier), \
	       identifier->size(identifier));

	memset(ipc.identity, '\0', sizeof(ipc.identity));

	if ( !_encode_ipc(&ipc, bufr) )
		goto done;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method decodes an identity generation request which was encoded
 * in ASN1 format by a client requesting identity generation.  The
 * decoded request is submitted to the identity generator for processing.
 *
 * \param this		A pointer to the identity generation object which
 *			is requesting the identity.
 *
 * \param identity	A Buffer object which contains the encoded
 *			identity request.  On return this buffer will be
 *			loaded with the generated identity.
 *
 * \return		A true value is returned if the decoding was
 *			successful.  A fale value indicated the
 *			decoding failed.
 */

static _Bool decode_get_identity(CO(IDengine, this), CO(Buffer, identity))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc *ipcp,
			    ipc;


	/* Object and arguement verification. */
	if ( S->poisoned )
		goto done;
	if ( (identity == NULL) || identity->poisoned(identity) )
		goto done;

	/* Setup for the identity decode. */
	memset(&ipc, '\0', sizeof(struct IDengine_ipc));
	if ( !_decode_ipc(&ipc, identity) )
		goto done;

	memset(ipc.identity, '\0', sizeof(ipc.identity));

	/* Request processing of the structure. */
	if ( !S->ipc->lock(S->ipc) )
		goto done;
	ipcp = S->ipc->get(S->ipc);

	ipc.pid = ipcp->pid;
	*ipcp = ipc;
	ipcp->valid = false;

	kill(ipcp->pid, SIGUSR1);
	while ( !ipcp->valid )
		continue;

	/* Clone and unlock the processing area. */
	ipc = *ipcp;

	memset(ipcp->name,	 '\0', sizeof(ipcp->name));
	memset(ipcp->identifier, '\0', sizeof(ipcp->identifier));
	memset(ipcp->identity,	 '\0', sizeof(ipcp->identity));

	if ( !S->ipc->unlock(S->ipc) )
		goto done;

	/* Return the identity if the request completed without error. */
	if ( ipc.error ) {
		S->query_failed = true;
		retn = true;
		goto done;
	}

	identity->reset(identity);
	if ( !_encode_ipc(&ipc, identity) )
		goto done;

	S->query_failed = false;
	retn = true;


 done:
	memset(ipc.name,	'\0', sizeof(ipc.name));
	memset(ipc.identifier,	'\0', sizeof(ipc.identifier));
	memset(ipc.identity,	'\0', sizeof(ipc.identity));

	if ( !retn ) 
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method decodes an identity generation request response in
 * ASN1 format.  It is designed to process the output of the
 * ->decode_get_identity method.
 *
 * \param this		A pointer to the identity generation object which
 *			is requesting decoding of the identity.
 *
 * \param identity	A Buffer object which contains the encoded
 *			identity request.  On return this buffer will be
 *			loaded with the generated identity.
 *
 * \return		A true value is returned if the decoding was
 *			successful.  A fale value indicated the
 *			decoding failed.
 */

static _Bool decode_identity(CO(IDengine, this), CO(Buffer, identity))

{
	STATE(S);

	_Bool retn = false;

	struct IDengine_ipc ipc;


	if ( !_decode_ipc(&ipc, identity) )
		goto done;
	if ( ipc.error ) {
		S->query_failed = true;
		retn = true;
		goto done;
	}

	identity->reset(identity);
	if ( !identity->add(identity, ipc.identity, sizeof(ipc.identity)) )
		goto done;

	S->query_failed = false;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor for checking the status of
 * the flag which indicates if the identity generation failed.
 *
 * \param this	A pointer to the object whose generation status is 
 *		to be quered
 *
 * \return	A boolean value is returned which provides an
 *		indication of the status of the query.
 */

static _Bool query_failed(CO(IDengine, this))

{
	STATE(S);

	return S->query_failed;
}


/**
 * External public method.
 *
 * This method implements a destructor for a IDengine object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(IDengine, this))

{
	STATE(S);


	if ( S->ipc != NULL )
		WHACK(S->ipc);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a IDengine object.
 *
 * \return	A pointer to the initialized IDengine.  A null value
 *		indicates an error was encountered in object generation.
 */

extern IDengine NAAAIM_IDengine_Init(void)

{
	auto Origin root;

	auto IDengine this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_IDengine);
	retn.state_size   = sizeof(struct NAAAIM_IDengine_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_IDengine_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->setup  = setup;
	this->attach = attach;

	this->get_id_info = get_id_info;

	this->get_identity = get_identity;
	this->set_identity = set_identity;
	this->set_error	   = set_error;

	this->encode_get_identity = encode_get_identity;
	this->decode_get_identity = decode_get_identity;
	this->decode_identity	  = decode_identity;

	this->query_failed = query_failed;
	this->whack = whack;

	return this;
}
