/** \file
 * This file implements an object which manages the encoding and of an
 * EDI transaction.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define EDIPACKET_MAGIC 0xbeaf001f


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

#include "EDIpacket.h"

#define STATE(var) CO(EDIpacket_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_EDIpacket_OBJID)
#error Object identifier not defined.
#endif


/** PossumPacket private state information. */
struct NAAAIM_EDIpacket_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/** Object status. */
	_Bool poisoned;

	/** Magic number. */
	uint32_t magic;

	/**
	 * The type of EDI packet.
	 */
	EDIpacket_type type;

	/**
	 * Requested authentication time.
	 */
	time_t authtime;

	/**
	 * The object containing the payload.  This will be either in
	 * encrypted of decrypted form.
	 */
	Buffer payload;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the EDI transaction which will be transmitted
 * over the wire.
 */
typedef struct {
	ASN1_INTEGER *magic;
	ASN1_ENUMERATED *type;
	ASN1_INTEGER *authtime;
	ASN1_OCTET_STRING *payload;
} edi_payload;

ASN1_SEQUENCE(edi_payload) = {
	ASN1_SIMPLE(edi_payload, magic,		ASN1_INTEGER),
	ASN1_SIMPLE(edi_payload, type,		ASN1_ENUMERATED),
	ASN1_SIMPLE(edi_payload, authtime,	ASN1_INTEGER),
	ASN1_SIMPLE(edi_payload, payload,	ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(edi_payload)

IMPLEMENT_ASN1_FUNCTIONS(edi_payload)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_EDIpacket_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(EDIpacket_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_EDIpacket_OBJID;

	S->poisoned = false;

	S->magic    = EDIPACKET_MAGIC;
	S->type	    = EDIpacket_none;
	S->authtime = 0;
	S->payload  = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements setting the EDI packet type for the
 * transaction.
 *
 * \param this	A pointer to the EDI transaction object whose
 *		type is to be set.
 *
 * \return	If the packet type was successfully set a true
 *		value is returned.  If setting the type failed a
 *		false value is returned.
 */

static _Bool set_type(CO(EDIpacket, this), EDIpacket_type type)

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	S->type = type;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor for returning the EDI transaction
 * type.
 *
 * \param this	A pointer to the EDI transaction object whose type is
 *		to be queried.
 *
 * \return	The EDI transaction type.  A value of IDpacket_none is
 *		returned if the object is poisoned.
 */

static EDIpacket_type get_type(CO(EDIpacket, this))

{
	STATE(S);


	if ( S->poisoned )
		return EDIpacket_none;

	return S->type;
}



/**
 * External public method.
 *
 * This method implements setting the authentication time for the
 * EDI transaction.
 *
 * \param this		A pointer to the EDI transaction object which
 *			is to have its authentication time set.
 *
 * \param authtime	The authentication time to be used.
 *
 * \return		If the authentication time is successfully set
 *			a true value is returned.  If setting the time
 *			failed a false value is returned.
 */

static _Bool set_authtime(CO(EDIpacket, this), time_t authtime)

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;

	S->authtime = authtime;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor for returning the EDI transaction
 * time.
 *
 * \param this		A pointer to the EDI transaction object whose
 *			authentication time is to be queried.
 *
 * \return
 */

static time_t get_authtime(CO(EDIpacket, this))

{
	STATE(S);


	if ( S->poisoned )
		return 0;

	return S->authtime;
}


/**
 * External public method.
 *
 * This method implements adding the contents of a supplied Buffer
 * object as the EDI transaction payload.  This can either be the
 * ASCII version of the EDI transaction or the encrypted variant.
 *
 * \param this		A pointer to the EDI transaction object which
 *			is to have its payload set.
 *
 * \param payload	The object containing the contents to be
 *			used as the payload.
 */

static _Bool set_payload(CO(EDIpacket, this), CO(Buffer, payload))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( (payload == NULL) || payload->poisoned(payload) )
		goto done;

	if ( !S->payload->add_Buffer(S->payload, payload) )
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
 * This method implements an accessor method for extracting the contents
 * of the EDI transaction payload.  The payload is loaded into a
 * user supplied Buffer object.
 *
 * \param this	A pointer to the EDI transaction object whose payload is
 *		to be extracted.
 *
 * \param bufr	The object which the payload is to be loaded into.
 *
 * \return	If an error is encountered a false value is returned
 *		and the transaction object is poisoned.  A true
 *		value indicates the payload was successfully extracted
 *		into the supplied object.
 */

static _Bool get_payload(CO(EDIpacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( !bufr->add_Buffer(bufr, S->payload) )
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
 * This method implements encoding the contents of the object into
 * ASN1 format suitable for transmission 'over the wire'.
 *
 * \param this	A pointer to the EDI transaction object which is to
 *		be encoded.
 *
 * \param bufr	The object into which the encoded object is loaded.
 *
 * \return	If an error occurs during encoding a false value is
 *		returned to the caller.  A true value indicates the
 *		object was encoded and the contents of the supplied
 *		Buffer is valid.
 */

static _Bool encode_payload(CO(EDIpacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	int asn_size;

	edi_payload *edi = NULL;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;


	/* Encode the object components. */
	if ( (edi = edi_payload_new()) == NULL )
		goto done;

	if ( ASN1_INTEGER_set(edi->magic, S->magic) != 1 )
		goto done;
	if ( ASN1_ENUMERATED_set(edi->type, S->type) != 1 )
		goto done;
	if ( ASN1_INTEGER_set(edi->authtime, S->authtime) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(edi->payload, S->payload->get(S->payload), \
				   S->payload->size(S->payload)) != 1 )
		goto done;

        asn_size = i2d_edi_payload(edi, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;
	retn = true;


 done:
	if ( edi != NULL )
		edi_payload_free(edi);

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements decoding of an ASN1 encoded EDI transaction
 * into the appropriate members of an object.
 *
 * \param this	A pointer to the EDI transaction object which is to
 *		be decoded.
 *
 * \param bufr	An object containing the ASN1 encoded transaction.
 *
 * \return	If an error occurs during decoding a false value is
 *		returned to the caller.  A true value indicates the
 *		object was decode and the contents of the calling
 *		object are valid.
 */

static _Bool decode_payload(CO(EDIpacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	int asn_size;

	edi_payload *edi = NULL;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;


	/* Unmarshall the supplied buffer. */
	p	 = bufr->get(bufr);
	asn_size = bufr->size(bufr);

        if ( !d2i_edi_payload(&edi, &p, asn_size) )
		goto done;

	S->magic = ASN1_INTEGER_get(edi->magic);
	if ( S->magic != EDIPACKET_MAGIC )
		goto done;

	S->type	    = ASN1_ENUMERATED_get(edi->type);
	S->authtime = ASN1_INTEGER_get(edi->authtime);

	if ( !S->payload->add(S->payload, ASN1_STRING_data(edi->payload), \
			      ASN1_STRING_length(edi->payload)) )
		goto done;
	retn = true;


 done:
	if ( edi != NULL )
		edi_payload_free(edi);

	if ( retn == false )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method prints the contents of an EDIpacket object.  The
 * status, ie, whether or not the object has been poisoned is also
 * indicated.
 *
 * \param this	A pointer to the object which is to be printed..
 */

static void print(CO(EDIpacket, this))

{
	STATE(S);


	fprintf(stdout, "status: %s\n", S->poisoned ? "* POISONED *" : "OK");
	fprintf(stdout, "magic: %08x\n", S->magic);
	fprintf(stdout, "time: %d\n", (int) S->authtime);
	fprintf(stdout, "type: %d\n", (int) S->type);

	fputs("payload:\n", stdout);
	S->payload->hprint(S->payload);

	return;
}


/**
 * External public method.
 *
 * This method implements resetting of an authenticator object.  It
 * provides a method for loading the object with an alternate representation
 * of the payload, for example an encrypted copy.
 *
 * \param this	The object to be reset.
 */

static void reset(CO(EDIpacket, this))

{
	STATE(S);


	if ( S->poisoned )
		return;

	S->payload->reset(S->payload);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a EDIpacket object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(EDIpacket, this))

{
	STATE(S);


	/* Release Buffer elements. */
	WHACK(S->payload);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a EDIpacket object.
 *
 * \return	A pointer to the initialized EDIpacket.  A null value
 *		indicates an error was encountered in object generation.
 */

extern EDIpacket NAAAIM_EDIpacket_Init(void)

{
	Origin root;

	EDIpacket this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_EDIpacket);
	retn.state_size   = sizeof(struct NAAAIM_EDIpacket_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_EDIpacket_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->payload, goto err);

	/* Method initialization. */
	this->set_type = set_type;
	this->get_type = get_type;

	this->set_authtime = set_authtime;
	this->get_authtime = get_authtime;

	this->set_payload = set_payload;
	this->get_payload = get_payload;

	this->encode_payload = encode_payload;
	this->decode_payload = decode_payload;

	this->print = print;
	this->reset = reset;
	this->whack = whack;

	return this;

 err:
	WHACK(this->state->payload);

	whack(this);
	return NULL;
}
