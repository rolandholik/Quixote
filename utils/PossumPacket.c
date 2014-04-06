/** \file
 * This file implements an object which creates and decodes the exchange
 * packets which implement the POSSUM protocol.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define BIRTHDATE 1396167420


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "RandomBuffer.h"
#include "IDtoken.h"
#include "AES256_cbc.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "OTEDKS.h"

#include "PossumPacket.h"

#define STATE(var) CO(PossumPacket_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_PossumPacket_OBJID)
#error Object identifier not defined.
#endif


/** PossumPacket private state information. */
struct NAAAIM_PossumPacket_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/**
	 * The key scheduler to be used.
	 */
	OTEDKS otedks;

	/**
	 * The replay nonce which will be used as the key to generate
	 * the shared secret from the diffie-hellman based key.
	 */
	RandomBuffer nonce;

	/**
	 * The Buffer object which holds the concantenation of the identity
	 * NONE and the SCRYPT hash using that salt.
	 */
	Buffer identity;

	/**
	 * Requested authentication time.
	 */
	time_t auth_time;

	/* The Buffer object holding the identity authenticator. */
	Buffer authenticator;

	/**
	 * A Buffer object which holds the HMAC checksum over a packet.
	 */
	Buffer checksum;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the authenticator which will be transmitted over
 * the wire.
 */
typedef struct {
	ASN1_INTEGER *auth_time;
	ASN1_OCTET_STRING *authenticator;
} packet1_payload;

ASN1_SEQUENCE(packet1_payload) = {
	ASN1_SIMPLE(packet1_payload, auth_time, ASN1_INTEGER),
	ASN1_SIMPLE(packet1_payload, authenticator, \
		    ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(packet1_payload)

IMPLEMENT_ASN1_FUNCTIONS(packet1_payload)


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_PossumPacket_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(PossumPacket_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_PossumPacket_OBJID;

	S->poisoned	 = false;
	S->otedks	 = NULL;
	S->nonce	 = NULL;
	S->identity	 = NULL;
	S->authenticator = NULL;
	S->checksum	 = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This function computes the packet checksum over the supplied buffer.
 *
 * \param this		The object whose packet checksum is to be
 *			computed.
 *
 * \param packet	The state of the object for which the
 *			authenticator is being built.
 *
 * \param status	A buffer containing the software status to be
 *			used in encoding the checksum.
 *
 * \return		If an error is encountered a false value is
 *			returned, a true value indicates the authenticator
 *			was constructed.
 */

static _Bool compute_checksum(CO(PossumPacket_State, S), \
			      CO(Buffer, status), CO(Buffer, packet))

{
	_Bool retn = false;

	Buffer b;

	SHA256 hmac_key;

	SHA256_hmac hmac;


	/* Verify the packet checksum. */
	INIT(NAAAIM, SHA256, hmac_key, goto done);
	hmac_key->add(hmac_key, status);
	hmac_key->add(hmac_key, S->otedks->get_key(S->otedks));
	if ( !hmac_key->compute(hmac_key) )
		goto done;
	b = hmac_key->get_Buffer(hmac_key);

	if ( (hmac = NAAAIM_SHA256_hmac_Init(b)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, packet);
	if ( !hmac->compute(hmac) )
		goto done;

	if ( S->checksum->add_Buffer(S->checksum, hmac->get_Buffer(hmac)) )
		retn = true;
	S->checksum->print(S->checksum);

 done:
	WHACK(hmac_key);
	WHACK(hmac);

	return retn;
}

			 
/**
 * Internal private function.
 *
 * This function implements the creation of the authenticator object.
 *
 * This object contains the following elements:
 *
 *	Diffie-Hellman private key.
 *	Replay NONCE.
 *	Hardware quote.
 *
 * And is encrypted with an OTEDKS key based on the identity provided
 * to the object and the authentication time specified for the
 * object.
 *
 * \param state		The state of the object for which the
 *			authenticator is being built.
 *
 * \param otedks	The key scheduler to be used to create the
 *			authenticator.
 *
 * \return		If an error is encountered a false value is
 *			returned, a true value indicates the authenticator
 *			was constructed.
 */

static _Bool create_authenticator(CO(PossumPacket_State, S))

{
	_Bool retn = false;

	unsigned int lp;

	Buffer key,
	       iv,
	       auth = NULL;

	AES256_cbc cipher;


	/* Generate and load Diffie Hellman key. */
	INIT(HurdLib, Buffer, auth, goto done);
	for (lp= 0; lp < 32 / 4; ++ lp)
		auth->add_hexstring(auth, "feadbeef");

	/* Add the replay NONCE. */
	INIT(NAAAIM, RandomBuffer, S->nonce, goto done);
	if ( !S->nonce->generate(S->nonce, 32) )
		goto done;
	auth->add_Buffer(auth, S->nonce->get_Buffer(S->nonce));

	/* Add the hardware quote. */
	if ( !auth->add_hexstring(auth, "0000fead0000beaf") )
		goto done;

	/* Encrypt the authenticator. */
	key = S->otedks->get_key(S->otedks);
	iv  = S->otedks->get_iv(S->otedks);

	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		goto done;
	if ( cipher->encrypt(cipher, auth) == NULL )
		goto done;

	if ( S->authenticator->add_Buffer(S->authenticator, \
					  cipher->get_Buffer(cipher)) )
		retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(auth);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of the first POSSUM exchange
 * packet.  This packet is sent by the client to identify and attest
 * the state of the client.
 *
 * \param this		The object whose packet 1 state is to be
 *			created.
 *
 * \param token		The identity token to be used to create the
 *			state.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of creating the packet.  A false value
 *		indicates creation failed while a true indicates it
 *		was successful.
 */

static _Bool create_packet1(CO(PossumPacket, this), CO(IDtoken, token))

{

	STATE(S);

	_Bool retn = false;

	Buffer b,
	       key = NULL;

	RandomBuffer nonce = NULL;

	SHA256_hmac hmac = NULL;


	/* Status checks. */
	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;

	/* Load the identification challenge nonce. */
	INIT(NAAAIM, RandomBuffer, nonce, goto done);
	nonce->generate(nonce, 256 / 8);
	S->identity->add_Buffer(S->identity, nonce->get_Buffer(nonce));

	/* Hash the organization key and identity with the nonce. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(S->identity)) == NULL )
		goto done;

	if ( (b = token->get_element(token, IDtoken_orgkey)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, b);

	if ( (b = token->get_element(token, IDtoken_orgid)) == NULL )
		goto done;
	hmac->add_Buffer(hmac, b);

	hmac->compute(hmac);
	if ( !S->identity->add_Buffer(S->identity, hmac->get_Buffer(hmac)) )
		goto done;

	/* Create the authenticator based on the OTEDKS key. */
	if ( create_authenticator(S) )
		retn = true;

 done:
	WHACK(key);
	WHACK(nonce);
	WHACK(hmac);

	if ( retn == false )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements retrieval of the asserted identity.
 *
 * \param this	The packet whose identity is to be retrieved.
 *
 * \param bufr	The Buffer object which the identity is to be
 *		loaded into.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future activity.
 */

static _Bool get_identity(CO(PossumPacket, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Status checks. */
	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( !bufr->add_Buffer(bufr, S->identity) )
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
 * This method implements retrieval of the authenticator from a decoded
 * POSSUM packet.
 *
 * \param this	The packets whose authenticator is to be retrived.
 *
 * \param token	The identity token which contains the identity
 *		representation of the host which will be used to
 *		decode the packet.  In this application the token is
 *		assumed to hold the SHA256 based hash of the
 *		actually device identity.
 *
 * \param bufr	The buffer object which will hold the authentication
 *		identity elements.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of loading the elements.  On failure the object
 *		is poisoned for future activity.
 */

static _Bool get_authenticator(CO(PossumPacket, this), CO(IDtoken, token), \
			       CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	Buffer idkey,
	       idhash,
	       iv,
	       key;

	OTEDKS otedks = NULL;

	AES256_cbc cipher = NULL;


	/* Condition checks. */
	if ( S->poisoned || bufr->poisoned(bufr) )
		goto done;
	if ( S->authenticator->size(S->authenticator) == 0 )
		goto done;

	/* Extract the identity key and hash of the identity. */
	idkey  = token->get_element(token, IDtoken_key);
	idhash = token->get_element(token, IDtoken_id);
	if ( (idkey == NULL) || (idhash == NULL) )
		goto done;

	/* Compute the key from the host identity. */
	if ( (otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto done;
	if ( !otedks->compute(otedks, S->auth_time, idkey, idhash) )
		goto done;
	iv  = otedks->get_iv(otedks);
	key = otedks->get_key(otedks);

	/*
	 * Decrypt the authenticator and load it back into the supplied
	 * buffer.
	 */
	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		goto done;
	if ( !cipher->decrypt(cipher, S->authenticator) )
		goto done;
	
	if ( bufr->add_Buffer(bufr, cipher->get_Buffer(cipher)) )
		retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;
	WHACK(otedks);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the encoding of the contents of the
 * PossumPacket object into an ASN1 structure.  The binary encoding
 * is loaded into a Buffer object provided by the caller.
 *
 * \param this		The packet1 payload whose elements are to be
 *			encoded for transmission.
 *
 * \param status	The software status to be used in encoding the
 *			packet.
 *
 * \param bufr		The Buffer object which the payload is to be encoded
 *			into.
 *
 * \return	A boolean value is used to return success or failure of
 *		the encoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool encode_packet1(CO(PossumPacket, this), CO(Buffer, status),
			    CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	int asn_size;

	uint32_t auth_time;

	packet1_payload *packet1 = NULL;


	/* Arguement status check. */
	if ( S->poisoned )
		goto done;
	if ( (status == NULL ) || status->poisoned(status) )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	/* Add the identity assertion to the packet. */
	bufr->add_Buffer(bufr, S->identity);

	/* Add the authentication time. */
	auth_time = htonl(S->auth_time);
	if ( !bufr->add(bufr, (unsigned char *) &auth_time, \
			sizeof(auth_time)) )
		goto done;

	/* ASN1 encode the authenticator. */
	if ( (packet1 = packet1_payload_new()) == NULL )
		goto done;

        if ( ASN1_OCTET_STRING_set(packet1->authenticator,		     \
				   S->authenticator->get(S->authenticator),  \
                                   S->authenticator->size(S->authenticator)) \
	     != 1 )
                goto done;

        asn_size = i2d_packet1_payload(packet1, p);
        if ( asn_size < 0 )
                goto done;
	if ( !bufr->add(bufr, asn, asn_size) )
		goto done;

	/* Append the checksum to the packet. */
	if ( !compute_checksum(S, status, bufr) )
		goto done;
	if ( bufr->add_Buffer(bufr, S->checksum) )
		retn = true;

 done:
	if ( retn == false )
		S->poisoned = true;
	if ( packet1 != NULL )
		packet1_payload_free(packet1);

	return retn;
}


/**
 * External public method.
 *
 * This method implements verification of a type 1 packet and
 * subjsequent decoding of the authenticator.  The type 1 packet
 * consists of the following three fields:
 *
 *	Identity assertion
 *	32-bit authentication time in network byte order.
 *	Authenticator
 *	HMAC-SHA256 checksum over the three data elements of the
 *	packet.
 *	
 * \param this		The PossumPacket object which is to receive the
 *			encoded object.
 *
 * \param token		The identity token of the client which had initiatied
 *			the packet.
 *
 * \param status	The anticipated software status of the client.
 *
 * \param packet	The type 1 packet being decoded.
 *
 * \return	A boolean value is used to return success or failure of
 *		the decoding.  A true value is used to indicate
 *		success.  Failure results in poisoning of the object.
 */

static _Bool decode_packet1(CO(PossumPacket, this), CO(IDtoken, token),
			    CO(Buffer, status), CO(Buffer, packet))

{
	STATE(S);

	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned const char *p = asn;

	int asn_size;

	packet1_payload *packet1 = NULL;

	Buffer payload = NULL;


	/* Arguement status checks. */
	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;
	if ( (status == NULL) || status->poisoned(status) )
		goto done;
	if ( (packet == NULL) || packet->poisoned(packet) )
		goto done;

	/* Extract the authentication time and initialize the scheduler. */
	S->auth_time = *((uint32_t *) (packet->get(packet) + 2*NAAAIM_IDSIZE));
	S->auth_time = ntohl(S->auth_time);
	fprintf(stdout, "Auth time: %d\n", (int) S->auth_time);
	this->set_schedule(this, token, S->auth_time);

	/* Compute the checksum over the packet. */
	INIT(HurdLib, Buffer, payload, goto done);
	if ( !payload->add(payload, packet->get(packet), \
			   packet->size(packet) - NAAAIM_IDSIZE) )
		goto done;
	if ( !compute_checksum(S, status, payload) )
		goto done;

	p  = packet->get(packet) + packet->size(packet);
	p -= NAAAIM_IDSIZE;
	if ( memcmp(S->checksum->get(S->checksum), p, NAAAIM_IDSIZE) != 0 )
		goto done;

	
	/* Decode the authenticator. */
	p = packet->get(packet) + 2*NAAAIM_IDSIZE + sizeof(uint32_t);
	asn_size = packet->size(packet) - 3*NAAAIM_IDSIZE - sizeof(uint32_t);
        if ( !d2i_packet1_payload(&packet1, &p, asn_size) )
                goto done;

	S->authenticator->add(S->authenticator, \
			      ASN1_STRING_data(packet1->authenticator), \
			      ASN1_STRING_length(packet1->authenticator));

	retn = true;

	
 done:
	if ( retn == false )
		S->poisoned = true;
	if ( packet1 != NULL )
		packet1_payload_free(packet1);

	WHACK(payload);
	return retn;
}


/**
 * External public method.
 *
 * This method sets the key schedule to be used for the POSSUM exchange.
 *
 * \param this		The exchange for which the schedule is to be set.
 *
 * \param token		The identity token to be used for the scheduler.
 *
 * \param auth_time	The authentication time to be used for scheduling
 *			the key.
 *
 * \return		A boolean value is used to indicate whether or
 *			not key scheduling was successful.  A true
 *			value indicates the schedule was set with a false
 *			value indicating an error was experienced.
 */

static _Bool set_schedule(CO(PossumPacket, this), CO(IDtoken, token), \
			  time_t auth_time)

{
	STATE(S);

	_Bool retn = false;

	Buffer idkey,
	       idhash;

	SHA256 hash = NULL;


	/* Verify arguements. */
	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;

	/* Set the authentication time. */
	S->auth_time = auth_time;

	/*
	 * Get the identity elements to be used from the token.  If
	 * the identity is not a hash value compute the hash of
	 * the identity.
	 */
	INIT(NAAAIM, SHA256, hash, goto done);
	if ( (idkey = token->get_element(token, IDtoken_key)) == NULL )
		goto done;
	if ( (idhash = token->get_element(token, IDtoken_id)) == NULL )
		goto done;
	if ( idhash->size(idhash) != NAAAIM_IDSIZE ) {
		hash->add(hash, idhash);
		if ( !hash->compute(hash) )
			goto done;
		idhash = hash->get_Buffer(hash);
	}

	if ( S->otedks->compute(S->otedks, S->auth_time, idkey, idhash) )
		retn = true;

 done:
	WHACK(hash);

	return retn;
}


/**
 * External public method.
 *
 * This method prints the contents of an PossumPacket object.  The
 * status, ie, whether or not the object has been poisoned is also
 * indicated.
 *
 * \param this	A pointer to the object which is to be printed..
 */

static void print(CO(PossumPacket, this))

{
	STATE(S);


	if ( S->poisoned )
		fputs("* POISONED *\n", stdout);

	fputs("identity:\n", stdout);
	S->identity->print(S->identity);

	fprintf(stdout, "time: %d\n", (int) S->auth_time);

	fputs("authenticator:\n", stdout);
	S->authenticator->print(S->authenticator);

	return;
}


/**
 * External public method.
 *
 * This method implements resetting of an authenticator object.  It
 * allows an authenicator to be used multiple times.
 *
 * \param this	The object to be reset.
 */

static void reset(CO(PossumPacket, this))

{
	STATE(S);


	if ( S->poisoned )
		return;

	S->identity->reset(S->identity);
	S->auth_time = 0;
	S->authenticator->reset(S->authenticator);

	return;
}
     

/**
 * External public method.
 *
 * This method implements a destructor for a PossumPacket object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(PossumPacket, this))

{
	STATE(S);


	/* Release Buffer elements. */
	WHACK(S->otedks);
	WHACK(S->nonce);
	WHACK(S->identity);
	WHACK(S->authenticator);
	WHACK(S->checksum);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a PossumPacket object.
 *
 * \return	A pointer to the initialized PossumPacket.  A null value
 *		indicates an error was encountered in object generation.
 */

extern PossumPacket NAAAIM_PossumPacket_Init(void)

{
	Origin root;

	PossumPacket this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_PossumPacket);
	retn.state_size   = sizeof(struct NAAAIM_PossumPacket_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_PossumPacket_OBJID, \
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	if ( (this->state->otedks = NAAAIM_OTEDKS_Init(BIRTHDATE)) == NULL )
		goto err;
	INIT(HurdLib, Buffer, this->state->identity, goto err);
	INIT(HurdLib, Buffer, this->state->authenticator, goto err);
	INIT(HurdLib, Buffer, this->state->checksum, goto err);

	/* Method initialization. */
	this->create_packet1 = create_packet1;
	this->get_identity	= get_identity;
	this->get_authenticator = get_authenticator;
	this->encode_packet1	   = encode_packet1;
	this->decode_packet1	   = decode_packet1;

	this->set_schedule = set_schedule;
	this->print	   = print;
	this->reset	   = reset;
	this->whack	   = whack;

	return this;

 err:
	WHACK(this->state->otedks);
	WHACK(this->state->identity);
	WHACK(this->state->authenticator);
	WHACK(this->state->checksum);

	whack(this);
	return NULL;
}
