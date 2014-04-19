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

#include <Curve25519.h>

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

/* Protocol packet numbers. */
#define POSSUMPACKET_MAGIC1 ((NAAAIM_LIBID << 16) | NAAAIM_PossumPacket_OBJID)

/* Protocol definitions. */
#define POSSUM_PROTOCOL1 (POSSUM_PACKET_TRIPLEDES_CBC << 24) | \
			 (POSSUM_PACKET_HMAC_MD5 << 16 )     | \
			 (POSSUM_PACKET_EC << 8)	     | \
			 POSSUM_PACKET_CURVE25519


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
	 * Packet magic number.
	 */
	uint32_t magic;

	/**
	 * Protocol number.
	 */
	uint32_t protocol;

	/**
	 * Security parameter index.
	 */
	uint32_t spi;

	/**
	 * Requested authentication time.
	 */
	time_t auth_time;

	/**
	 * The object holding the nonce's which will be used.  A total
	 * of 64 bytes will be generated, 32 bytes will be used to
	 * protect against a reply and 32 will be used for the hardware
	 * quote.
	 */
	Buffer nonce;

	/**
	 * The object holding the DH public key to be used for the
	 * key exchange.
	 */
	Buffer public;

	/**
	 * The object holding the hardware quote.
	 */
	Buffer hardware;

	/**
	 * The Buffer object which holds the concantenation of the identity
	 * NONE and the SCRYPT hash using that salt.
	 */
	Buffer identity;
};


/**
 * The following definitions define the ASN1 encoding sequence for
 * the DER encoding of the authenticator which will be transmitted over
 * the wire.
 */
typedef struct {
	ASN1_INTEGER *magic;
	ASN1_INTEGER *protocol;
	ASN1_INTEGER *spi;
	ASN1_OCTET_STRING *nonce;
	ASN1_OCTET_STRING *public;
        ASN1_OCTET_STRING *hardware;
} packet1_payload;

ASN1_SEQUENCE(packet1_payload) = {
	ASN1_SIMPLE(packet1_payload, magic,	ASN1_INTEGER),
	ASN1_SIMPLE(packet1_payload, protocol,	ASN1_INTEGER),
	ASN1_SIMPLE(packet1_payload, spi,	ASN1_INTEGER),
	ASN1_SIMPLE(packet1_payload, nonce,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(packet1_payload, public,	ASN1_OCTET_STRING),
	ASN1_SIMPLE(packet1_payload, hardware,	ASN1_OCTET_STRING),
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
	S->magic	 = 0;
	S->protocol	 = 0;
	S->spi		 = 0;
	S->auth_time	 = 0;

	S->otedks	 = NULL;
	S->nonce	 = NULL;
	S->public	 = NULL;
	S->hardware	 = NULL;
	S->identity	 = NULL;

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
 * \param checksum	The object which is to hold the computed
 *			checksum.
 *
 * \return		If an error is encountered a false value is
 *			returned, a true value indicates the authenticator
 *			was constructed.
 */

static _Bool compute_checksum(CO(PossumPacket_State, S),	      \
			      CO(Buffer, status), CO(Buffer, packet), \
			      CO(Buffer, checksum))

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

	if ( checksum->add_Buffer(checksum, hmac->get_Buffer(hmac)) )
		retn = true;

 done:
	WHACK(hmac_key);
	WHACK(hmac);

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
 * \param dh		The elliptic curve to be used to implement
 *			the shared key.
 *
 * \param spi		The Security Parameter Index to be proposed/used.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of creating the packet.  A false value
 *		indicates creation failed while a true indicates it
 *		was successful.
 */

static _Bool create_packet1(CO(PossumPacket, this), CO(IDtoken, token),
			    CO(Curve25519, dh), const uint32_t spi)

{

	STATE(S);

	_Bool retn = false;

	Buffer b;

	RandomBuffer rnd = NULL;

	SHA256_hmac hmac = NULL;


	/* Status checks. */
	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;
	if ( (dh == NULL) || dh->poisoned(dh) )
		goto done;

	/* Set the Security Parameter Index. */
	S->spi = spi;

	/* Load the identification challenge nonce. */
	INIT(NAAAIM, RandomBuffer, rnd, goto done);
	rnd->generate(rnd, 256 / 8);
	S->identity->add_Buffer(S->identity, rnd->get_Buffer(rnd));

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

	/* Add 32 bytes for the replay nonce. */
	rnd->generate(rnd, 32);
	if ( !S->nonce->add_Buffer(S->nonce, rnd->get_Buffer(rnd)) )
		goto done;

	/* Add the Diffie-Hellman key. */
	if ( (b = dh->get_public(dh)) == NULL )
		goto done;
	if ( !S->public->add_Buffer(S->public, b) )
		goto done;

	/* Add the hardware status quote. */
	if ( !S->hardware->add_hexstring(S->hardware, "0000fead0000beaf") )
		goto done;

	retn = true;

 done:
 	WHACK(rnd);
	WHACK(hmac);

	if ( retn == false )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of the second POSSUM exchange
 * packet.  This packet is sent by the host in response to a
 * POSSUM packet1 to verify and attest to the status of the host.
 *
 * \param this		The object whose packet 2 state is to be
 *			created.
 *
 * \param token		The identity token to be used to create the
 *			state.
 *
 * \param dh		The elliptic curve to be used to implement
 *			the shared key.
 *
 * \return	A boolean value is used to indicate the sucess or
 *		failure of creating the packet.  A false value
 *		indicates creation failed while a true indicates it
 *		was successful.
 */

#if 0
static _Bool create_packet2(CO(PossumPacket, this), CO(IDtoken, token),
			    CO(Curve25519, dh))

{

	STATE(S);

	_Bool retn = false;

	Buffer b;

	RandomBuffer rnd = NULL;

	SHA256_hmac hmac = NULL;


	/* Status checks. */
	if ( S->poisoned )
		goto done;
	if ( token == NULL )
		goto done;
	if ( (dh == NULL) || dh->poisoned(dh) )
		goto done;

	/* Load the identification challenge nonce. */
	INIT(NAAAIM, RandomBuffer, rnd, goto done);
	rnd->generate(rnd, 256 / 8);
	S->identity->add_Buffer(S->identity, rnd->get_Buffer(rnd));

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

	/* Add 32 bytes for the replay nonce. */
	rnd->generate(rnd, 32);
	if ( !S->nonce->add_Buffer(S->nonce, rnd->get_Buffer(rnd)) )
		goto done;

	/* Add the Diffie-Hellman key. */
	if ( (b = dh->get_public(dh)) == NULL )
		goto done;
	if ( !S->public->add_Buffer(S->public, b) )
		goto done;

	/* Add the hardware status quote. */
	if ( !S->hardware->add_hexstring(S->hardware, "0000fead0000beaf") )
		goto done;

	retn = true;

 done:
 	WHACK(rnd);
	WHACK(hmac);

	if ( retn == false )
		S->poisoned = true;
	return retn;
}
#endif

			 
/**
 * Internal private method.
 *
 * This function uses ASN.1 encoding to marshall the elements of the
 * identity authenticator into a buffer and then encrypts the buffer
 * with under the OTEDKS epoch key.
 *
 * \param state		The state of the object for which the
 *			authenticator is being built.
 *
 * \param bufr		The object which the encrypted authenticator
 *			is to be added to.
 *
 * \return		If an error is encountered a false value is
 *			returned, a true value indicates the authenticator
 *			was constructed.
 */

static _Bool create_authenticator(CO(PossumPacket_State, S), CO(Buffer, bufr))

{
	_Bool retn = false;

        unsigned char *asn = NULL;

        unsigned char **p = &asn;

	int asn_size;

	Buffer key,
	       iv,
	       auth = NULL;

	AES256_cbc cipher = NULL;

	packet1_payload *packet1 = NULL;


	/* Set the packet magic number. */
	S->magic = POSSUMPACKET_MAGIC1;

	/* Set the packet protocol number. */
	S->protocol = POSSUM_PROTOCOL1;

	/* ASN1 encode the authenticator. */
	INIT(HurdLib, Buffer, auth, goto done);

	if ( (packet1 = packet1_payload_new()) == NULL )
		goto done;

	if ( ASN1_INTEGER_set(packet1->magic, S->magic) != 1 )
		goto done;

	if ( ASN1_INTEGER_set(packet1->protocol, S->protocol) != 1 )
		goto done;

	if ( ASN1_INTEGER_set(packet1->spi, S->spi) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(packet1->nonce, S->nonce->get(S->nonce), \
				   S->nonce->size(S->nonce)) != 1 )
		goto done;

	if ( ASN1_OCTET_STRING_set(packet1->public,	      \
				   S->public->get(S->public), \
				   S->public->size(S->public)) != 1 )
		goto done;

        if ( ASN1_OCTET_STRING_set(packet1->hardware,			\
				   S->hardware->get(S->hardware),	\
                                   S->hardware->size(S->hardware)) != 1 )
                goto done;

        asn_size = i2d_packet1_payload(packet1, p);
        if ( asn_size < 0 )
                goto done;
	if ( !auth->add(auth, asn, asn_size) )
		goto done;

	/* Encrypt the authenticator. */
	key = S->otedks->get_key(S->otedks);
	iv  = S->otedks->get_iv(S->otedks);

	if ( (cipher = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		goto done;
	if ( cipher->encrypt(cipher, auth) == NULL )
		goto done;

	if ( bufr->add_Buffer(bufr, cipher->get_Buffer(cipher)) )
		retn = true;

 done:
	if ( !retn )
		S->poisoned = true;
	if ( packet1 != NULL )
		packet1_payload_free(packet1);

	WHACK(auth);
	WHACK(cipher);

	return retn;
}


/**
 * External public method.
 *
 * This method implements packaging of the various components of
 * a type 1 packet into a buffer and then computes a checksum over
 * the packet.
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

	uint32_t auth_time;

	Buffer checksum = NULL;


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

	/* Add the encrypted authenticator to the packet. */
	if ( !create_authenticator(S, bufr) )
		goto done;

	/* Append the checksum to the packet. */
	INIT(HurdLib, Buffer, checksum, goto done);
	if ( !compute_checksum(S, status, bufr, checksum) )
		goto done;
	if ( bufr->add_Buffer(bufr, checksum) )
		retn = true;


 done:
	if ( retn == false )
		S->poisoned = true;

	WHACK(checksum);

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

	Buffer b,
	       iv,
	       key,
	       payload	= NULL,
	       checksum = NULL;

	AES256_cbc cipher = NULL;


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
	S->identity->add(S->identity, packet->get(packet), 2*NAAAIM_IDSIZE);
	S->auth_time = *((uint32_t *) (packet->get(packet) + 2*NAAAIM_IDSIZE));
	S->auth_time = ntohl(S->auth_time);
	this->set_schedule(this, token, S->auth_time);

	/* Set the protocol number. */

	/* Compute the checksum over the packet. */
	INIT(HurdLib, Buffer, payload, goto done);
	if ( !payload->add(payload, packet->get(packet), \
			   packet->size(packet) - NAAAIM_IDSIZE) )
		goto done;

	INIT(HurdLib, Buffer, checksum, goto done);
	if ( !compute_checksum(S, status, payload, checksum) )
		goto done;

	p  = packet->get(packet) + packet->size(packet);
	p -= NAAAIM_IDSIZE;
	if ( memcmp(checksum->get(checksum), p, NAAAIM_IDSIZE) != 0 )
		goto done;

	
	/* Extract the encrypted authenticator. */
	p = packet->get(packet) + 2*NAAAIM_IDSIZE + sizeof(uint32_t);
	asn_size = packet->size(packet) - 3*NAAAIM_IDSIZE - sizeof(uint32_t);
	payload->reset(payload);
	if ( !payload->add(payload, p, asn_size) )
		goto done;

	/* Decrypt the authenticator.. */
	iv  = S->otedks->get_iv(S->otedks);
	key = S->otedks->get_key(S->otedks);
	if ( (cipher = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		goto done;
	if ( !cipher->decrypt(cipher, payload) )
		goto done;
	b = cipher->get_Buffer(cipher);

	/* Unmarshall the ASN1 structure. */
	p = b->get(b);
        if ( !d2i_packet1_payload(&packet1, &p, asn_size) )
                goto done;

	S->magic    = ASN1_INTEGER_get(packet1->magic);
	S->protocol = ASN1_INTEGER_get(packet1->protocol);
	S->spi	    = ASN1_INTEGER_get(packet1->spi);

	S->nonce->add(S->nonce, ASN1_STRING_data(packet1->nonce), \
		      ASN1_STRING_length(packet1->nonce));
	S->public->add(S->public, ASN1_STRING_data(packet1->public), \
		       ASN1_STRING_length(packet1->public));
	S->hardware->add(S->hardware, ASN1_STRING_data(packet1->hardware), \
			 ASN1_STRING_length(packet1->hardware));

	if ( S->magic == POSSUMPACKET_MAGIC1 )
		retn = true;

 done:
	if ( retn == false )
		S->poisoned = true;
	if ( packet1 != NULL )
		packet1_payload_free(packet1);

	WHACK(payload);
	WHACK(checksum);
	WHACK(cipher);

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
 * This method implements a general accessor for retrieving numeric
 * element from a POSSUM packet.
 *
 * \param this		The packet whose element value to be retrieved.
 *
 * \param element	The enumerated type of the value to be
 *			retrieved.
 *
 * \return		The requested Buffer object is returned.  A
 *			NULL value is used to indicate that an
 *			unknown element was requested.
 */

static uint32_t get_value(CO(PossumPacket, this), \
			  const PossumPacket_value value)

{
	STATE(S);


	if ( S->poisoned )
		return 0;

	switch ( value ) {
		case PossumPacket_spi:
			return S->spi;
			break;
		case PossumPacket_protocol:
			return S->protocol;
			break;

		default:
			return 0;
			break;
	}

	return 0;
}


/**
 * External public method.
 *
 * This method implements a general accessor for retrieving components
 * of a POSSUM packet.
 *
 * \param this		The packet whose element is to be retrieved.
 *
 * \param element	The enumerated type of the element to be
 *			retrieved.
 *
 * \return		The requested Buffer object is returned.  A
 *			NULL value is used to indicate that an
 *			unknown element was requested.
 */

static Buffer get_element(CO(PossumPacket, this), \
			   const PossumPacket_element element)

{
	STATE(S);


	if ( S->poisoned )
		return NULL;

	switch ( element ) {
		case PossumPacket_nonce:
			return S->nonce;
			break;
		case PossumPacket_public:
			return S->public;
			break;
		case PossumPacket_hardware:
			return S->hardware;
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

	fprintf(stdout, "magic: %08x\n", S->magic);
	fprintf(stdout, "protocol: %08x\n", S->protocol);
	fprintf(stdout, "time: %d\n", (int) S->auth_time);
	fprintf(stdout, "spi: %08x\n", S->spi);

	fputs("nonce:\n", stdout);
	S->nonce->print(S->nonce);

	fputs("public:\n", stdout);
	S->public->print(S->public);

	fputs("hardware:\n", stdout);
	S->hardware->print(S->hardware);

	fputs("identity:\n", stdout);
	S->identity->print(S->identity);


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

	S->magic	= 0;
	S->protocol	= 0;
	S->auth_time	= 0;

	S->otedks->reset(S->otedks);
	S->nonce->reset(S->nonce);
	S->public->reset(S->public);
	S->hardware->reset(S->hardware);
	S->identity->reset(S->identity);

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
	WHACK(S->public);
	WHACK(S->hardware);
	WHACK(S->identity);

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
	INIT(HurdLib, Buffer, this->state->nonce, goto err);
	INIT(HurdLib, Buffer, this->state->public, goto err);
	INIT(HurdLib, Buffer, this->state->hardware, goto err);
	INIT(HurdLib, Buffer, this->state->identity, goto err);

	/* Method initialization. */
	this->create_packet1 = create_packet1;
	this->encode_packet1 = encode_packet1;

	this->decode_packet1 = decode_packet1;

	this->set_schedule = set_schedule;
	this->get_value	   = get_value;
	this->get_element  = get_element;

	this->print	   = print;
	this->reset	   = reset;
	this->whack	   = whack;

	return this;

 err:
	WHACK(this->state->otedks);
	WHACK(this->state->nonce);
	WHACK(this->state->public);
	WHACK(this->state->hardware);
	WHACK(this->state->identity);

	whack(this);
	return NULL;
}
