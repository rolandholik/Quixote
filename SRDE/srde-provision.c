/** \file
 * This file contains a utility which provisions an platform specific
 * EPID token to the platform.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions local to this file. */
#define PGM		"srde-provision"
#define COPYRIGHT	"%s: Copyright (c) %s, %s. All rights reserved.\n"
#define DATE		"2020"
#define COMPANY		"Enjellic Systems Development, LLC"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <SHA256.h>
#include <RandomBuffer.h>
#include <HTTP.h>

#include "SRDE.h"
#include "PCEenclave.h"
#include "SRDEmessage.h"
#include "SRDEepid.h"
#include "PVEenclave.h"
#include "SRDEecdsa.h"
#include "intel-messages.h"

#include "SRDEaesgcm.h"
#include "SRDEcmac.h"


/**
 * Definitions for the ECC256 public key structure.
 */
struct sgx_ec256_public
{
	uint8_t gx[32];
	uint8_t gy[32];
};


/**
 * Structure definition for an ECC256 signature.  This needs to
 * be converted to bytes rather then double words but this format
 * will be retained until signature verification is completed.
 */
struct sgx_ec256_signature
{
	uint8_t x[32];
	uint8_t y[32];
};


/**
 * The default PEK key supplied by Intel.
 */
const struct sgx_ec256_public pek_pub_key = {
	{
		0xd3, 0x43, 0x31, 0x3b, 0xf7, 0x3a, 0x1b, 0xa1,
		0xca, 0x47, 0xb2, 0xab, 0xb2, 0xa1, 0x43, 0x4d,
		0x1a, 0xcd, 0x4b, 0xf5, 0x94, 0x77, 0xeb, 0x44,
		0x5a, 0x06, 0x2d, 0x13, 0x4b, 0xe1, 0xc5, 0xa0
	},
	{
		0x33, 0xf8, 0x41, 0x6b, 0xb2, 0x39, 0x45, 0xcc,
		0x8d, 0xcd, 0x81, 0xb4, 0x80, 0xb4, 0xbd, 0x82,
		0x11, 0xf2, 0xdc, 0x9c, 0x0b, 0x4c, 0x8a, 0x28,
		0xb0, 0xaa, 0xca, 0x65, 0x14, 0xd2, 0xc8, 0x62
	}
};


/**
 * Object to hold validated server name.
 */
static String Server = NULL;

/**
 * Variable to hold the message TTL.
 */
static uint16_t Ttl = 0;

/**
 * Flag variable to request verbose output.
 */
static _Bool Verbose = false;


/**
 * Internal public function.
 *
 * This method implements outputting of an error message and status
 * information on how to run the utility.
 *
 * \param err	A pointer to a null-terminated buffer holding the
 *		error message to be output.
 *
 * \return	No return value is defined.
 */

static void usage(char *err)

{
	fprintf(stdout, "%s: EPID provisioning tool.\n", PGM);
	fprintf(stdout, COPYRIGHT, PGM, DATE, COMPANY);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("Usage:\n", stdout);
	fputs("\t-p:\tThe file containing the PCE initialization token\n", \
	      stdout);
	fputs("\t-t:\tThe file containing the PVE initialization token\n\n", \
	      stdout);

	return;
}


/**
 * Internal public function.
 *
 * This method implements reading the contents of an input file.
 *
 * \param fname		A pointer to the null-terminated string containing
 *			the name of the file which is to be read.
 *
 * \param msg		The object which the contents of the file is
 *			be read into.
 *
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of reading the file.  A false value indicates
 *		the read failed while a true file indicates the supplied
 *		object has the contents of the file.
 */

static _Bool read_input(CO(char *, fname), CO(String, msg))

{
	_Bool retn = false;

	unsigned char *p;

	File infile = NULL;

	Buffer bufr = NULL;


	/* Verify the object status. */
	if ( msg->poisoned(msg) )
		ERR(goto done);


	/* Open and read in the contents of the file. */
	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, fname) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !infile->slurp(infile, bufr) )
		ERR(goto done);

	if ( bufr->size == 0 ) {
		fputs("No file input.\n", stderr);
		ERR(goto done);
	}

	p = bufr->get(bufr) + bufr->size(bufr) - 1;
	if ( *p == '\n' )
		*p = '\0';
	else {
		if ( !bufr->add(bufr, (void *) "\0", 1) )
			ERR(goto done);
	}

	if ( !msg->add(msg, (char *) bufr->get(bufr)) )
		ERR(goto done);
	retn = 1;


 done:
	WHACK(infile);
	WHACK(bufr);

	return retn;
}


/**
 * Internal private function.
 *
 * This function is a subordinate helper function for the
 * process_message1 function.  This function verifies the ECDSA
 * signature in the PEK structure.
 *
 * \param msg		A pointer to the object which is managing
 *			the message.
 *
 * \param pekbufr	An object containing the PEK structure in
 *			binary form.
 *
 * \return		A boolean value is used to indicated the status
 *			of signature verifiocation.  A false value
 *			indicates verification failed while a true
 *			value indicates the signature was verified.
 */

static _Bool _verify_pek(CO(SRDEmessage, msg), CO(Buffer, pekbufr))

{
	_Bool retn = false;

	size_t lp,
	       index;

	struct SGX_pek pek;

	struct sgx_ec256_signature signature;

	Buffer sig     = NULL,
	       key     = NULL,
	       pbufr   = NULL;

	SRDEecdsa ecdsa = NULL;


	/* Work on a local copy of the PEK structure. */
	memcpy(&pek, pekbufr->get(pekbufr), sizeof(struct SGX_pek));

	INIT(HurdLib, Buffer, pbufr, ERR(goto done));
	if ( !pbufr->add(pbufr, (void *) &pek, sizeof(pek.n) + sizeof(pek.e)) )
		ERR(goto done);


	/* Convert the signature to big endian format. */
	INIT(HurdLib, Buffer, sig, ERR(goto done));
	memcpy(&signature, pek.pek_signature, sizeof(signature));

	index = sizeof(signature.x) - 1;
	for (lp= 0; lp < sizeof(signature.x); ++lp) {
		sig->add(sig, (unsigned char *) &signature.x[index], 1);
		--index;
	}
	if ( sig->poisoned(sig) )
		ERR(goto done);
	memcpy(&signature.x, sig->get(sig), sizeof(signature.x));

	sig->reset(sig);
	index = sizeof(signature.y) - 1;
	for (lp= 0; lp < sizeof(signature.y); ++lp) {
		sig->add(sig, (unsigned char *) &signature.y[index], 1);
		--index;
	}
	if ( sig->poisoned(sig) )
		ERR(goto done);

	memcpy(&signature.y, sig->get(sig), sizeof(signature.y));
	sig->reset(sig);
	if ( !sig->add(sig, (void *) &signature, sizeof(signature)) )
		ERR(goto done);


	/* Verify the signature. */
	INIT(HurdLib, Buffer, key, ERR(goto done));
	if ( !key->add(key, (void *) &pek_pub_key, sizeof(pek_pub_key)) )
		ERR(goto done);

	INIT(NAAAIM, SRDEecdsa, ecdsa, ERR(goto done));
	if ( !ecdsa->verify(ecdsa, key, pbufr, sig) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(key);
	WHACK(pbufr);
	WHACK(sig);
	WHACK(ecdsa);

	return retn;
}


/**
 * Internal private function.
 *
 * This function is a subordinate helper function for the
 * process_message1 function.  This function verifies the signature
 * of the provisioning server attributes using the RSA key
 * extracted from the PEK structure that was previously validated.
 *
 * The server URL and the time-to-live parameter are obtained from
 * statically scoped variables that were previously extracted.
 *
 * \param msg	A pointer to the object which is managing the
 *		message.
 *
 * \param pek	A pointer to the PEK structure.
 *
 * \return	A boolean value is used to indicated the status of
 *		the endpoint verfication.  A false value indicates
 *		the verification filed while a true value indicates
 *		the endpoint attributes are valid.
 */

static _Bool _verify_endpoint(CO(SRDEmessage, msg), \
			      CO(struct SGX_pek *, pek), CO(Buffer, signature))

{
	_Bool retn = false;

	static const uint8_t der[] = {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20
	};

	unsigned char sigout[sizeof(der) + 32];

	BIGNUM *exponent = NULL,
	       *modulus	 = NULL;

	RSA *key = NULL;

	Buffer b;

	Sha256 sha256 = NULL;


	/*
	 * Convert the exponent and modulus from binary big-endian
	 * format into big numbers.
	 */
	if ( (exponent = BN_bin2bn(pek->e, sizeof(pek->e), NULL)) == NULL )
		ERR(goto done);

	if ( (modulus = BN_bin2bn(pek->n, sizeof(pek->n), NULL)) == NULL )
		ERR(goto done);

	if ( (key = RSA_new()) == NULL )
		ERR(goto done);
	if ( RSA_set0_key(key, modulus, exponent, NULL) == 0 )
		ERR(goto done);


	/* Decrypt and extract the signature. */
	memset(sigout, '\0', sizeof(sigout));
	if ( RSA_public_decrypt(signature->size(signature) - 1,	       \
				signature->get(signature) + 1, sigout, \
				key, RSA_PKCS1_PADDING) == -1 )
	       ERR(goto done);

	signature->reset(signature);
	if ( !signature->add(signature, sigout, sizeof(sigout)) )
		ERR(goto done);

	if ( memcmp(signature->get(signature), der, sizeof(der) != 0) )
		ERR(goto done);
        signature->reset(signature);
	if ( !signature->add(signature, sigout + sizeof(der), \
			     sizeof(sigout) - sizeof(der)) )
		ERR(goto done);

	memset(sigout, '\0', sizeof(sigout));
	memcpy(sigout, signature->get(signature), signature->size(signature));
	signature->reset(signature);


	/* Compute and compare the hash of the endpoint information. */
	if ( !msg->get_xid(msg, signature) )
		ERR(goto done);
	signature->add(signature, (unsigned char *) &Ttl, sizeof(Ttl));
	if ( !signature->add(signature,				    \
			     (unsigned char *) Server->get(Server), \
			     Server->size(Server)) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, sha256, ERR(goto done));
	sha256->add(sha256, signature);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	if ( !memcmp(sigout, b->get(b), b->size(b)) == 0 )
		ERR(goto done);
	retn = true;


 done:
	RSA_free(key);

	WHACK(sha256);

	return retn;
}


/**
 * Internal private function.
 *
 * This function implements the process of validating an endpoint
 * verification message from the Intel servers.  This message provides
 * a validated URL to be used for further message processing.
 *
 * \param msg		A pointer to the object which is managing
 *			the message.
 *
 * \param response	An object containing the string encoded message
 *			returned from the Intel server.
 *
 * \return		A boolean value is used to indicated the status
 *			of the message processing.  A false value
 *			indicates that message processing failed while
 *			a true value indicates the message was
 *			processed and verified.
 */

static _Bool process_message1(CO(SRDEmessage, msg), CO(String, response), \
			      struct SGX_pek *pek)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	struct SGX_pek lpek;


	/* Decode and verify the message count. */
	if ( !msg->decode(msg, response) )
		ERR(goto done);
	if ( msg->message_count(msg) != 3 )
		ERR(goto done);
	if ( Verbose )
		msg->dump(msg);


	/* Extract the server TTL and URL. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !msg->get_message(msg, TLV_ES_INFORMATION, 1, bufr) )
		ERR(goto done);

	Ttl = *(uint16_t *) bufr->get(bufr);
	Ttl = ntohs(Ttl);

	if ( !bufr->add(bufr, (unsigned char *) "\0", 1) )
		ERR(goto done);

	INIT(HurdLib, String, Server, ERR(goto done));
	if ( !Server->add(Server, (char *) (bufr->get(bufr) + sizeof(Ttl))) )
		ERR(goto done);

	if ( Verbose ) {
		fputs("\nSERVER:\n\t", stdout);
		Server->print(Server);
		fprintf(stdout, "\tTTL: %u\n", Ttl);
	}


	/* Process the PEK message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_PEK, 2, bufr) )
		ERR(goto done);

	if ( !_verify_pek(msg, bufr) )
		ERR(goto done);
	if ( Verbose )
		fputs("\nPEK verified.\n", stdout);
	memcpy(&lpek, bufr->get(bufr), sizeof(struct SGX_pek));


	/* Process the signature message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_SIGNATURE, 1, bufr) )
		ERR(goto done);
	if ( !_verify_endpoint(msg, &lpek, bufr) )
		ERR(goto done);

	if ( Verbose )
		fputs("\nEndpoint verified:\n", stdout);
	*pek = lpek;
	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * Internal private function.
 *
 * This function is a subordinate helper function for the
 * process_message2 function.  This function verifies and decrypts
 * the internal message.
 *
 * \param msg	A pointer to the object which is managing the
 *		message.
 *
 * \param sk	A pointer to the transaction id which was used to
 *		generate the outgoing message that generated the
 *		message being processed.
 *
 * \param msg2	The object which will be loaded with the decrypted
 *		internal message.
 *
 * \param nonce	The object that will be loaded with the nonce
 *		supplied by the provisiong server for the received
 *		message.
 *
 * \return	A boolean value is used to indicated the status of
 *		the decryption.  A false value indicates
 *		the decryption failed while a true value indicates
 *		the output object carries a valid message.
 */

static _Bool _decrypt_message2(CO(SRDEmessage, msg), CO(Buffer, sk), \
			       CO(Buffer, msg2), CO(Buffer, nonce))

{
	_Bool retn = false;

	Buffer bufr    = NULL,
	       aaad    = NULL,
	       iv      = NULL,
	       key     = NULL,
	       payload = NULL,
	       encout  = NULL;

	SRDEcmac cmac = NULL;

	SRDEaesgcm aesgcm = NULL;


	/* Compute the key to be used for decrypting the payload. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !msg->get_xid(msg, bufr) )
		ERR(goto done);

	if ( !msg->get_message(msg, TLV_NONCE, 1, nonce) )
		ERR(goto done);
	if ( !bufr->add_Buffer(bufr, nonce) )
		ERR(goto done);

	INIT(HurdLib, Buffer, key, ERR(goto done));
	INIT(NAAAIM, SRDEcmac, cmac, ERR(goto done));
	if ( !cmac->compute(cmac, sk, bufr, key) )
		ERR(goto done);

	sk->reset(sk);
	if ( !sk->add_Buffer(sk, key) )
		ERR(goto done);

	INIT(HurdLib, Buffer, aaad, ERR(goto done));
	if ( !msg->get_header(msg, aaad) )
		ERR(goto done);


	/* Extract the initialization vector and the encrypted payload. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_BLOCK_CIPHER_TEXT, 1, bufr) )
		ERR(goto done);

	INIT(HurdLib, Buffer, iv, ERR(goto done));
	if ( !iv->add(iv, bufr->get(bufr), 12) )
		ERR(goto done);

	INIT(HurdLib, Buffer, payload, ERR(goto done));
	if ( !payload->add(payload, bufr->get(bufr) + 12, \
			   bufr->size(bufr) - 12) )
		ERR(goto done);

	/* Get the authentication code and decrypt the payload. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_MESSAGE_AUTHENTICATION_CODE, 1, bufr) )
		ERR(goto done);

	INIT(NAAAIM, SRDEaesgcm, aesgcm, ERR(goto done));
	if ( !aesgcm->decrypt(aesgcm, key, iv, payload, msg2, aaad, bufr) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(aaad);
	WHACK(iv);
	WHACK(key);
	WHACK(payload);
	WHACK(encout);

	WHACK(cmac);
	WHACK(aesgcm);

	return retn;
}


/**
 * Internal private function.
 *
 * This function implements the processing of message 2.  This is the
 * message returned from the Intel provisioning server in response to
 * message 1 that was received in response to the endpoint selection
 * message.
 *
 * \param msg		A pointer to the object which is managing
 *			the message.
 *
 * \param response	An object containing the ASCII encoded message
 *			returned from the Intel server.
 *
 * \param sk		The object containing the session to be used
 *			to generate the encryption key to decrypt the
 *			encrypted portion of the payload.  This object
 *			will be loaded with the generated key for
 *			use by the caller in encrypting the returned
 *			payload.
 *
 * \param pek		A pointer to the structure containing the PEK
 *			key that is used as the authentication root
 *			source.
 *
 * \param nonce		The object that will be loaded with the NONCE
 *			that was supplied by the caller.
 *
 * \return		A boolean value is used to indicated the status
 *			of the message processing.  A false value
 *			indicates that message processing failed while
 *			a true value indicates the message was
 *			processed and verified.
 */

static _Bool process_message2(CO(SRDEmessage, msg), CO(String, response), \
			      CO(Buffer, sk), struct SGX_pek *pek,	  \
			      CO(Buffer, nonce))

{
	_Bool retn = false;

	Buffer b,
	       message = NULL;

	Sha256 sha256 = NULL;


	/* Decode and verify the message count. */
	if (!msg->decode(msg, response) )
		ERR(goto done);
	if ( (msg->message_count(msg) != 3) && (msg->message_count(msg) != 4) )
		ERR(goto done);
	if ( msg->message_count(msg) == 4 ) {
		fputs("Message 2 SIGRL not supported.\n", stderr);
		ERR(goto done);
	}
	if ( Verbose )
		msg->dump(msg);


	/* Decrypt the internal message. */
	INIT(HurdLib, Buffer, message, ERR(goto done));
	if ( !_decrypt_message2(msg, sk, message, nonce) )
		ERR(goto done);
	if ( Verbose )
		fputs("\nDecrypted internal message.\n", stdout);

	if ( !msg->reload_messages(msg, message) )
		ERR(goto done);
	if ( (msg->message_count(msg) != 4) && (msg->message_count(msg) != 6) )
		ERR(goto done);

	if ( Verbose ) {
		fputc('\n', stdout);
		msg->dump(msg);
	}

	/* Verify the internal message. */
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	message->reset(message);
	message->add(message, pek->n, sizeof(pek->n) + sizeof(pek->e));
	sha256->add(sha256, message);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	b = sha256->get_Buffer(sha256);

	message->reset(message);
	if ( !msg->get_message(msg, TLV_PS_ID, 1, message) )
		ERR(goto done);
	if ( !message->equal(message, b) )
		ERR(goto done);

	if ( Verbose )
		fputs("\nVerified internal message.\n", stdout);
	retn = true;


 done:
	WHACK(message);
	WHACK(sha256);

	return retn;
}


/**
 * Internal private function.
 *
 * This function is a subordinate helper function for the
 * process_message3 function.  This function verifies and decrypts
 * the internal message.
 *
 * \param msg	A pointer to the object which is managing the
 *		message.
 *
 * \param sk	A pointer to the transaction id which was used to
 *		generate the outgoing message that generated the
 *		message being processed.
 *
 * \param msg3	The object which will be loaded with the decrypted
 *		internal message.
 *
 * \return	A boolean value is used to indicated the status of
 *		the decryption.  A false value indicates
 *		the decryption failed while a true value indicates
 *		the output object carries a valid message.
 */

static _Bool _decrypt_message3(CO(SRDEmessage, msg), CO(Buffer, sk), \
			       CO(Buffer, msg3))

{
	_Bool retn = false;

	Buffer bufr    = NULL,
	       nonce   = NULL,
	       aaad    = NULL,
	       iv      = NULL,
	       key     = NULL,
	       payload = NULL,
	       encout  = NULL;

	SRDEcmac cmac = NULL;

	SRDEaesgcm aesgcm = NULL;


	/* Compute the key to be used for decrypting the payload. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !msg->get_xid(msg, bufr) )
		ERR(goto done);

	INIT(HurdLib, Buffer, nonce, ERR(goto done));
	if ( !msg->get_message(msg, TLV_NONCE, 1, nonce) )
		ERR(goto done);
	if ( !bufr->add_Buffer(bufr, nonce) )
		ERR(goto done);

	INIT(HurdLib, Buffer, key, ERR(goto done));
	INIT(NAAAIM, SRDEcmac, cmac, ERR(goto done));
	if ( !cmac->compute(cmac, sk, bufr, key) )
		ERR(goto done);

	/* Generate the additional authentication information. */
	INIT(HurdLib, Buffer, aaad, ERR(goto done));
	if ( !msg->get_header(msg, aaad) )
		ERR(goto done);
	if ( !aaad->add_Buffer(aaad, nonce) )
		ERR(goto done);


	/* Extract the initialization vector and the encrypted payload. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_BLOCK_CIPHER_TEXT, 1, bufr) )
		ERR(goto done);

	INIT(HurdLib, Buffer, iv, ERR(goto done));
	if ( !iv->add(iv, bufr->get(bufr), 12) )
		ERR(goto done);

	INIT(HurdLib, Buffer, payload, ERR(goto done));
	if ( !payload->add(payload, bufr->get(bufr) + 12, \
			   bufr->size(bufr) - 12) )
		ERR(goto done);

	/* Get the authentication code and decrypt the payload. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_MESSAGE_AUTHENTICATION_CODE, 1, bufr) )
		ERR(goto done);

	INIT(NAAAIM, SRDEaesgcm, aesgcm, ERR(goto done));
	if ( !aesgcm->decrypt(aesgcm, key, iv, payload, msg3, aaad, bufr) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(nonce);
	WHACK(aaad);
	WHACK(iv);
	WHACK(key);
	WHACK(payload);
	WHACK(encout);

	WHACK(cmac);
	WHACK(aesgcm);

	return retn;
}


/**
 * Internal private function.
 *
 * This function implements the processing of provisioning message 3.
 * This is the message returned from the Intel provisioning server in
 * response to the message which was the result of processing message
 * 2.  Message three contains the EPID blob which is the target
 * of the provisioning process.
 *
 * \param msg		A pointer to the object which is managing
 *			the message.
 *
 * \param response	An object containing the ASCII encoded message
 *			returned from the Intel server.
 *
 * \param sk		The object containing the session to be used
 *			to generate the encryption key to decrypt the
 *			encrypted portion of the payload.  This object
 *			will be loaded with the generated key for
 *			use by the caller in encrypting the returned
 *			payload.
 *
 * \return		A boolean value is used to indicated the status
 *			of message three processing.  A false value
 *			indicates that message processing failed while
 *			a true value indicates the message was
 *			processed and verified.
 */

static _Bool process_message3(CO(SRDEmessage, msg), CO(String, response), \
			      CO(Buffer, sk))

{
	_Bool retn = false;

	Buffer message = NULL;


	/* Decode and verify the message count. */
	if (!msg->decode(msg, response) )
		ERR(goto done);
	if ( (msg->message_count(msg) != 3) )
		ERR(goto done);
	if ( Verbose )
		msg->dump(msg);


	/* Decrypt and verify the internal message. */
	INIT(HurdLib, Buffer, message, ERR(goto done));
	if ( !_decrypt_message3(msg, sk, message) )
		ERR(goto done);
	if ( Verbose )
		fputs("\nDecrypted internal message 3.\n", stdout);

	if ( !msg->reload_messages(msg, message) )
		ERR(goto done);
	if ( msg->message_count(msg) != 5 )
		ERR(goto done);

	if ( Verbose ) {
		fputc('\n', stdout);
		msg->dump(msg);
	}

	retn = true;

 done:
	WHACK(message);

	return retn;
}


/**
 * Internal private function.
 *
 * This function implements generation of message output.  If no
 * output file has specified the encoded message is sent to standard
 * output.  Otherwise the message is output into the specified file.
 *
 * \param msg		A pointer to the object which is managing
 *			the message to be output.
 *
 * \param outfile	The name of the output file.
 *
 * \return		No return value is specified.
 */

static void generate_output(CO(SRDEmessage, msg), CO(char *, outfile))

{
	char *url = "http://ps.sgx.trustedservices.intel.com:80/";

	Buffer bufr    = NULL,
	       outbufr = NULL;

	String message = NULL;

	File output = NULL;

	HTTP http = NULL;


	/* Load the message. */
	INIT(HurdLib, String, message, ERR(goto done));
	if ( !msg->encode(msg, message) )
		ERR(goto done);

	/* Issue the HTTP post request. */
	INIT(NAAAIM, HTTP, http, ERR(goto done));
	http->add_arg(http, "-q");

	INIT(HurdLib, Buffer, outbufr, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) message->get(message), \
			message->size(message)) )
		ERR(goto done);

	if ( !http->post(http, url, bufr, outbufr) )
		ERR(goto done);


	/* No output file, send to standard output. */
	if ( outfile == NULL ) {
		if ( !outbufr->add(outbufr, (void *) "\0", 1) )
			ERR(goto done);

		message->reset(message);
		if ( !message->add(message, (char *) outbufr->get(outbufr)) )
			ERR(goto done);
		message->print(message);
	}
	else {
		INIT(HurdLib, File, output, ERR(goto done));
		if ( !output->open_rw(output, outfile) )
			ERR(goto done);
		if ( !output->write_Buffer(output, outbufr) )
			ERR(goto done);
	}


 done:
	WHACK(bufr);
	WHACK(outbufr);
	WHACK(message);
	WHACK(output);
	WHACK(http);

	return;
}


/**
 * Internal private function.
 *
 * This function implements support for saving a PEK structure to
 * a file and reading a PEK structure from a file.  It allows a PEK
 * once generated to be saved for subsequent processing stages.
 *
 * \param pekfile	A character buffer containing the null-terminated
 *			string of the filename to be used to write or
 *			read the PEK.
 *
 * \param mode		A boolean value used to indicate whether the
 *			PEK file is to be read or written.  A value of
 *			false indicates the file is to be written while
 *			a value of true specifies the file is to be
 *			read.
 *
 * \param pek		A pointer to the structure which will be loaded
 *			with the contents of the file.
 *
 * \return		No return value is specified.
 */

static _Bool pek_file(CO(char *, file), _Bool mode, struct SGX_pek *pek)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	File pekfile = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, pekfile, ERR(goto done));

	if ( mode ) {
		if ( !pekfile->open_rw(pekfile, file) )
			ERR(goto done);

		bufr->add(bufr, (void *) pek, sizeof(struct SGX_pek));
		if ( !pekfile->write_Buffer(pekfile, bufr) )
			ERR(goto done);
	} else {
		if ( !pekfile->open_ro(pekfile, file) )
			ERR(goto done);
		if ( !pekfile->slurp(pekfile, bufr) )
			ERR(goto done);
		memcpy(pek, bufr->get(bufr), sizeof(struct SGX_pek));
	}

	retn = true;


 done:
	WHACK(bufr);
	WHACK(pekfile);

	return retn;
}


/* Main program starts here. */

extern int main(int argc, char *argv[])

{
	char *input	    = NULL,
	     *msg_output    = NULL,
	     *sk_value	    = NULL,
	     *pek_fname	    = NULL,
	     *pve_token	    = NULL,
	     *pce_token	    = NULL;

	int opt,
	    retn = 0;

	uint8_t type;

	struct SGX_pek pek;

	struct SGX_targetinfo pce_tgt;

	struct SGX_report pek_report;

	struct SGX_platform_info platform_info;

	struct SGX_message3 msg3;

	enum {
		none=0,
		endpoint,
		message1,
		message2,
		message3,
		test_message,
		dump_message
	} mode = none;

	Buffer b,
	       bufr	  = NULL,
	       nonce	  = NULL,
	       sk_ek2	  = NULL,
	       epid_sig	  = NULL,
	       report_sig = NULL;

	String response = NULL;

	PVEenclave pve = NULL;

	PCEenclave pce = NULL;

	SRDEmessage msg = NULL;

	SRDEepid epid = NULL;

	RandomBuffer rbufr = NULL;

	File epid_output = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "123DETvi:k:o:p:s:t:")) != EOF )
		switch ( opt ) {
			case '1':
				mode = message1;
				break;
			case '2':
				mode = message2;
				break;
			case '3':
				mode = message3;
				break;
			case 'D':
				mode = dump_message;
				break;
			case 'E':
				mode = endpoint;
				break;
			case 'T':
				mode = test_message;
				break;
			case 'v':
				Verbose = true;
				break;

			case 'i':
				input = optarg;
				break;
			case 'k':
				pek_fname = optarg;
				break;
			case 'o':
				msg_output = optarg;
				break;
			case 'p':
				pce_token = optarg;
				break;
			case 's':
				sk_value = optarg;
				break;
			case 't':
				pve_token = optarg;
				break;
		}

	if ( mode == none ) {
		usage("No mode specified.\n");
		return 1;
	}

	if ( (mode == message1) && (input == NULL) ) {
		usage("No message 1 input specified.\n");
		return 1;
	}

	if ( (mode == message3) && (input == NULL) ) {
		usage("No message 3 input specified.\n");
		return 1;
	}

	if ( (mode == dump_message) && (input == NULL) ) {
		usage("No input file for message dump.\n");
		return 1;
	}

	if ( (mode == test_message) && (input == NULL) ) {
		usage("No input file for message testing.\n");
		return 1;
	}


	/* Load input if needed. */
	INIT(NAAAIM, SRDEmessage, msg, ERR(goto done));

	INIT(HurdLib, String, response, ERR(goto done));
	if ( input != NULL ) {
		if ( !read_input(input, response) )
			ERR(goto done);
	}


	/* Dump a received message. */
	if ( mode == dump_message ) {
		if ( !msg->decode(msg, response) )
			ERR(goto done);
		msg->dump(msg);
	}


	/*
	 * Test an incoming message type to determine if it is a
	 * terminal EPID generation message.
	 */
	if ( mode == test_message ) {
		if ( !msg->decode(msg, response) )
			ERR(goto done);
		if ( !msg->get_response_type(msg, &type) )
			ERR(goto done);
		if ( type != 3 )
			retn = 1;
	}


	/* Decode a message 1 response. */
	if ( mode == message1 ) {
		if ( !process_message1(msg, response, &pek) )
			ERR(goto done);


		/* Generate components for message 2. */
		INIT(NAAAIM, PCEenclave, pce, ERR(goto done));
		if ( !pce->open(pce, pce_token) )
			ERR(goto done);
		pce->get_target_info(pce, &pce_tgt);

		INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
		if ( !pve->open(pve, pve_token) )
			ERR(goto done);

		memset(&pek_report, '\0', sizeof(struct SGX_report));
		if ( !pve->get_message1(pve, &pek, &pce_tgt, &pek_report) )
			ERR(goto done);
		if ( Verbose )
			fputs("\nPVE message one created.\n", stdout);
		if ( pek_fname != NULL ) {
			if ( !pek_file(pek_fname, 1, &pek) )
				ERR(goto done);
		}

		if ( !pce->get_info(pce, &pek, &pek_report) )
			ERR(goto done);
		if ( Verbose )
			fputs("\npce information created.\n", stdout);


		/*
		 * Initialize message 2 request:
		 *	protocol: SE_EPID_PROVISIONING (0)
		 *	type: TYPE_PROV_MSG1 (0)
		 *	version: TLV_VERSION2 (2)
		 */
		msg->reset(msg);

		INIT(NAAAIM, RandomBuffer, rbufr, ERR(goto done));
		if ( !rbufr->generate(rbufr, 8) )
			ERR(goto done);
		b = rbufr->get_Buffer(rbufr);

		msg->init_request(msg, 0, 0, 2, b->get(b));

		if ( !msg->encode_message2(msg, rbufr, pce, &pek, \
					   &pek_report) )
			ERR(goto done);

		if ( Verbose )
			msg->dump(msg);
		generate_output(msg, msg_output);

		retn = 0;
		goto done;
	}


	/* Decode a message 2 response. */
	if ( mode == message2 ) {
		if ( sk_value == NULL ) {
			usage("No SK value specified.\n");
			goto done;
		}
		INIT(HurdLib, Buffer, sk_ek2, ERR(goto done));
		if ( !sk_ek2->add_hexstring(sk_ek2, sk_value) )
			ERR(goto done);

		/* Needed: xid, sk, pek, perhaps bpi. */
		if ( pek_fname != NULL ) {
			if ( !pek_file(pek_fname, 0, &pek) )
				ERR(goto done);
		}

		INIT(HurdLib, Buffer, nonce, ERR(goto done));
		if ( !process_message2(msg, response, sk_ek2, &pek, nonce) )
			ERR(goto done);


		/* Get PCE enclave target information. */
		INIT(NAAAIM, PCEenclave, pce, ERR(goto done));
		if ( !pce->open(pce, pce_token) )
			ERR(goto done);
		pce->get_target_info(pce, &pce_tgt);


		/* Generate message three from PVE enclave. */
		INIT(HurdLib, Buffer, epid_sig, ERR(goto done));
		INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
		if ( !pve->open(pve, pve_token) )
			ERR(goto done);

		if ( !pve->get_message3(pve, msg, &pek, &pce_tgt, epid_sig,
					&platform_info, &msg3) )
			ERR(goto done);
		if ( Verbose )
			fputs("\nGenerated message three.\n", stdout);


		/* Sign the report in the message. */
		INIT(HurdLib, Buffer, report_sig, ERR(goto done));
		if ( !pce->certify_enclave(pce, &msg3.pwk2_report, \
					   &platform_info, report_sig) )
			ERR(goto done);

		if ( Verbose )
			fputs("\nReport signature generated.\n", stdout);


		/*
		 * Initialize message 3 request:
		 *	protocol: SE_EPID_PROVISIONING (0)
		 *	type: TYPE_PROV_MSG3 (2)
		 *	version: TLV_VERSION2 (2)
		 */
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		if ( !msg->get_xid(msg, bufr) )
			ERR(goto done);

		msg->reset(msg);
		msg->init_request(msg, 0, 2, 2, bufr->get(bufr));

		if ( !msg->encode_message3(msg, nonce, sk_ek2, &msg3, \
					   epid_sig, report_sig) )
			ERR(goto done);

		if ( Verbose )
			msg->dump(msg);
		generate_output(msg, msg_output);

		retn = 0;
	}


	/* Decode a message 3 response. */
	if ( mode == message3 ) {
		if ( msg_output == NULL ) {
			usage("No output file specified.\n");
			goto done;
		}

		if ( sk_value == NULL ) {
			usage("No SK value specified.\n");
			goto done;
		}
		INIT(HurdLib, Buffer, sk_ek2, ERR(goto done));
		if ( !sk_ek2->add_hexstring(sk_ek2, sk_value) )
			ERR(goto done);

		if ( !process_message3(msg, response, sk_ek2) )
			ERR(goto done);

		/* Generate EPID blob using PVE enclave. */
		INIT(NAAAIM, SRDEepid, epid, ERR(goto done));
		INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
		if ( !pve->open(pve, pve_token) )
			ERR(goto done);
		if ( !pve->get_epid(pve, msg, epid) )
			ERR(goto done);

		if ( !epid->save(epid, msg_output) )
			ERR(goto done);
		if ( Verbose )
			fputc('\n', stdout);
		fprintf(stdout, "Provisioned EPID: %s\n", msg_output);

		retn = 0;
	}


	if ( mode == endpoint ) {
		/* Load the provisioning enclave. */
		INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
		if ( !pve->open(pve, pve_token) )
			ERR(goto done);

		/* Get the endpoint. */
		if ( !pve->get_endpoint(pve) )
			ERR(goto done);

		/* Encode the message. */
		if ( !pve->generate_endpoint_message(pve, msg) )
			ERR(goto done);

		if ( Verbose )
			msg->dump(msg);
		generate_output(msg, msg_output);

		retn = 0;
	}


 done:
	WHACK(bufr);
	WHACK(sk_ek2);
	WHACK(nonce);
	WHACK(epid_sig);
	WHACK(report_sig);
	WHACK(epid);
	WHACK(response);
	WHACK(pve);
	WHACK(pce);
	WHACK(msg);
	WHACK(rbufr);
	WHACK(epid_output);

	WHACK(Server);

	return retn;
}
