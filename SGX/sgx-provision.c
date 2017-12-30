/** \file
 * This file contains a utility which provisions an platform specific
 * EPID token to the platform.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

/* Definitions local to this file. */
#define PGM "sgx-provision"


#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>
#include "SGXmessage.h"
#include "PVEenclave.h"
#include "SGXecdsa.h"
#include "intel-messages.h"


/**
 * Structure definition for the PEK signed structure returned from
 * the intel server.
 */
struct PEK {
	uint8_t n[256];
	uint8_t e[4];
	uint8_t sha1_ne[20];
	uint8_t pek_signature[2 * 32];
	uint8_t sha1_sign[20];
} __attribute__((packed));


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
	fprintf(stdout, "%s: SGX provisioning tool.\n", PGM);
	fprintf(stdout, "%s: (C)IDfusion, LLC\n", PGM);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("Usage:\n", stdout);
	fputs("\t-t:\tThe file containing the initialization token\n\n", \
	      stdout);

	return;
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

static _Bool _verify_pek(CO(SGXmessage, msg), CO(Buffer, pekbufr))

{
	_Bool retn = false;

	size_t lp,
	       index;

	struct PEK pek;

	struct sgx_ec256_signature signature;

	Buffer sig     = NULL,
	       key     = NULL,
	       pbufr   = NULL;

	SGXecdsa ecdsa = NULL;


	/* Work on a local copy of the PEK structure. */
	memcpy(&pek, pekbufr->get(pekbufr), sizeof(struct PEK));

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

	INIT(NAAAIM, SGXecdsa, ecdsa, ERR(goto done));
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

static _Bool process_message1(CO(SGXmessage, msg), CO(String, response))

{
	_Bool retn = false;

	Buffer bufr = NULL;


	/* Decode and verify the message count. */
	if ( !msg->decode(msg, response) )
		ERR(goto done);
	if ( msg->message_count(msg) != 3 )
		ERR(goto done);
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

	fputs("\nSERVER:\n\t", stdout);
	Server->print(Server);
	fprintf(stdout, "\tTTL: %u\n", Ttl);


	/* Process the PEK message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_PEK, 1, bufr) )
		ERR(goto done);
	if ( !_verify_pek(msg, bufr) )
		ERR(goto done);
	fputs("\nPEK verified.\n", stdout);

	/* Process the signature message. */
	bufr->reset(bufr);
	if ( !msg->get_message(msg, TLV_SIGNATURE, 1, bufr) )
		ERR(goto done);

	fputs("\nSIGNATURE:\n", stdout);
	bufr->hprint(bufr);

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/* Main program starts here. */

extern int main(int argc, char *argv[])

{
	char *msg1_response = NULL,
	     *token = NULL;

	int opt,
	    retn;

	String response = NULL;

	PVEenclave pve = NULL;

	SGXmessage msg = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "1:t:")) != EOF )
		switch ( opt ) {
			case '1':
				msg1_response = optarg;
				break;

			case 't':
				token = optarg;
				break;
		}

	if ( token == NULL ) {
		usage("No initialization token specified.\n");
		return 1;
	}

	INIT(NAAAIM, SGXmessage, msg, ERR(goto done));


	/* Decode a message 1 response. */
	if ( msg1_response != NULL ) {
		INIT(HurdLib, String, response, ERR(goto done));
		if ( !response->add(response, msg1_response) )
			ERR(goto done);

		if ( !process_message1(msg, response) )
			ERR(goto done);
		retn = 0;
		goto done;
	}


	/* Load the provisioning enclave. */
	INIT(NAAAIM, PVEenclave, pve, ERR(goto done));
	if ( !pve->open(pve, token) )
		ERR(goto done);


	/* Get the endpoint. */
	if ( !pve->get_endpoint(pve) )
		ERR(goto done);


	/* Encode the message. */
	if ( !pve->generate_message1(pve, msg) )
		ERR(goto done);

	msg->dump(msg);
	retn = 0;


 done:
	WHACK(pve);
	WHACK(msg);
	WHACK(response);

	WHACK(Server);

	return retn;
}
