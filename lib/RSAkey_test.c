/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/ssl.h>

#include <HurdLib.h>
#include "Buffer.h"
#include "String.h"
#include "File.h"
#include "NAAAIM.h"
#include "RSAkey.h"


extern int main(int argc, char *argv[])

{
	char *pubkey,
	     *privkey;
	unsigned char *encrypted;

	unsigned int lp;

	Buffer payload = NULL;

	RSAkey rsakey = NULL;

	File certfile = NULL;

	const char *engine_cmds[] = {
		"SO_PATH", "/usr/local/musl/lib/engines/engine_pkcs11.so", \
		"ID", "pkcs11",					    	   \
		"LIST_ADD", "1",				    	   \
		"LOAD", NULL,					    	   \
		"MODULE_PATH", "/usr/local/lib/opensc-pkcs11.so",   	   \
		NULL, NULL
	};


	if ( argc == 1 ) {
		fputs("No arguements specified - usage:\n", stderr);
		fputs("\tRSAkey_test generate\n", stderr);
		fputs("\tRSAkey_test certifificate certfile\n", stderr);
		fputs("\tRSAkey_test pkcs11 keyid\n", stderr);
		fputs("\tRSAkey_test file public_key private_key\n", stderr);
		goto done;
	}

	if ( (payload = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer creation\n", stderr);
		return 1;
	}

	if ( (rsakey = NAAAIM_RSAkey_Init()) == NULL ) {
		fputs("Failed RSAkey init.\n", stderr);
		ERR(goto done);
	}

	if ( strcmp(argv[1], "generate") == 0 ) {
		if ( !rsakey->generate_key(rsakey, 2048) ) {
			fputs("Error generating 2048 bit key.\n", stderr);
			goto done;
		}

		fputs("Key components:\n", stdout);
		rsakey->print(rsakey);
		fputc('\n', stdout);

		fputs("Key in PEM form:\n", stdout);
		rsakey->get_private_key(rsakey, payload);
		payload->hprint(payload);

		goto done;
	}

	if ( strcmp(argv[1], "certificate") == 0 ) {
		if ( argc < 3 ) {
			fputs("No certificate file specified.\n", stderr);
			goto done;
		}

		INIT(HurdLib, File, certfile, ERR(goto done));
		if ( !certfile->open_ro(certfile, argv[2]) )
			ERR(goto done);
		if ( !certfile->slurp(certfile, payload) )
			ERR(goto done);

		if ( !rsakey->load_certificate(rsakey, payload) )
			ERR(goto done);

		fputs("Public key from certificate.\n\n", stdout);
		rsakey->print(rsakey);

		goto done;
	}

	if ( strcmp(argv[1], "pkcs11") == 0 ) {
		if ( !rsakey->init_engine(rsakey, engine_cmds) )
			ERR(goto done);
		if ( argc <= 2) {
			fputs("No token identifier specified.\n", stderr);
			ERR(goto done);
		}
		pubkey	= argv[2];
		privkey	= argv[2];
	} else if ( argc >= 3 ) {
		pubkey	= argv[2];
		privkey	= argv[3];
	}
	else {
		fputs("No public/private keys specifed.\n", stderr);
		ERR(goto done);
	}
	fprintf(stdout, "key type=%s, public=%s, private=%s\n", argv[1], \
		pubkey, privkey);


	/* Encrypt a test message. */
	if ( !rsakey->load_public_key(rsakey, pubkey, NULL) ) {
		fputs("Failed load of private key.\n", stderr);
		ERR(goto done);
	}
	rsakey->print(rsakey);

	if ( !payload->add(payload, (unsigned char *) "\xfe\xad\xbe\xaf", \
			   4) ) {
		fputs("Error setting payload\n", stderr);
		ERR(goto done);
	}
	fputs("encrypted buffer: ", stdout);
	payload->print(payload);

	if ( !rsakey->encrypt(rsakey, payload) ) {
		fputs("Error encrypting buffer\n", stderr);
		ERR(goto done);
	}

	fprintf(stdout, "encrypted (size = %d):\n", rsakey->size(rsakey));
	if ( (encrypted = payload->get(payload)) == NULL )
		ERR(goto done);

	for (lp= 1; lp <= rsakey->size(rsakey); ++lp) {
		fprintf(stdout, "%02x", *(encrypted + lp - 1));
		if ( ((lp % 32) == 0) )
			fputc('\n', stdout);
	}
	fputc('\n', stdout);

	WHACK(rsakey);


	/*
	 * Decrypt the payload to test.
	 *
	 * Unfortunately it appears that within the context of a single
	 * process PKCS11 based access to a key fails.  Until the root
	 * cause of this regression can be deduced only allow full
	 * test cycles for file based keys.
	 */
	if ( strcmp(argv[1], "pkcs11") == 0 ) {
		fputs("Decryption test not supported for PKCS11.\n", stdout);
		goto done;
	}

	if ( (rsakey = NAAAIM_RSAkey_Init()) == NULL ) {
		fputs("Failed RSAkey init.\n", stderr);
		ERR(goto done);
	}

	if ( !rsakey->load_private_key(rsakey, privkey, NULL) ) {
		fputs("Failed load of private key.\n", stderr);
		ERR(goto done);
	}
	rsakey->print(rsakey);

	if ( !rsakey->decrypt(rsakey, payload) ) {
		fputs("Failed decryption.\n", stderr);
		ERR(goto done);
	}

	fprintf(stderr, "Decrypted buffer - size=%zd\n", \
		payload->size(payload));
	payload->print(payload);


 done:
	WHACK(payload);
	WHACK(rsakey);
	WHACK(certfile);

	return 0;
}
