#include <stdio.h>
#include <stdbool.h>

#include "Buffer.h"
#include "NAAAIM.h"
#include "RSAkey.h"


extern int main(int argc, char *argv[])

{
	auto unsigned char *encrypted;

	auto unsigned int lp;

	auto Buffer payload;

	auto RSAkey enckey,
		    deckey;


	if ( (payload = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer creation\n", stderr);
		return 1;
	}

	if ( (enckey = NAAAIM_RSAkey_Init()) == NULL ) {
		fputs("Failed RSAkey init.\n", stderr);
		payload->whack(payload);
		return 1;
	}

	if ( !enckey->load_public_key(enckey, "org-public.pem") ) {
		fputs("Failed load of private key.\n", stderr);
		payload->whack(payload);
		enckey->whack(enckey);
		return 0;
	}
	enckey->print(enckey);

	if ( !payload->add(payload, "\xfe\xad\xbe\xaf", 4) ) {
		fputs("Error setting payload\n", stderr);
		goto done;
	}
	fputs("encrypted buffer: ", stdout);
	payload->print(payload);

	if ( !enckey->encrypt(enckey, payload) ) {
		fputs("Error encrypting buffer\n", stderr);
		goto done;
	}

	fprintf(stdout, "encrypted (size = %d):\n", enckey->size(enckey));
	if ( (encrypted = payload->get(payload)) == NULL )
		goto done;

	for (lp= 1; lp <= enckey->size(enckey); ++lp) {
		fprintf(stdout, "%02x", *(encrypted + lp - 1));
		if ( ((lp % 32) == 0) )
			fputc('\n', stdout);
	}
	fputc('\n', stdout);

	enckey->whack(enckey);


	/* Decrypt the payload to test. */
	if ( (deckey = NAAAIM_RSAkey_Init()) == NULL ) {
		fputs("Failed RSAkey init.\n", stderr);
		payload->whack(payload);
		return 1;
	}

	if ( !deckey->load_private_key(enckey, "org-private.pem") ) {
		fputs("Failed load of public key.\n", stderr);
		payload->whack(payload);
		deckey->whack(deckey);
		return 0;
	}
	deckey->print(deckey);

	if ( !deckey->decrypt(deckey, payload) ) {
		fputs("Failed decryption.\n", stderr);
		payload->whack(payload);
		deckey->whack(deckey);
		return 0;
	}

	fputs("Decrypted buffer:\n", stdout);
	payload->print(payload);

	
 done:
	payload->whack(payload);
	deckey->whack(deckey);

	return 0;
}
