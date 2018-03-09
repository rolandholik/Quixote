#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include <HurdLib.h>
#include <Buffer.h>

#include "SHA256.h"
#include "RandomBuffer.h"
#include "Curve25519.h"
#include "SHA256_hmac.h"
#include "AES256_cbc.h"


void test_one()

{
	uint8_t lp;

	size_t len;

	static const unsigned char *input = \
		(const unsigned char *) "abc";

	Buffer bufr = NULL;

	Sha256 sha256 = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	len = strlen((char *) input);
	fputs("Input:\n", stdout);
	for (lp= 0; lp < len; ++lp)
		fprintf(stdout, "%02x", input[lp]);
	fputs("\n\n", stdout);

	if ( !bufr->add(bufr, input, len) )
		ERR(goto done);
	fputs("Buffer:\n", stdout);
	bufr->print(bufr);
	fputc('\n', stdout);
	bufr->hprint(bufr);

	fputc('\n', stdout);
	fputs("SHA256:\n", stdout);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	sha256->print(sha256);


 done:
	WHACK(bufr);
	WHACK(sha256)

	return;
}


void test_two()

{
	Buffer b;

	RandomBuffer random = NULL;


	INIT(NAAAIM, RandomBuffer, random, ERR(goto done));
	b = random->get_Buffer(random);

	fputs("8 bytes:\n", stdout);
	if ( !random->generate(random, sizeof(uint64_t)) )
		ERR(goto done);
	b->print(b);

	fputs("18 bytes:\n", stdout);
	if ( !random->generate(random, 18) )
		ERR(goto done);
	b->print(b);

	fputs("32 bytes:\n", stdout);
	if ( !random->generate(random, 32) )
		ERR(goto done);
	b->print(b);


 done:
	WHACK(random);

	return;
}


void test_three(void)

{
	Curve25519 ours	  = NULL,
		   theirs = NULL;

	Buffer b,
	       shared = NULL;


	/* Create the public/private keypairs. */
	INIT(NAAAIM, Curve25519, ours, goto done);
	if ( !ours->generate(ours) )
		goto done;
	fputs("Our public:\n", stdout);
	b = ours->get_public(ours);
	b->print(b);

	INIT(NAAAIM, Curve25519, theirs, goto done);
	if ( !theirs->generate(theirs) )
		goto done;
	fputs("\nTheir public:\n", stdout);
	b = theirs->get_public(theirs);
	b->print(b);


	/* Generate and confirm the shared secrets. */
	INIT(HurdLib, Buffer, shared, goto done);
	if ( !ours->compute(ours, theirs->get_public(theirs), shared) )
		goto done;
	fputs("\nOur key:\n", stdout);
	shared->print(shared);

	shared->reset(shared);
	if ( !theirs->compute(theirs, ours->get_public(ours), shared) )
		goto done;
	fputs("\nTheir key:\n", stdout);
	shared->print(shared);


 done:
	WHACK(ours);
	WHACK(theirs);
	WHACK(shared);

	return;
}


void test_four()

{
	static const unsigned char *input = \
		(const unsigned char *) "Hi There";

	static const char *hkey = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

	Buffer b,
	       key  = NULL,
	       bufr = NULL;

	SHA256_hmac hmac = NULL;


	/* Setup input buffer. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, input, strlen((char *) input)) )
		ERR(goto done);
	fputs("Input:\n", stdout);
	bufr->hprint(bufr);


	/* Setup buffer with key. */
	INIT(HurdLib, Buffer, key,  ERR(goto done));
	if ( !key->add_hexstring(key, hkey) )
		ERR(goto done);
	fputs("\nKey:\n", stdout);
	key->print(key);


	/* Compute the message authentication code. */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL )
		ERR(goto done);
	hmac->add_Buffer(hmac, bufr);
	if ( !hmac->compute(hmac) )
		ERR(goto done);

	fputc('\n', stdout);
	fputs("SHA256_HMAC:\n", stdout);
	b = hmac->get_Buffer(hmac);
	b->print(b);

	fputs("\nExpected:\n", stdout);
	fputs("198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7	\n", stdout);


 done:
	WHACK(bufr);
	WHACK(hmac)

	return;
}


void test_five()

{
	static const unsigned char *input = \
		(const unsigned char *) "The Secret";

	static const char *iv_val  = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
			  *key_val = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";

	Buffer iv   = NULL,
	       key  = NULL,
	       bufr = NULL;

	AES256_cbc encrypt = NULL,
		   decrypt = NULL;


	/* Setup input buffer. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, input, strlen((char *) input)) )
		ERR(goto done);
	fputs("Input:\n", stdout);
	bufr->hprint(bufr);


	/* Setup IV and key. */
	INIT(HurdLib, Buffer, iv,  ERR(goto done));
	if ( !iv->add_hexstring(iv, iv_val) )
		ERR(goto done);
	fputs("\nIV:\n", stdout);
	iv->print(iv);

	INIT(HurdLib, Buffer, key, ERR(goto done));
	if ( !key->add_hexstring(key, key_val) )
		ERR(goto done);
	fputs("KEY:\n", stdout);
	key->print(key);


	/* Encrypt the string. */
	if ( (encrypt = NAAAIM_AES256_cbc_Init_encrypt(key, iv)) == NULL )
		ERR(goto done);
	if ( !encrypt->encrypt(encrypt, bufr) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, encrypt->get_Buffer(encrypt)) )
		ERR(goto done);

	fputc('\n', stdout);
	fputs("Encrypted payload:\n", stdout);
	bufr->print(bufr);


	/* Decrypt the string to confirm invertibility. */
	if ( (decrypt = NAAAIM_AES256_cbc_Init_decrypt(key, iv)) == NULL )
		ERR(goto done);
	if ( !decrypt->decrypt(decrypt, encrypt->get_Buffer(encrypt)) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add_Buffer(bufr, decrypt->get_Buffer(decrypt)) )
		ERR(goto done);

	fputc('\n', stdout);
	fputs("Decrypted payload:\n", stdout);
	bufr->hprint(bufr);


 done:
	WHACK(bufr);
	WHACK(iv);
	WHACK(key);
	WHACK(encrypt);
	WHACK(decrypt);

	return;
}


void test_naaaim(unsigned int test)

{

	fprintf(stdout, "Test number: %u\n", test);
	switch ( test ) {
		case 1:
			test_one();
			break;
		case 2:
			test_two();
			break;
		case 3:
			test_three();
			break;
		case 4:
			test_four();
			break;
		case 5:
			test_five();
			break;

		default:
			fputs("Invalid test.\n", stderr);
			break;
	}
	fprintf(stdout, "End test: %d\n", test);


	return;
}
