/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-naaaim-interface.h"

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "SHA256.h"
#include "RandomBuffer.h"
#include "Curve25519.h"
#include "SHA256_hmac.h"
#include "AES256_cbc.h"
#include "Base64.h"
#include "RSAkey.h"
#include "SEALkey.h"


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


void test_six()

{
	RandomBuffer rnd = NULL;

	Buffer b,
	       bufr = NULL;

	String ascii = NULL;

	Base64 base64 = NULL;


	/* Create a random buffer to encode. */
	INIT(NAAAIM, RandomBuffer, rnd, ERR(goto done));
	if ( !rnd->generate(rnd, 16) )
		ERR(goto done);

	b = rnd->get_Buffer(rnd);
	fputs("Random buffer:\n", stdout);
	b->print(b);


	/* Encode the random buffer. */
	INIT(HurdLib, String, ascii, ERR(goto done));
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !base64->encode(base64, b, ascii) )
		ERR(goto done);
	fputs("\nEncoded random buffer:\n", stdout);
	ascii->print(ascii);


	/* Decode the buffer. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !base64->decode(base64, ascii, bufr) )
		ERR(goto done);
	fputs("\nDecoded random buffer:\n", stdout);
	bufr->print(bufr);


 done:
	WHACK(rnd);
	WHACK(bufr);
	WHACK(ascii);
	WHACK(base64);

	return;
}


void test_seven()

{
	RSAkey key = NULL;

	Buffer public  = NULL,
	       private = NULL,
	       payload = NULL;

	const static uint8_t encdata[32] = {			\
		0x70, 0x53, 0x4d, 0x06, 0x62, 0xe1, 0x4b, 0x8e, \
		0xef, 0xc7, 0x9e, 0x02, 0x3d, 0x95, 0xa1, 0x7d, \
		0xcf, 0x79, 0x2b, 0xbc, 0x2d, 0xb6, 0xd8, 0x4d, \
		0x31, 0x88, 0xfb, 0x04, 0xb6, 0xa9, 0x1d, 0xf5  \
	};


	INIT(HurdLib, Buffer, public, ERR(goto done));
	INIT(HurdLib, Buffer, private, ERR(goto done));

	fputs("Generating 2048 bit RSA key.\n", stdout);
	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	if ( !key->generate_key(key, 2048) )
		ERR(goto done);

	fputs("\nKey components:\n", stdout);
	key->print(key);

	fputs("\nPrivate key in PEM form:\n", stdout);
	key->get_private_key(key, private);
	private->hprint(private);

	fputs("\nPublic key in PEM form:\n", stdout);
	key->get_public_key(key, public);
	public->hprint(public);

	WHACK(key);
	INIT(NAAAIM, RSAkey, key, ERR(goto done));
	INIT(HurdLib, Buffer, payload, ERR(goto done));

	if ( !key->load_public(key, public) )
		ERR(goto done);

	if ( !payload->add(payload, encdata, sizeof(encdata)) )
		ERR(goto done);
	fputs("\nPayload to be encrypted:\n", stdout);
	payload->hprint(payload);

	if ( !key->encrypt(key, payload) )
		ERR(goto done);
	fputs("\nPayload encrypted with public key:\n", stdout);
	payload->hprint(payload);

	WHACK(key);
	INIT(NAAAIM, RSAkey, key, ERR(goto done));

	if ( !key->load_private(key, private) )
		ERR(goto done);
	if ( !key->decrypt(key, payload) )
		ERR(goto done);

	fputs("\nPayload decrypted with private key:\n", stdout);
	payload->hprint(payload);


	if ( !key->encrypt(key, payload) )
		ERR(goto done);
	fputs("\nPayload encrypted with private key:\n", stdout);
	payload->hprint(payload);

	WHACK(key);
	INIT(NAAAIM, RSAkey, key, ERR(goto done));

	if ( !key->load_public(key, public) )
		ERR(goto done);
	if ( !key->decrypt(key, payload) )
		ERR(goto done);

	fputs("\nPayload decrypted with public key:\n", stdout);
	payload->hprint(payload);


 done:
	WHACK(key);

	WHACK(public);
	WHACK(private);
	WHACK(payload);

	return;
}


void test_eight()
{
	static unsigned char id[32] = {
		0x37, 0x34, 0xd3, 0xa8, 0x52, 0xa0, 0x95, 0x87, \
		0x50, 0xe5, 0x8a, 0xb3, 0xb0, 0xa6, 0x38, 0x5e, \
		0xc9, 0xca, 0x6c, 0x64, 0x40, 0xc4, 0x2c, 0xf8, \
		0x47, 0x61, 0x51, 0x4e, 0x1c, 0x5e, 0xd7, 0x56  \
	};

	Buffer kreq  = NULL,
	       iv    = NULL,
	       key   = NULL;

	SEALkey sealkey = NULL;


	INIT(HurdLib, Buffer, iv, ERR(goto done));
	INIT(HurdLib, Buffer, key, ERR(goto done));
	INIT(NAAAIM, SEALkey, sealkey, ERR(goto done));

	if ( !sealkey->generate_mrsigner(sealkey) )
		ERR(goto done);
	sealkey->print(sealkey);

	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);
	fputs("Unshrouded key:\n", stdout);
	key->hprint(key);


	/* Retrieve the key request components. */
	INIT(HurdLib, Buffer, kreq,  ERR(goto done));

	if ( !sealkey->get_request(sealkey, kreq) )
		ERR(goto done);
	fputs("\nRe-generating key on DER encoded key request:\n", stdout);
	kreq->hprint(kreq);


	/* Test re-generation of the key. */
	sealkey->reset(sealkey);
	if ( !sealkey->set_request(sealkey, kreq) )
		ERR(goto done);

	if ( !sealkey->generate_mrsigner(sealkey) )
		ERR(goto done);

	fputs("\n", stdout);
	sealkey->print(sealkey);

	iv->reset(iv);
	key->reset(key);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);

	fputs("Unshrouded key:\n", stdout);
	key->hprint(key);


	/* Test a re-generatable key. */
	key->reset(key);
	sealkey->reset(sealkey);

	if ( !key->add(key, id, sizeof(id)) )
		ERR(goto done);
	if ( !sealkey->generate_static_key(sealkey, 1 /* SIGNER KEY*/, key) )
		ERR(goto done);

	iv->reset(iv);
	key->reset(key);
	if ( !sealkey->get_iv_key(sealkey, iv, key) )
		ERR(goto done);

	fputs("\nStatic key:\n", stdout);
	key->hprint(key);


 done:
	WHACK(kreq);
	WHACK(iv);
	WHACK(key);
	WHACK(sealkey);

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
		case 6:
			test_six();
			break;
		case 7:
			test_seven();
			break;
		case 8:
			test_eight();
			break;

		default:
			fputs("Invalid test.\n", stderr);
			break;
	}
	fprintf(stdout, "End test: %d\n", test);


	return;
}
