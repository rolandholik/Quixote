#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "NAAAIM.h"
#include "Config.h"
#include "Buffer.h"
#include "SHA256.h"
#include "SHA256_hmac.h"
#include "OrgID.h"
#include "PatientID.h"
#include "RandomBuffer.h"
#include "RSAkey.h"


static _Bool permute_identity(const Config const parser,	   \
			      const Buffer const input_identity, \
			      const Buffer const output_identity)

{
	auto const char *base,
			*key;

	auto _Bool retn = false;

	auto Buffer base_bufr = NULL,
		    key_bufr  = NULL;

	auto SHA256_hmac permute = NULL;


	/* Get the export base and key. */
	if ( (base = parser->get(parser, "base")) == NULL ) {
		fputs("Cannot set export base.\n", stderr);
		goto done;
	}
	if ( (key = parser->get(parser, "key")) == NULL ) {
		fputs("Cannot set export key.\n", stderr);
		goto done;
	}


	/* Initialize HMAC object with key. */
	if ( (key_bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot initialize key buffer object.\n", stderr);
		goto done;
	}
	if ( !key_bufr->add_hexstring(key_bufr, key) ) {
		fputs("Cannot load key buffer.\n", stderr);
		goto done;
	}
	if ( (permute = NAAAIM_SHA256_hmac_Init(key_bufr)) == NULL ) {
		fputs("Cannot initialize HMAC object.\n", stderr);
		goto done;
	}


	/* Add export base. */
	if ( (base_bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot initialize export base buffer object.\n", \
		      stderr);
		goto done;
	}
	if ( !base_bufr->add_hexstring(base_bufr, base) ) {
		fputs("Cannot load export base.\n", stderr);
		goto done;
	}

	/* Add input identity and compute exported identity. */
	if ( !base_bufr->add_Buffer(base_bufr, input_identity) ) {
		fputs("Cannot add input identity.\n", stderr);
		goto done;
	}
	if ( !permute->add_Buffer(permute, base_bufr) ) {
		fputs("Cannot add export vector.\n", stderr);
		goto done;
	}
	if ( !permute->compute(permute) ) {
		fputs("Cannot generate export identity.\n", stderr);
		goto done;
	}

	/* Load exported identity. */
	if ( !output_identity->add_Buffer(output_identity, \
					 permute->get_Buffer(permute)) ) {
		fputs("Cannot load output identity.\n", stderr);
		goto done;
	}

	retn = true;
	

 done:
	if ( key_bufr != NULL )
		key_bufr->whack(key_bufr);
	if ( base_bufr != NULL )
		base_bufr->whack(base_bufr);
	if ( permute != NULL )
		permute->whack(permute);

	return retn;
}


static _Bool output_ptid(const PatientID const ptid,	  \
			 const RandomBuffer const random, \
			 const char * const keyfile)

{
	auto _Bool retn = false;

	auto unsigned char *encrypted;

	auto unsigned int lp;

	auto Buffer payload = NULL;

	auto RSAkey key = NULL;


	/* Setup the payload. */
	if ( (payload = HurdLib_Buffer_Init()) == NULL )
		goto done;
	payload->add_Buffer(payload, ptid->get_Buffer(ptid));
	payload->add_Buffer(payload, random->get_Buffer(random));


	/* Setup and encrypt payload with the private key. */
	if ( (key = NAAAIM_RSAkey_Init()) == NULL )
		goto done;
	if ( !key->load_private_key(key, keyfile) )
		goto done;
	if ( !key->encrypt(key, payload) )
		goto done;

	/* Output the private key in block format. */
	encrypted = payload->get(payload);
	fputs("-----BEGIN PATIENT IDENTITY-----\n", stdout);
	for (lp= 1; lp <= key->size(key); ++lp) {
		fprintf(stdout, "%02x", *(encrypted + lp - 1));
		if ( ((lp % 32) == 0) )
			fputc('\n', stdout);
	}
	fputs("-----END PATIENT IDENTITY-----\n", stdout);
	retn = true;


 done:
	if ( payload != NULL )
		payload->whack(payload);
	if ( key != NULL )
		key->whack(key);

	return retn;
}

static _Bool generate_token(const Config const parser,	\
			    const OrgID const orgid,	\
			    const PatientID const ptid)

{
	auto _Bool retn = false;

	auto char *rsakey;

	auto Buffer rb,
		    bf = NULL;

	auto RandomBuffer random = NULL;

	auto SHA256 sha256 = NULL;

	auto SHA256_hmac hmac = NULL;


	if ( (rsakey = parser->get(parser, "rsakey")) == NULL ) {
		fputs("Failed RSA key lookup.\n", stderr);
		goto done;
	}

	/* Generate the random nonce for an identity. */
	if ( (random = NAAAIM_RandomBuffer_Init()) == NULL ) {
		fputs("Cannot create random number generator.", stderr);
		goto done;
	}
	if ( !random->generate(random, 512 / 8) ) {
		fputs("Cannot generate id nonce.\n", stderr);
		goto done;
	}

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Cannot create hashing object.\n", stderr);
		goto done;
	}


	/*
	 * Generate the user specific organizational hash key from the
	 * first 256 bits of the random nonce.
	 */
	if ( (bf = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot create buffer object.\n", stderr);
		goto done;
	}
	rb = random->get_Buffer(random);
	bf->add(bf, rb->get(rb), 256 / 8);
	sha256->add(sha256, bf);
	sha256->compute(sha256);


	/*
	 * Hash the organizational identity with the user key generated
	 * in the previous section.
	 */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(sha256->get_Buffer(sha256))) \
	     == NULL ) {
		fputs("Cannot create HMAC object.\n", stderr);
		goto done;
	}
	hmac->add_Buffer(hmac, orgid->get_Buffer(orgid));
	hmac->compute(hmac);


	/* Output the identity token. */
	fputs("-----BEGIN IDENTITY TOKEN-----\n", stdout);

	fputs("-----BEGIN ORGANIZATION IDENTITY-----\n", stdout);
	sha256->print(sha256);
	hmac->print(hmac);
	fputs("-----END ORGANIZATION IDENTITY-----\n", stdout);

	if ( !output_ptid(ptid, random, rsakey) )
	      fputs("Error outputing id token.\n", stderr);
	fputs("-----END IDENTITY TOKEN-----\n", stdout);

	sha256->reset(sha256);
	sha256->add(sha256, random->get_Buffer(random));
	sha256->compute(sha256);
	fputs("\nOrg token id: ", stdout);
	sha256->print(sha256);
	retn = true;


 done:
	if ( bf != NULL )
		bf->whack(bf);
	if ( random != NULL )
		random->whack(random);
	if ( sha256 != NULL )
		sha256->whack(sha256);
	if ( hmac != NULL )
		hmac->whack(hmac);

	return retn;
}


extern int main(int argc, char *argv[])

{
	auto _Bool token = false;

	auto char *ssnid,
		  *anonymizer,
		  *credential,
		  *config = NULL,
		  *organization = NULL,
		  *ssn = NULL;

	auto int retn;

	auto _Bool permute = false;

	auto Buffer bufr = NULL;

	auto Config parser = NULL;

	auto OrgID orgid = NULL;

	auto PatientID ptid = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "Tpc:i:o:")) != EOF )
		switch ( retn ) {
			case 'T':
				token = true;
				break;
			case 'c':
				config = optarg;
				break;
			case 'i':
				ssn = optarg;
				break;
			case 'o':
				organization = optarg;
				break;
			case 'p':
				permute = true;
				break;
		}

	if ( (organization == NULL) || (ssn == NULL) ) {
		fputs("Inputs not specified.\n", stderr);
		return 1;
	}

	if ( config == NULL )
		config = "./orgid.txt";

	retn = 1;


	/* Parse the organizational identity file. */
	if ( (parser = HurdLib_Config_Init()) == NULL ) {
		fputs("Failed Config init.\n", stderr);
		goto done;
	}

	if ( !parser->parse(parser, config) ) {
		fputs("Failed parsing of identity keys\n", stderr);
		goto done;
	}


	/* Generate the organizational identity. */
	if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
		fputs("Failed organization object init.\n", stderr);
		goto done;
	}

	if ( !parser->set_section(parser, organization) ) {
		fputs("Organization section not found.\n", stderr);
		goto done;
	}

	if ( (anonymizer = parser->get(parser, "anonymizer")) == NULL ) {
		fputs("Anonymizer not available\n", stderr);
		goto done;
	}

	if ( (credential = parser->get(parser, "credential")) == NULL ) {
		fputs("Organizational credential not available.\n", stderr);
		goto done;
	}

	orgid->create(orgid, anonymizer, credential);


	/* Create the user identity. */
	if ( (ptid = NAAAIM_PatientID_Init()) == NULL ) {
		fputs("Error creating patient identity object.\n", stderr);
		goto done;
	}

	if ( (ssnid = parser->get(parser, "ssnid")) == NULL ) {
		fputs("SSN identifier not set\n", stderr);
		goto done;
	}

	ptid->create(ptid, orgid, ssnid, ssn);


	/* Output user identities if token generation is not requested. */
	if ( !token ) {
		fputs("Domain:  ", stdout);
		if ( permute ) {
			bufr->reset(bufr);
			permute_identity(parser, orgid->get_Buffer(orgid), \
					 bufr);
			bufr->print(bufr);
		}
		else
			orgid->print(orgid);

		fputs("Element: ", stdout);
		if ( permute ) {
			bufr->reset(bufr);
			permute_identity(parser, orgid->get_Buffer(orgid), \
					 bufr);
			bufr->print(bufr);
		}
		else
			ptid->print(ptid);
	}
	else
		generate_token(parser, orgid, ptid);


 done:
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( parser != NULL )
		parser->whack(parser);
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( ptid != NULL )
		ptid->whack(ptid);

	return retn;
}
