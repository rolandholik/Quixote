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
#include "DBduct.h"
#include "String.h"


/* Variables static to this module. */
static String Credkey = NULL;


/**
 * Private function.
 *
 * This function implements the creation of an organizational identity.
 *
 * \param orgid		The organization management object in which the
 *			identity is to be created.
 *
 * \param config	The object which provides configuration
 *			information for object creation.
 *
 * \param dbname	The name of the database which contains identity
 *			keying information.  A null value indicates the
 *			database should not be queried.
 *
 * \param credential	A pointer to a null-terminated character buffer
 *			containing the credential to be used for
 *			generating the organizational identity.
 *
 * \return		If creation of the organizational identity is
 *			successful the object to manage the identity is
 *			returned to the caller.  A NULL value indicates
 *			failure.
 */

static OrgID generate_organization_id(OrgID orgid, const Config const config, \
				      const char * const dbname, 	      \
				      char *credential)

{
	auto _Bool retn = false;

	auto char *anonymizer = NULL,
		  query[256];

	auto DBduct db = NULL;


	/*
	 * Initialize the identity management object and determine the
	 * credential to be used.
	 */
	if ( (orgid = NAAAIM_OrgID_Init()) == NULL )
		goto done;

	if ( credential == NULL ) {
		if ( (credential = config->get(config, "credential")) \
		     == NULL )
			goto done;
	}


	/*
	 * Retrieve organizational keying information from a database if
	 * one has been defined.
	 */
	if ( dbname != NULL ) {
		if ( (db = NAAAIM_DBduct_Init()) == NULL )
			goto done;
		if ( !db->init_connection(db, dbname) )
			goto done;

		snprintf(query, sizeof(query), "select orgkey,credkey from " \
			 "npi where number = '%s'", credential);
		if ( db->query(db, query) != 1 )
			goto done;

		anonymizer = db->get_element(db, 0, 0);

		Credkey = HurdLib_String_Init_cstr(db->get_element(db, 0, 1));
		if ( Credkey == NULL )
			goto done;
	}

	if ( (anonymizer == NULL) ) {
		if ( (anonymizer = config->get(config, "anonymizer")) == \
		     NULL )
			goto done;
	}

	orgid->create(orgid, anonymizer, credential);

	retn = true;


 done:
	if ( db != NULL )
		db->whack(db);
	if ( retn == false ) {
		orgid->whack(orgid);
		orgid = NULL;
	}

	return orgid;
}


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

	auto Sha256 sha256 = NULL;

	auto SHA256_hmac hmac = NULL;


	/* Get the RSA keyfile. */
	if ( (rsakey = parser->get(parser, "rsakey")) == NULL ) {
		fputs("No RSA key specified.\n", stderr);
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

	sha256->reset(sha256);
	sha256->add(sha256, random->get_Buffer(random));
	sha256->compute(sha256);
	fputs("-----BEGIN TOKEN KEY-----\n", stdout);
	sha256->print(sha256);
	fputs("-----END TOKEN KEY-----\n", stdout);

	fputs("-----END IDENTITY TOKEN-----\n", stdout);

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
	auto _Bool domain   = false,
		   identity = false,
		   token    = false;

	auto char *ssnid,
		  *err = NULL,
		  *credential = NULL,
		  *anonymizer = NULL,
		  *config = NULL,
		  *organization = NULL,
		  *ssn = NULL,
		  *dbname = NULL;

	auto int retn;

	auto _Bool permute = false;

	auto Buffer bufr = NULL;

	auto Config parser = NULL;

	auto OrgID orgid = NULL;

	auto PatientID ptid = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "DITa:c:d:f:pi:o:")) != EOF )
		switch ( retn ) {
			case 'D':
				domain = true;
				break;
			case 'I':
				identity = true;
				break;
			case 'T':
				token = true;
				break;
			case 'a':
				anonymizer = optarg;
				break;
			case 'c':
				credential = optarg;
				break;
			case 'd':
				dbname = optarg;
				break;
			case 'f':
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

#if 0
	if ( (organization == NULL) || (ssn == NULL) ) {
		err = "Inputs not specified.";
		goto done;
	}
#endif

	if ( config == NULL )
		config = "./orgid.txt";

	retn = 1;


	/* Parse the organizational identity file. */
	if ( (parser = HurdLib_Config_Init()) == NULL ) {
		err = "Failed Config init.";
		goto done;
	}

	if ( !parser->parse(parser, config) ) {
		err = "Failed parsing of identity keys.";
		goto done;
	}


	/* Generate the organizational identity. */
	if ( dbname == NULL )
		parser->set_section(parser, organization);

	if ( (orgid = generate_organization_id(orgid, parser, dbname, \
					       credential)) == NULL ) {
		err = "Failure in organizational identity generation.";
		goto done;
	}


	/* Create the user identity. */
	if ( (ptid = NAAAIM_PatientID_Init()) == NULL ) {
		err = "Error creating patient identity object.";
		goto done;
	}

	if ( Credkey != NULL )
		ssnid = Credkey->get(Credkey);
	else if ( (ssnid = parser->get(parser, "ssnid")) == NULL ) {
		err = "SSN identifier not set";
		goto done;
	}

	ptid->create(ptid, orgid, ssnid, ssn);


	/* Output user identities if token generation is not requested. */
	if ( !domain && !identity && !token ) {
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

	if ( identity )
		ptid->print(ptid);

	if ( domain )
		orgid->print(orgid);

	if ( token ) {
		generate_token(parser, orgid, ptid);
	}



 done:
	if ( err != NULL )
		fprintf(stderr, "%s\n", err);

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( parser != NULL )
		parser->whack(parser);
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( ptid != NULL )
		ptid->whack(ptid);

	if ( Credkey != NULL )
		Credkey->whack(Credkey);

	return retn;
}
