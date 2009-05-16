#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "Config.h"
#include "Buffer.h"
#include "SHA256.h"
#include "SHA256_hmac.h"


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


extern int main(int argc, char *argv[])

{
	auto char *value,
		  *organization = NULL,
		  *ssn = NULL;

	auto int retn;

	auto _Bool debug   = false,
		   permute = false;

	auto Buffer bufr   = NULL,
		    hashin = NULL;

	auto Config parser = NULL;

	auto SHA256 orgid = NULL,
		    ssnid = NULL;


	/* Get the organizational name and SSN. */
	while ( (retn = getopt(argc, argv, "pi:o:")) != EOF )
		switch ( retn ) {
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
	retn = 1;


	/* Parse the organizational identity file. */
	if ( (parser = HurdLib_Config_Init()) == NULL ) {
		fputs("Failed Config init.\n", stderr);
		goto done;
	}

	if ( !parser->parse(parser, "./orgid.txt") ) {
		fputs("Failed parsing of identity keys\n", stderr);
		goto done;
	}


	/* Generate the organizational identity. */
	if ( (orgid = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Failed SHA256 init.\n", stderr);
		goto done;
	}

	if ( !parser->set_section(parser, organization) ) {
		fputs("Organization section not found.\n", stderr);
		goto done;
	}

	if ( (value = parser->get(parser, "anonymizer")) == NULL ) {
		fputs("Anonymizer not set\n", stderr);
		goto done;
	}

	if ( (hashin = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot initialize hash buffer.\n", stderr);
		goto done;
	}

	if ( !hashin->add_hexstring(hashin, value) ) {
		fputs("Cannot add anonymizer.\n", stderr);
		goto done;
	}


	/* Convert organization credential to a hash value. */
	if ( (bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Cannot create buffer object.\n", stderr);
		goto done;
	}
	if ( (value = parser->get(parser, "credential")) == NULL ) {
		fputs("Organizational credential not set.\n", stderr);
		goto done;
	}
	if ( !bufr->add(bufr, value, strlen(value)) ) {
		fputs("Cannot add organizational credential.\n", stderr);
		goto done;
	}

	if ( !orgid->add(orgid, bufr) ) {
		fputs("Cannot add organizational credential to hash.\n", \
		      stderr);	
		goto done;
	}
	if ( !orgid->compute(orgid) ) {
		fputs("Cannot generate credential hash.\n", stderr);
		goto done;
	}
	if ( !hashin->add_Buffer(hashin, orgid->get_Buffer(orgid)) ) {
		fputs("Cannot add credential hash.\n", stderr);
		goto done;
	}


	/* Compute and permute the organizational identity hash. */
	orgid->reset(orgid);
	if ( !orgid->add(orgid, hashin) ) {
		fputs("Cannot add input for organizational hash.\n", stderr);
		goto done;
	}
	orgid->compute(orgid);

	fputs("Domain:  ", stdout);
	if ( permute ) {
		bufr->reset(bufr);
		permute_identity(parser, orgid->get_Buffer(orgid), bufr);
		bufr->print(bufr);
	}
	else
		orgid->print(orgid);


	/* Build the user credential hash. */
	if ( (ssnid = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Failed SHA256 init.\n", stderr);
		goto done;
	}
	hashin->reset(hashin);
	bufr->reset(bufr);

	if ( (value = parser->get(parser, "ssnid")) == NULL ) {
		fputs("SSN identifier not set\n", stderr);
		goto done;
	}

	if ( !hashin->add_hexstring(hashin, value) ) {
		fputs("Cannot add anonymizer.\n", stderr);
		goto done;
	}

	/* Convert SSN credential to a hash value. */
	if ( !bufr->add(bufr, ssn, strlen(ssn)) ) {
		fputs("Cannot add organizational credential.\n", stderr);
		goto done;
	}
	if ( !ssnid->add(ssnid, bufr) ) {
		fputs("Cannot add ssn credentail to hash.\n", \
		      stderr);	
		goto done;
	}
	if ( !ssnid->compute(ssnid) ) {
		fputs("Cannot generate SSN credential hash.\n", stderr);
		goto done;
	}

	if ( debug ) {
		fputs("ssn:\t", stderr);
		ssnid->print(ssnid);
	}
	if ( !hashin->add_Buffer(hashin, ssnid->get_Buffer(ssnid)) ) {
		fputs("Cannot add credential hash.\n", stderr);
		goto done;
	}
	
	/* Compute the user identity hash. */
	ssnid->reset(ssnid);
	if ( !ssnid->add(ssnid, hashin) ) {
		fputs("Cannot add input for organizational hash.\n", stderr);
		goto done;
	}
	ssnid->compute(ssnid);
	if ( debug ) {
		fputs("SSN id:  ", stdout);
		ssnid->print(ssnid);
	}


	/* Compute the user organizational identity. */
	hashin->reset(hashin);
	
	if ( !hashin->add_Buffer(hashin, orgid->get_Buffer(orgid)) ) {
		fputs("Cannot add organizational identity.\n", stderr);
		goto done;
	}
	if ( !hashin->add_Buffer(hashin, ssnid->get_Buffer(ssnid)) ) {
		fputs("Cannot add user identity.\n", stderr);
		goto done;
	}

	orgid->reset(orgid);
	if ( !orgid->add(orgid, hashin) ) {
		fputs("Cannot generate organizational identity.\n", stderr);
		goto done;
	}
	orgid->compute(orgid);

	fputs("Element: ", stdout);
	if ( permute ) {
		bufr->reset(bufr);
		permute_identity(parser, orgid->get_Buffer(orgid), bufr);
		bufr->print(bufr);
	}
	else
		orgid->print(orgid);

	
 done:
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( hashin != NULL )
		hashin->whack(hashin);
	if ( parser != NULL )
		parser->whack(parser);
	if ( orgid != NULL )
		orgid->whack(orgid);
	if ( ssnid != NULL )
		ssnid->whack(ssnid);

	return retn;
}
