#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include <String.h>
#include <Buffer.h>
#include <File.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"


extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *token	   = NULL,
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = NULL;

	int opt,
	    retn = 1;

	struct SGX_einittoken *einit;

	struct SGX_targetinfo target;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "de:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'e':
				enclave_name = optarg;
				break;
			case 'n':
				sgx_device = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}

	if ( enclave_name == NULL ) {
		fputs("No enclave name specifed.\n", stderr);
		goto done;
	}


	/* Load the launch token. */
	if ( token == NULL ) {
		fputs("No token specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, sgx_device, enclave_name, debug) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);
	fputs("Enclave loaded.\n", stdout);


	/* Test generation of a target information structure. */
	if ( !enclave->get_targetinfo(enclave, &target) )
		ERR(goto done);

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &target.mrenclave, \
		  sizeof(target.mrenclave));

	fputs("\nTarget information:\n", stdout);
	fputs("Measurement:\n", stdout);
	bufr->print(bufr);

	fputs("\nAttributes:\n", stdout);
	fprintf(stdout, "\tFlags: 0x%0lx\n", target.attributes.flags);
	fprintf(stdout, "\tXFRM: 0x%0lx\n", target.attributes.xfrm);

	fprintf(stdout, "\nMiscselect: 0x%0x\n", target.miscselect);
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(token_file);
	WHACK(enclave);

	return retn;

}
