/**
 * Utility to dump sgx metadata from an enclave.
 */


#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <Origin.h>
#include <HurdLib.h>

#include <NAAAIM.h>

#include "SGX.h"
#include "SGXsigstruct.h"


int main(int argc, char *argv[])

{
	int retn = 1;

	SGXsigstruct sigstruct = NULL;


	if (argc != 3) {
		fprintf(stderr, "%s: Specify signature file and " \
			"option (dump or generate).\n", \
			argv[0]);
		goto done;
	}

	INIT(NAAAIM, SGXsigstruct, sigstruct, ERR(goto done));
	if ( !sigstruct->load(sigstruct, argv[1]) )
		ERR(goto done);

	if ( strcmp(argv[2], "dump") == 0 )
		sigstruct->dump(sigstruct);
	else if ( strcmp(argv[2], "generate") == 0 )
		sigstruct->generate(sigstruct);
	else
		fputs("Unknown option.\n", stdout);

	retn = 0;


 done:
	WHACK(sigstruct);

	return retn;
}