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

#include "SGXmetadata.h"


int main(int argc, char *argv[])

{
	int retn = 1;

	SGXmetadata metadata = NULL;


	if (argc != 2) {
		fprintf(stderr, "%s: Specify enclave name.\n", argv[0]);
		goto done;
	}

	INIT(NAAAIM, SGXmetadata, metadata, ERR(goto done));

	if ( !metadata->load(metadata, argv[1]) )
		ERR(goto done);
	metadata->dump(metadata);


	retn = 0;


 done:
	WHACK(metadata);

	return retn;
}