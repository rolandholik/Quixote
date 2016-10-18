#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGXenclave.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	SGXenclave enclave = NULL;


	if (argc != 3) {
		fprintf(stderr, "%s: Specify enclave device node and "
			"enclave image\n", argv[0]);
		goto done;
	}


	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, argv[1], argv[2]) ) {
		fputs("Taking error exit.\n", stderr);
		ERR(goto done);
	}

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);


 done:
	WHACK(enclave);

	return retn;
}
