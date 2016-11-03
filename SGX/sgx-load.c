#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	_Bool debug = false;

	SGXenclave enclave = NULL;


	if (argc != 4) {
		fprintf(stderr, "%s: Specify enclave device node, enclave "
			"image and debug status.\n", argv[0]);
		goto done;
	}
	if ( strcmp(argv[3], "1") == 0 )
		debug = true;


	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, argv[1], argv[2], debug) ) {
		fputs("Taking error exit.\n", stderr);
		ERR(goto done);
	}

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave) )
		ERR(goto done);


 done:
	WHACK(enclave);

	return retn;
}
