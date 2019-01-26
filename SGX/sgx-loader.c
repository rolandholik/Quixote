#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXloader.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	_Bool debug = false;

	SGXloader loader = NULL;


	if (argc != 3) {
		fprintf(stderr, "%s: Specify enclave name and debug " \
			"status.\n", argv[0]);
		goto done;
	}
	if ( strcmp(argv[2], "1") == 0 )
		debug = true;

	INIT(NAAAIM, SGXloader, loader, ERR(goto done));

	if ( !loader->load(loader, argv[1], debug) ) {
		fputs("Taking error exit.\n", stderr);
		ERR(goto done);
	}
	loader->dump(loader);


 done:
	WHACK(loader);
	return retn;
}
