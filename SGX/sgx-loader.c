#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGXloader.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	SGXloader loader = NULL;


	if (argc != 2) {
		fprintf(stderr, "%s: Specify enclave name.\n", argv[0]);
		goto done;
	}

	INIT(NAAAIM, SGXloader, loader, ERR(goto done));

	if ( !loader->load(loader, argv[1]) ) {
		fputs("Taking error exit.\n", stderr);
		ERR(goto done);
	}
	loader->dump(loader);


 done:
	WHACK(loader);
	return retn;
}
