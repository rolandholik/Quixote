#include <stdio.h>
#include <stdbool.h>

#include "NAAAIM.h"
#include "Buffer.h"



extern int main(int argc, char *argv[])

{
	auto char bufr[32];

	auto Buffer rand;

	auto FILE *rndfile;


	if ( (rndfile = fopen("/dev/urandom", "r")) == NULL ) {
		fputs("Cannot open random file.\n", stderr);
		return 1;
	}

	if ( fread(bufr, sizeof(bufr), 1, rndfile) != 1 ) {
		fclose(rndfile);
		fputs("Error reading random file.\n", stderr);
		return 1;
	}
	fclose(rndfile);


	if ( (rand = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer init.\n", stderr);
		return 0;
	}
		
	rand->add(rand, bufr, sizeof(bufr));
	rand->print(rand);
	rand->whack(rand);


	return 0;
}
