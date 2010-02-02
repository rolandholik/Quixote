#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "NAAAIM.h"
#include "IDtoken.h"


extern int main(int argc, char *argv[])

{
	auto _Bool parse = false;

	auto int retn = 1;

	auto IDtoken token = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "P")) != EOF )
		switch ( retn ) {
			case 'P':
				parse = true;
				break;
		}


	if ( parse ) {
		if ( (token = NAAAIM_IDtoken_Init()) == NULL ) {
			fputs("Cannot initialize token.\n", stderr);
			goto done;
		}

		if ( !token->parse(token, stdin) ) {
			fputs("Error parsing token.\n", stderr);
			goto done;
		}
	}


	if ( token != NULL )
		token->whack(token);

 done:
	return retn;
}
