/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <IDtoken.h>
#include <SHA256.h>

#include "TPMcmd.h"
#include "IDmgr.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *identity = "device";

	int opt,
	    retn = 1;

	String name = NULL;

	IDmgr idmgr = NULL;

	IDtoken token = NULL;


	while ( (opt = getopt(argc, argv, "i:")) != EOF )
		switch ( opt ) {
			case 'i':
				identity = optarg;
				break;
		}

	INIT(NAAAIM, IDtoken, token, goto done);

	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->attach(idmgr) ) {
		fputs("Failed attach\n", stderr);
		retn = 0;
		goto done;
	}

	if ( (name = HurdLib_String_Init_cstr(identity)) == NULL )
		goto done;

	if ( !idmgr->get_idtoken(idmgr, name, token) )
		goto done;

	fprintf(stdout, "Identity: %s\n", identity);
	token->print(token);
		

 done:
	WHACK(name);
	WHACK(token);
	WHACK(idmgr);

	return retn;
}
