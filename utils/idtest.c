/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

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
#include <IDmgr.h>
#include <TPMcmd.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool key = false;

	char *identity = "device";

	int opt,
	    retn = 1;

	Buffer idhash = NULL,
	       idkey  = NULL;

	String name = NULL;

	IDmgr idmgr = NULL;

	IDtoken token = NULL;


	while ( (opt = getopt(argc, argv, "ki:")) != EOF )
		switch ( opt ) {
			case 'k':
				key = true;
				break;
			case 'i':
				identity = optarg;
				break;
		}


	INIT(NAAAIM, IDmgr, idmgr, goto done);
	if ( !idmgr->attach(idmgr) ) {
		fputs("Failed attach\n", stderr);
		retn = 0;
		goto done;
	}

	if ( (name = HurdLib_String_Init_cstr(identity)) == NULL )
		goto done;

	if ( key ) {
		INIT(HurdLib, Buffer, idhash, goto done);
		INIT(HurdLib, Buffer, idkey, goto done);

		if ( !idmgr->get_id_key(idmgr, name, idhash, idkey) )
			goto done;
		fputs("idhash:\n", stdout);
		idhash->print(idhash);
		fputs("idkey:\n", stdout);
		idkey->print(idkey);
	} else {
		INIT(NAAAIM, IDtoken, token, goto done);

		if ( !idmgr->get_idtoken(idmgr, name, token) )
			goto done;

		fprintf(stdout, "Identity: %s\n", identity);
		token->print(token);
	}
		

 done:
	WHACK(idhash);
	WHACK(idkey);
	WHACK(name);
	WHACK(token);
	WHACK(idmgr);

	return retn;
}
