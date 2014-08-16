/** \file
 * This file implements loading of an identity token into TPM NVram
 * memory.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <IDtoken.h>

#include "TPMcmd.h"

/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	FILE *idt = NULL;

	Buffer id  = NULL,
	       pwd = NULL;

	TPMcmd cmd = NULL;

	IDtoken token = NULL;


	if ( argv[1] == NULL ) {
		fputs("No identity specified.\n", stdout);
		goto done;
	}
	if ( (idt = fopen(argv[1], "ro")) == NULL )
		goto done;

	INIT(HurdLib, Buffer, id, goto done);
	INIT(HurdLib, Buffer, pwd, goto done);
	INIT(NAAAIM, IDtoken, token, goto done);
	INIT(NAAAIM, TPMcmd, cmd, goto done);

	token->parse(token, idt);
	if ( !token->encode(token, id) )
		goto done;

	pwd->add(pwd, (unsigned char *) "hoot", 4);
	if ( !cmd->nv_write(cmd, 0xbeaf, id, false, pwd) )
		goto done;

	retn = 0;

 done:
	if ( idt != NULL )
		fclose(idt);

	WHACK(id);
	WHACK(pwd);
	WHACK(cmd);
	WHACK(token);

	return retn;
}
