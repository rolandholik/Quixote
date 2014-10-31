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

/* Local defines. */
#define IDENTITY_NV_INDEX 0xbeaf


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
	const char * const nvpwd = "hoot";

	const char * const nvcmd = "tpm_nvdefine -z -p OWNERWRITE -s 366 " \
		"-r 15 -i 0xbeaf -o hoot 2>&1 >/dev/null";

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

	/*
	 * For now assume that the NVram index has been created but
	 * needs to be updated for the new identity.
	 */
	if ( !pwd->add(pwd, (unsigned char *) nvpwd, strlen(nvpwd)) )
		goto done;

	if ( !cmd->nv_remove(cmd, IDENTITY_NV_INDEX, false, pwd) ) {
		fputs("Failed to remove NVram region.\n", stderr);
		goto done;
	}

	if ( system(nvcmd) != 0 ) {
		fputs("Failed to define NVram region.\n", stderr);
		goto done;
	}

	if ( !cmd->nv_write(cmd, 0xbeaf, id, false, pwd) ) {
		fputs("Failed NVram update.\n", stderr);
		goto done;
	}

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
