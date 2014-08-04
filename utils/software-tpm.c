/** \file
 * This file implements a utility to obtain the current software
 * measurement of a system.  It does this by reading the contents
 * of the following pseudo-file:
 *
 *	/sys/kernel/security/ima/binary_runtime_measurements
 *
 * And computes a composite hash over the measurements of the
 * files which have been made by the operating system.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>

#include "SoftwareTPM.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	SoftwareTPM swtpm = NULL;


	INIT(NAAAIM, SoftwareTPM, swtpm, goto done);
	if ( !swtpm->start(swtpm) ) {
		fputs("Failed software TPM start.\n", stderr);
		goto done;
	}
	fputs("TPM software shell\n", stdout);
	system(getenv("SHELL"));

 done:
	WHACK(swtpm);

	return retn;
}
