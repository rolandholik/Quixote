/** \file
 * This file implements a utility to execute TPM commands which are
 * specified as command-line arguements to the application.
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
#include <stdint.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>

#include "TPMcmd.h"


extern int main(int argc, char *argv[])

{
	int retn = 1;

	const static char *str = "9cfe5319370fe19207093adcfa6a98eb09e39099";

	Buffer bufr;

	TPMcmd tpmcmd = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(NAAAIM, TPMcmd, tpmcmd, goto done);

	if ( !bufr->add_hexstring(bufr, str) )
		goto done;
	if ( !tpmcmd->pcr_extend(tpmcmd, 2, bufr) ) {
		fputs("Failed extend.\n", stderr);
		goto done;
	}
	fputs("Extended PCR:\n", stdout);
	bufr->hprint(bufr);

	bufr->reset(bufr);
	if ( !tpmcmd->pcr_read(tpmcmd, 2, bufr) ) {
		fputs("Failed PCR read.\n", stdout);
		goto done;
	}
	bufr->hprint(bufr);


 done:
	WHACK(bufr);
	WHACK(tpmcmd);

	return retn;
}
