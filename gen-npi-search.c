/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <Buffer.h>

#include "NAAAIM.h"
#include "OrgID.h"


extern int main(int argc, char *argv[])

{
	auto char credential[11],
		  anonymizer[65];

	auto int retn;

	auto OrgID orgid = NULL;


	/* Get the organizational identifier and SSN. */
	if ( (orgid = NAAAIM_OrgID_Init()) == NULL ) {
		fputs("Failed organization object init.\n", stderr);
		goto done;
	}

	while ( fscanf(stdin, "%10s %64s ", credential, anonymizer) != EOF ) {
		orgid->create(orgid, anonymizer, credential);
		orgid->print(orgid);
		orgid->reset(orgid);
	}


 done:
	if ( orgid != NULL )
		orgid->whack(orgid);

	return retn;
}
