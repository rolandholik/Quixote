/** \file
 * This file implements a test harness for the SmartCard Object.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>

#include <HurdLib.h>

#include "NAAAIM.h"
#include "SmartCard.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int cnt,
	    retn = 1;

	SmartCard card = NULL;


	INIT(NAAAIM, SmartCard, card, goto done);
	if ( !card->get_readers(card, &cnt) )
		ERR(goto done);
	if ( cnt == 0 ) {
		if ( !card->wait_for_reader(card, &cnt) )
			ERR(goto done);
	}

	fprintf(stdout, "Reader cnt: %d\n", cnt);
	retn = 0;


 done:
	WHACK(card);

	return retn;
}
