/** \file
 * This file implements a test driver for the SecurityEvent object
 * which models an information exchange event in a Turing Security
 * Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>

#include "SecurityEvent.h"


/*

 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	String entry = NULL;

	Buffer bufr = NULL;

	SecurityEvent event = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{swapper/0:/bin/bash-3.2.48} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=3fffffffff} cell{uid=0, gid=0, mode=o100755, name_length=16, name=e1cb9766d47adb4d514d5590dd247504a3aab7e67839d65a6c6f4c32fc120e5d, s_id=xvda, s_uuid=feadbeaffeadbeaffeadbeaffeadbeaf, digest=d2a6bfe0d8a2346d45518dcaaf47642808d6c605506bd0b8e42a65a76735b98e}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, entry) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);
	if ( !event->get_identity(event, bufr) )
		ERR(goto done);
	event->dump(event);

	fputs("\nMeasurement:\n", stdout);
	bufr->print(bufr);

	fputs("\nEvent elements:\n", stdout);
	entry->reset(entry);
	if ( !event->format(event, entry) )
		ERR(goto done);
	entry->print(entry);

	/* Re-parse based on formatted event. */
	event->reset(event);
	if ( !event->parse(event, entry) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !event->get_identity(event, bufr) )
		ERR(goto done);
	fputs("\nMeasurement after re-parse:\n", stdout);
	bufr->print(bufr);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(event);

	return retn;
}
