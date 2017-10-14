/** \file
 * This file implements a test driver for the Subject object which is
 * used to model a Subject identity in the Linux iso-identity behavior
 * modeling system.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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

#include "Subject.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	String entry = NULL;

	Buffer bufr = NULL;

	Subject subject = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{swapper/0:/bin/bash-3.2.48} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=3fffffffff} subject{uid=0, gid=0, mode=0100755, name_length=16, name=e1cb9766d47adb4d514d5590dd247504a3aab7e67839d65a6c6f4c32fc120e5d, s_id=xvda, s_uuid=feadbeaffeadbeaffeadbeaffeadbeaf, digest=d2a6bfe0d8a2346d45518dcaaf47642808d6c605506bd0b8e42a65a76735b98e}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, Subject, subject, ERR(goto done));
	if ( !subject->parse(subject, entry) )
		ERR(goto done);
	if ( !subject->measure(subject) )
		ERR(goto done);
	if ( !subject->get_measurement(subject, bufr) )
		ERR(goto done);
	subject->dump(subject);


	subject->reset(subject);
	if ( !subject->parse(subject, entry) )
		ERR(goto done);
	if ( !subject->measure(subject) )
		ERR(goto done);
	fputs("\nMeasurement after reset:\n", stdout);
	bufr->print(bufr);

	fputs("\nIdentity elements:\n", stdout);
	entry->reset(entry);
	if ( !subject->format(subject, entry) )
		ERR(goto done);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(subject);

	return retn;
}
