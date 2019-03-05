/** \file
 * This file implements a test driver for the Actor object which is
 * used to model an actor identity in the Linux iso-identity behavior
 * modeling system.  using the Linux SGX kernel driver.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
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

#include "Actor.h"


/*

 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	String entry = NULL;

	Buffer bufr = NULL;

	Actor actor = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{swapper/0:/bin/bash-3.2.48} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=3fffffffff} subject{uid=0, gid=0, mode=o100755, name_length=16, name=e1cb9766d47adb4d514d5590dd247504a3aab7e67839d65a6c6f4c32fc120e5d, s_id=xvda, s_uuid=feadbeaffeadbeaffeadbeaffeadbeaf, digest=d2a6bfe0d8a2346d45518dcaaf47642808d6c605506bd0b8e42a65a76735b98e}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, Actor, actor, ERR(goto done));
	if ( !actor->parse(actor, entry) )
		ERR(goto done);
	if ( !actor->measure(actor) )
		ERR(goto done);
	if ( !actor->get_measurement(actor, bufr) )
		ERR(goto done);
	actor->dump(actor);


	actor->reset(actor);
	if ( !actor->parse(actor, entry) )
		ERR(goto done);
	if ( !actor->measure(actor) )
		ERR(goto done);
	fputs("\nMeasurement after reset:\n", stdout);
	bufr->print(bufr);

	fputs("\nIdentity elements:\n", stdout);
	entry->reset(entry);
	if ( !actor->format(actor, entry) )
		ERR(goto done);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(actor);

	return retn;
}
