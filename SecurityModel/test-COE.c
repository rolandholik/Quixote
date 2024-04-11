/** \file
 * This file implements a test driver for the COE object which is
 * used to model a context of execution in the Turing Security Event
 * Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#define SAMPLE "{\"export\": {\"type\": \"event\"}, \"event\": {\"pid\": \"1257\", \"process\": \"quixote-us\", \"type\": \"file_open\", \"ttd\": \"230\", \"p_ttd\": \"230\", \"task_id\": \"732eee4a11f0399597915b524eb95b7e1b10a7237a476adc92a1e6b769dee5d3\", \"p_task_id\": \"732eee4a11f0399597915b524eb95b7e1b10a7237a476adc92a1e6b769dee5d3\", \"ts\": \"26963237445770\"}, \"COE\": {\"uid\": \"0\", \"euid\": \"0\", \"suid\": \"0\", \"gid\": \"0\", \"egid\": \"0\", \"sgid\": \"0\", \"fsuid\": \"0\", \"fsgid\": \"0\", \"capeff\": \"0x3ffffffffff\"}, \"file_open\": {\"flags\": \"0\", \"uid\": \"2\", \"gid\": \"2\", \"mode\": \"0100755\", \"path\": \"/opt/Quixote/sbin/runc\", \"s_magic\": \"0xef53\", \"s_id\": \"xvda\", \"s_uuid\": \"feadbeaffeadbeaffeadbeaffeadbeaf\", \"digest\": \"db772be63147a4e747b4fe286c7c16a2edc4a8458bd3092ea46aaee77750e8ce\"}}"


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

#include "COE.h"


/*

 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	String entry = NULL;

	Buffer bufr = NULL;

	COE coe = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, SAMPLE) )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, COE, coe, ERR(goto done));
	if ( !coe->parse(coe, entry) )
		ERR(goto done);
	if ( !coe->measure(coe) )
		ERR(goto done);
	if ( !coe->get_measurement(coe, bufr) )
		ERR(goto done);
	coe->dump(coe);


	coe->reset(coe);
	if ( !coe->parse(coe, entry) )
		ERR(goto done);
	if ( !coe->measure(coe) )
		ERR(goto done);
	fputs("\nMeasurement after reset:\n", stdout);
	bufr->print(bufr);

	fputs("\nIdentity elements:\n", stdout);
	entry->reset(entry);
	if ( !coe->format(coe, entry) )
		ERR(goto done);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(coe);

	return retn;
}
