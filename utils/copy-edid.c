/** \file
 * This file implements a utility for copying an EDID block from
 * a pseudo-file source to a destination pseudo-file.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Local defines. */
#define EDID_SIZE 128


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool retn = false;

	Buffer bufr = NULL;

	File input  = NULL,
	     output = NULL;


	if ( argc != 3 ) {
		fputs("Improper number of arguements.\n", stderr);
		return 1;
	}

	INIT(HurdLib, Buffer, bufr, goto done);

	INIT(HurdLib, File, input, goto done);
	INIT(HurdLib, File, output, goto done);

	if ( !input->open_ro(input, argv[1]) )
		goto done;
	if ( !output->open_wo(output, argv[2]) )
		goto done;

	if ( !input->read_Buffer(input, bufr, EDID_SIZE) )
		goto done;
	if ( !output->write_Buffer(output, bufr) )
		goto done;

	retn = true;


 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(output);

	if ( !retn )
		fputs("EDID copy error\n", stderr);

	return retn ? 0 : 1;
}
