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
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <SoftwareStatus.h>


extern int main(int argc, char *argv[])

{
	int retn = 1;

	Buffer measurement;

	SoftwareStatus status = NULL;


	INIT(NAAAIM, SoftwareStatus, status, goto done);
	if ( !status->open(status) ) {
		fputs("Failed measurement open.\n", stderr);
		goto done;
	}

	if ( !status->measure(status) ) {
		fputs("Failed measurement request.\n", stderr);
		goto done;
	}

	measurement = status->get_template_hash(status);
	fputs("Template measurement:\n", stdout);
	measurement->print(measurement);

	measurement = status->get_file_hash(status);
	fputs("File measurement:\n", stdout);
	measurement->print(measurement);


 done:
	WHACK(status);

	return retn;
}
