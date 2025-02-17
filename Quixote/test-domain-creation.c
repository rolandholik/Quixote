/** \file
 *
 * This is a simple utility to test creation of TSEM modeling domains.
 * It provides a much more contained approach to testing domain
 * creation than attempting to use the trust orchestrators, which tend
 * to fail rather catastrophically leaving no chance to conduct
 * forensics on what happened.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "TSEMcontrol.h"


int main(int argc, char *argv[])

{
	char *model = "integrity";

	pid_t pid;

	uint64_t id;

	TSEMcontrol Control = NULL;


	INIT(NAAAIM, TSEMcontrol, Control, ERR(goto done));

	pid = fork();
	if (pid < 0) {
		fputs("Failed fork\n", stderr);
		exit(1);
	}

	/* Child process. */
	if ( pid == 0 ) {
		fprintf(stdout, "Creating ns with model: '%s'\n", model);

		if ( !Control->create_ns(Control, TSEMcontrol_TYPE_EXTERNAL,
					 model, NULL, TSEMcontrol_INIT_NS, 0) )
			ERR(goto done);
		fputs("Created namespace.\n", stderr);
		if ( !Control->id(Control, &id) )
			ERR(goto done);
		fprintf(stderr, "ID: %lu\n", id);
		pause();
		_exit(0);
	}

	waitpid(pid, NULL, 0);
	fputs("Test child finished.\n", stderr);


 done:
	WHACK(Control);

	return 0;
}
