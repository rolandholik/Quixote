/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <HurdLib.h>

#include "IPC.h"


extern int main(int argc, char *argv[])

{
	pid_t pid;

	const char * const ipcname = "IPC_test";

	void *ptr;

	IPC ipc = NULL;


	INIT(NAAAIM, IPC, ipc, goto done);

	if ( argv[1] == NULL ) {
		fputs("master: running.\n", stdout);
		if ( !ipc->create(ipc, ipcname, 16) ) {
			fputs("Failed to create segment.\n", stderr);
			goto done;
		}

		if ( !ipc->lock(ipc) )
			goto done;
	}
	else {
		fputs("slave: running.\n", stdout);
		if ( !ipc->attach(ipc, ipcname) )
			goto done;
		if ( !ipc->lock(ipc) )
			goto done;

		ptr = ipc->get(ipc);
		fprintf(stdout, "slave: Passed value: %d\n", *((pid_t *) ptr));

		if ( !ipc->unlock(ipc) )
			fputs("slave: Failed unlock.\n", stdout);

		fputs("slave: Releasing IPC.\n", stdout);
		WHACK(ipc);
		return 0;
	}

	if ( (pid = fork()) == -1 )
		goto done;

	/* Child. */
	if ( pid == 0 ) {
		fputs("master: starting slave.\n", stdout);
		execl(argv[0], argv[0], "test", NULL);
		fputs("Execution of child test failed.\n", stderr);
		_exit(1);
	}

	/* Parent. */
	fprintf(stdout, "master: Writing pid (%d) to shared memory.\n", pid);
	if ( !ipc->copy(ipc, (void *) &pid, sizeof(pid_t), 0) )
		goto done;
	sleep(5);
	fputs("master: Unlocking region.\n", stdout);
	if ( !ipc->unlock(ipc) )
		goto done;
	sleep(5);


 done:
	WHACK(ipc);

	return 0;
}
