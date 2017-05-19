/** \file
 * This file implements a utility for boot a canister into an independent
 * measurement domain.  After creating an independent measurement domain
 * the utility forks and then executes the boot of the contain in the
 * subordinate process.  The parent process monitors the following file
 *
 * /sys/fs/iso-identity/update
 *
 * For measurement domain updates.
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
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *update_file = NULL,
	     bufr[20 * 2 + 2];

	int opt,
	    fd	 = 0,
	    retn = 1;

	struct pollfd update;


	while ( (opt = getopt(argc, argv, "f:")) != EOF )
		switch ( opt ) {
			case 'f':
				update_file = optarg;
				break;
		}

	if ( update_file == NULL ) {
		fputs("No update file specified.\n", stderr);
		goto done;
	}


	if ( (fd = open(update_file, O_RDONLY)) < 0 ) {
		fprintf(stderr, "Cannot open update file: errno=%d - %s\n", \
			errno, strerror(errno));
		goto done;
	}
	update.fd = fd;
	update.events = POLLPRI;


	while ( 1 ) {
		do {
			fputs("Doing cycle.\n", stderr);
			memset(bufr, '\0', sizeof(bufr));
			retn = read(fd, bufr, sizeof(bufr) - 1);
			if ( retn == (sizeof(bufr) - 1) ) {
				fprintf(stdout, "%s", bufr);
				if ( lseek(fd, 0, SEEK_SET) < 0 ) {
					fputs("Seek error.\n", stderr);
					goto done;
				}
				continue;
			}
			fprintf(stderr, "Have error: retn=%d, errno=%d\n", \
				retn, errno);
			if ( (retn < 0) && (errno == ENODATA) )
				break;
		} while ( errno != ENODATA );

		fputs("Calling poll\n", stderr);
		retn = poll(&update, 1, -1);
		if ( retn < 0 ) {
			fprintf(stderr, "Poll error: casue=%s\n", \
				strerror(errno));
			goto done;
		}
		fprintf(stdout, "Poll return: %0x\n", update.revents);
	};


 done:
	if ( fd > 0 )
		close(fd);
	return retn;
}
