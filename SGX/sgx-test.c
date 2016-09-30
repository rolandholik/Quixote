/** \file
 * This file implements a utility for testing basic SGX functionality
 * using the Linux SGX kernel driver.
 *
 * A sample enclave is created using the enlave memory layout as
 * described in Figure 39.1 of the Intel Software Development Manual
 * (SDM).  The enclave memory layout is as follows:
 *
 * Base + size:----->
 *			Thread data pages
 *			TCS page
 *			Global data page
 *         		Code page
 * Base address:---->
 *
 * In a standard enclave the TCS page plus the thread data pages are
 * replicated once for each thread of execution which will be
 * supported by the enclave.
 */

/**************************************************************************
 * (C)Copyright 2016, IDfusion, LLC. All rights reserved.
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

#include "SGX.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int retc,
	    fd	 = -1,
	    retn = 1;

	char regular_page[4096];

	struct SGX_create_param create_param;

	struct SGX_secs secs;

	struct SGX_add_param add_param;

	struct SGX_secinfo secinfo;

	struct SGX_tcs tcs;

	struct SGX_destroy_param destroy_param;


	/* Open the SGX character device node. */
	if ( (fd = open(SGX_DEVICE, O_RDWR)) == -1 ) {
		fputs("Cannot open SGX device.\n", stderr);
		goto done;
	}


	/* Initialize the SECS control structure. */
	memset(&secs, '\0', sizeof(secs));
	secs.size	  = 1048576;
	secs.base	  = 0;
	secs.ssaframesize = 1;
	secs.miscselect	  = 0;
	secs.attributes	  = 36;
	secs.xfrm	  = 7;
	secs.isvprodid	  = 0;
	secs.isvsvn	  = 0;

	/* Setup the SGX enclave creation ioctl structure. */
	create_param.secs = &secs;
	create_param.addr = 0;

	/* Test creation of the enclave. */
	fputs("Testing SGX enclave creation: ", stdout);
	if ( (retc = ioctl(fd, SGX_IOCTL_ENCLAVE_CREATE, &create_param)) \
	     < 0 ) {
		fprintf(stdout, "Failed, errno=%d\n", errno);
		goto done;
	}
	fprintf(stdout, "OK, start adress=0x%0lx\n", create_param.addr);


	/* Test addition of a regular enclave page. */
	memset(regular_page, '\0', sizeof(regular_page));

	memset(&secinfo, '\0', sizeof(secinfo));
	secinfo.flags = (SGX_SECINFO_R | SGX_SECINFO_REG);

	memset(&add_param, '\0', sizeof(add_param));
	add_param.addr	    = create_param.addr;
	add_param.user_addr = (unsigned long) regular_page;
	add_param.secinfo   = &secinfo;

	fputs("Tesing SGX enclave regular page addition: ", stdout);
	if ( (retc = ioctl(fd, SGX_IOCTL_ENCLAVE_ADD_PAGE, &add_param)) < 0 ) {
		fprintf(stdout, "Failed, errno=%d\n", errno);
		goto done;
	}
	fputs("OK\n", stdout);

	/* Test addition of a Task Control Structure page. */
	memset(&tcs, '\0', sizeof(tcs));
	tcs.ossa = create_param.addr + 4096;
	tcs.cssa = 0;
	tcs.nssa = 2;
	tcs.ofsbase = tcs.ossa;
	tcs.ogsbase = tcs.ossa;
	tcs.fslimit = 0xfff;
	tcs.gslimit = 0xfff;

	secinfo.flags = (SGX_SECINFO_R | SGX_SECINFO_TCS);

	memset(&add_param, '\0', sizeof(add_param));
	add_param.addr	    = create_param.addr + 4096;
	add_param.user_addr = (unsigned long) &tcs;
	add_param.secinfo   = &secinfo;

	fputs("Testing SGX enclave TCS page addition: ", stdout);
	if ( (retc = ioctl(fd, SGX_IOCTL_ENCLAVE_ADD_PAGE, &add_param)) < 0 ) {
		fprintf(stdout, "Failed, errno=%d\n", errno);
		goto done;
	}
	fputs("OK\n", stdout);


	/* Test destruction of an enclave. */
	memset(&destroy_param, '\0', sizeof(destroy_param));
	destroy_param.addr = create_param.addr;

	fputs("Testing SGX enclave destruction: ", stdout);
	if ( (retc = ioctl(fd, SGX_IOCTL_ENCLAVE_DESTROY, &destroy_param)) \
	     < 0 ) {
		fprintf(stderr, "Failed, errno=%d\n", errno);
		goto done;
	}
	fputs("OK\n", stdout);
	
	
 done:
	if ( fd != -1 )
		close(fd);

	return retn;
}
