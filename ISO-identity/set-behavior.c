/** \file
 * This file implements a test harness for testing the
 * sys_set_behavior system call.  This system call implements the
 * functionality provided by the ios-identity sysfs interface but
 * with atomicity guarantees.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#define _GNU_SOURCE

#include <stdio.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <asm/unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>


/* sys_set_behavior system call interface definition. */
#define BEHAVIOR 285

#define IMA_SET_CONTOUR		0x1
#define IMA_SET_PSEUDONYM	0x2

#if 1
static inline int sys_behavior(unsigned char *bufr, size_t cnt, \
			       unsigned long flags)
{
	return syscall(326, bufr, cnt, flags);
}
#else
static __inline long sys_behavior(unsigned char * a1, size_t a2, \
				  unsigned int a3)
{
        unsigned long ret;
	unsigned long call = 326;
	fprintf(stderr, "Issuing system call: %lu\n", call);
        __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(call), "D"(a1), "S"(a2),
			      "d"(a3) : "rcx", "r11", "memory");
        return ret;
}
#endif


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *contour	= NULL,
	     *pseudonym = NULL;

	unsigned char *p;

	int opt,
	    retn = 1;

	String value = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "c:p:")) != EOF )
		switch ( opt ) {
			case 'c':
				contour = optarg;
				break;

			case 'p':
				pseudonym = optarg;
				break;
		}

	if ( (contour == NULL) && (pseudonym == NULL) ) {
		fputs("Specify either a pseudonym (-p), or contour (-c)\n", \
		      stderr);
		goto done;
	}
	INIT(HurdLib, String, value, ERR(goto done));


	if ( pseudonym != NULL ) {
		value->add(value, pseudonym);
		if ( !value->add(value, "\n") )
			ERR(goto done);
		p = (unsigned char *) value->get(value);
		if ( (retn = sys_behavior(p, value->size(value), \
					  IMA_SET_PSEUDONYM)) != 0 ) {
			fprintf(stderr, "Set pseudonym returned: %s\n", \
				strerror(errno));
			goto done;
		}
	}

	if ( contour != NULL ) {
		value->add(value, contour);
		if ( !value->add(value, "\n") )
			ERR(goto done);
		p = (unsigned char *) value->get(value);

		if ( (retn = sys_behavior(p, value->size(value), \
					  IMA_SET_CONTOUR)) != 0 ) {
			fprintf(stdout, "Set contour returned: %s\n", \
				strerror(errno));
			goto done;
		}
	}

	retn = 0;
		

 done:
	WHACK(value);

	return retn;
}
