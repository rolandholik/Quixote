/** \file
 * This file implements a test harness for testing the
 * sys_set_behavior system call.  This system call implements the
 * functionality provided by the ios-identity sysfs interface but
 * with atomicity guarantees.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
#include <sched.h>
#include <asm/unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <NAAAIM.h>


/* sys_set_behavior system call interface definition. */
#define BEHAVIOR 285

#define IMA_SET_CONTOUR		0x1
#define IMA_SET_PSEUDONYM	0x2
#define IMA_SET_AI		0x4

/* Flag for cloning the system behavior. */
#define CLONE_BEHAVIOR		0x00001000

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
	_Bool namespace = false;

	char *contour	= NULL,
	     *pseudonym = NULL,
	     *command	= NULL,
	     *ai_hook	= NULL,
	     *ai_value	= NULL;

	unsigned char *p;

	int opt,
	    retn = 1;

	long int opt_arg;

	String value = NULL;

	struct ai_control {
		unsigned int hook;
		unsigned int value;
	} ctl;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "na:c:p:r:v:")) != EOF )
		switch ( opt ) {
			case 'n':
				namespace = true;
				break;

			case 'a':
				ai_hook = optarg;
				break;
			case 'c':
				contour = optarg;
				break;
			case 'p':
				pseudonym = optarg;
				break;
			case 'r':
				command = optarg;
				break;
			case 'v':
				ai_value = optarg;
				break;
		}


	/* Unshare the behavior space. */
	if ( namespace ) {
		if ( unshare(CLONE_BEHAVIOR) < 0 )
			perror("Unshare returns");
		else {
			fputs("Spawning behavior shell.\n", stdout);
			system("/bin/sh");
			fputs("Behavior shell terminated.\n", stdout);
		}
		goto done;
	}


	/* Run a command in an independent behavior domain. */
	if ( command ) {
		if ( unshare(CLONE_BEHAVIOR) < 0 )
			perror("Unshare returns");
		else {
			fprintf(stdout, "Running command: %s\n", command);
			system(command);
		}
		goto done;
	}

	/* Set an introspection hook. */
	if ( ai_hook != NULL ) {
		if ( ai_value == NULL ) {
			fputs("No AI hook behavior specified.\n", stderr);
			goto done;
		}

		opt_arg = strtol(ai_hook, NULL, 0);
		if ( (errno == ERANGE) || (errno == EINVAL) ) {
			fputs("Error in hook value specification.\n", stderr);
			goto done;
		}
		ctl.hook = opt_arg;

		opt_arg = strtol(ai_value, NULL, 0);
		if ( (errno == ERANGE) || (errno == EINVAL) ) {
			fputs("Error in hook value specification.\n", stderr);
			goto done;
		}
		ctl.value = opt_arg;

		if ( (retn = sys_behavior((void *) &ctl, sizeof(ctl), \
					  IMA_SET_AI)) != 0 ) {
			fprintf(stdout, "Set ai hook returned: %s\n", \
				strerror(errno));
			goto done;
		}

		goto done;
	}


	/* Load either a contour point or define a pseudonym. */
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
