/** \file
 *
 * This file implements the definitions for the command interface 
 * for a cboot management instance.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Basename for the management socket. */
#define SOCKNAME "/var/run/cboot-mgmt"


/* Command definitions. */
enum {
	show_measurement=1,
	show_trajectory,
	show_forensics
} cboot_commands;

struct cboot_cmd_definition {
	int command;
	char *syntax;
};

struct cboot_cmd_definition cboot_cmd_list[] = {
	{show_measurement, "show measurement"},
	{show_trajectory,  "show trajectory"},
	{show_forensics,   "show forensics"},
	{0, NULL}
};
	
