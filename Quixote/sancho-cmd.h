/** \file
 *
 * This file implements the definitions for the command interface 
 * to the sancho security co-processor:
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Basename for the management socket. */
#define SOCKNAME "/var/run/quixote-mgmt"


/* Command definitions. */
enum {
	export_event=1,
	aggregate_event,
	seal_event,
	log_event,
	sancho_load,
	show_measurement,
	show_state,
	show_trajectory,
	show_counts,
	show_coefficients,
	show_forensics_counts,
	show_forensics_coefficients,
	show_forensics,
	show_events,
	show_map,
	enable_cell,
	sancho_reset,
	sancho_cmds_max
} sancho_commands;

struct sancho_cmd_definition {
	int command;
	char *syntax;
};

struct sancho_cmd_definition Sancho_cmd_list[] = {
	{export_event,			"export "},
	{aggregate_event,		"aggregate "},
	{seal_event,			"seal"},
	{log_event,			"log" },
	{sancho_load,			"load " },
	{show_measurement,		"show measurement"},
	{show_state,			"show state"},
	{show_trajectory,		"show trajectory"},
	{show_counts,			"show counts"},
	{show_coefficients,		"show coefficients"},
	{show_forensics_counts,		"show forensics_counts"},
	{show_forensics_coefficients,	"show forensics_coefficients"},
	{show_forensics,		"show forensics"},
	{show_events,			"show events"},
	{show_map,			"show map"},
	{enable_cell,			"enable cellular"},
	{sancho_reset,			"reset"},
	{0, NULL}
};
