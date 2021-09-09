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
	sancho_state=1,
	exchange_event,
	aggregate_event,
	seal_event,
	ai_event,
	show_measurement,
	show_state,
	show_trajectory,
	show_forensics,
	show_points,
	show_events,
	enable_cell,
	sancho_reset,
	sancho_cmds_max
} sancho_commands;

struct sancho_cmd_definition {
	int command;
	char *syntax;
};

struct sancho_cmd_definition Sancho_cmd_list[] = {
	{sancho_state,		"state "},
	{exchange_event,	"exchange "},
	{aggregate_event,	"aggregate "},
	{seal_event,		"seal"},
	{ai_event,		"ai_event" },
	{show_measurement,	"show measurement"},
	{show_state,		"show state"},
	{show_trajectory,	"show trajectory"},
	{show_forensics,	"show forensics"},
	{show_points,		"show points"},
	{show_events,		"show events"},
	{enable_cell,		"enable cellular"},
	{sancho_reset,		"reset"},
	{0, NULL}
};
