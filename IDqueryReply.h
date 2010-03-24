/** \file
 * This file contains the interface definitions for the object which
 * manages replies from the identity broker servers.
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_IDqueryReply_HEADER
#define NAAAIM_IDqueryReply_HEADER

/* Include files. */
#include <stddef.h>
#include <stdbool.h>

#include <Origin.h>
#include <Buffer.h>
#include <String.h>


/* Object type definitions. */
typedef struct NAAAIM_IDqueryReply * IDqueryReply;

typedef struct NAAAIM_IDqueryReply_State * IDqueryReply_State;

typedef	enum {
	IDQreply_notfound,
	IDQreply_ipredirect,
	IDQreply_phone,
	IDQreply_text,
	IDQreply_sms,
	IDQreply_sms_bimodal,
} IDqueryReply_type;


/**
 * External IDqueryReply object representation.
 */
struct NAAAIM_IDqueryReply
{
	/* External methods. */
	_Bool (*set_ip_reply)(const IDqueryReply, const char *, int);
	_Bool (*get_ip_reply)(const IDqueryReply, const Buffer, int *);
	_Bool (*set_text_reply)(const IDqueryReply, const String);
	_Bool (*get_text_reply)(const IDqueryReply, const String);
	_Bool (*set_sms_reply)(const IDqueryReply, const String);
	_Bool (*get_sms_reply)(const IDqueryReply, const String, int *);
	_Bool (*encode)(const IDqueryReply, const Buffer);
	_Bool (*decode)(const IDqueryReply, const Buffer);
	_Bool (*is_type)(const IDqueryReply, IDqueryReply_type);
	void (*reset)(const IDqueryReply);
	void (*whack)(const IDqueryReply);

	/* Private state. */
	IDqueryReply_State state;
};


/* IDqueryReply constructor call. */
extern IDqueryReply NAAAIM_IDqueryReply_Init(void);

#endif
