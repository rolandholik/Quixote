/** \file
 * This file contains definitions for the object which manages the
 * protocol for information queries to the identity provider server.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_ProviderQuery_HEADER
#define NAAAIM_ProviderQuery_HEADER

/* Include files. */
#include <stddef.h>
#include <stdbool.h>

#include <Origin.h>
#include <Buffer.h>


/* Object type definitions. */
typedef struct NAAAIM_ProviderQuery * ProviderQuery;

typedef struct NAAAIM_ProviderQuery_State * ProviderQuery_State;

typedef	enum {
	PQquery_simple,
	PQquery_simple_sms,

	PQreply_summary,
} ProviderQuery_type;


/**
 * External ProviderQuery object representation.
 */
struct NAAAIM_ProviderQuery
{
	/* External methods. */
	_Bool (*set_simple_query)(const ProviderQuery, const Buffer);
	_Bool (*get_simple_query)(const ProviderQuery, const Buffer);

	_Bool (*set_simple_query_sms)(const ProviderQuery, const Buffer, \
				      const char *, int);
	_Bool (*get_simple_query_sms)(const ProviderQuery, const Buffer, \
				      const String, int *);

	_Bool (*encode)(const ProviderQuery, const Buffer);
	_Bool (*decode)(const ProviderQuery, const Buffer);

	ProviderQuery_type (*type)(const ProviderQuery);

	void (*whack)(const ProviderQuery);

	/* Private state. */
	ProviderQuery_State state;
};


/* ProviderQuery constructor call. */
extern HCLINK ProviderQuery NAAAIM_ProviderQuery_Init(void);
#endif
