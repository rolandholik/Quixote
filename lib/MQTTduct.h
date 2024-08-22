/** \file
 * This file contains the header definitions for the MQTTduct object
 * that implements support for publishing strings to an MQTT broker.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_MQTTduct_HEADER
#define NAAAIM_MQttduct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_MQTTduct * MQTTduct;

typedef struct NAAAIM_MQTTduct_State * MQTTduct_State;


/**
 * External SSLDuct object representation.
 */
struct NAAAIM_MQTTduct
{
	/* External methods. */
	_Bool (*set_password)(const MQTTduct, const char *);
	_Bool (*init_publisher)(const MQTTduct, const char *, int port, \
				const char *, const char *, const char *);

	_Bool (*send_String)(const MQTTduct, const String);

	void (*reset)(const MQTTduct);
	void (*whack)(const MQTTduct);

	/* Private state. */
	MQTTduct_State state;
};


/* Duct constructor call. */
extern HCLINK MQTTduct NAAAIM_MQTTduct_Init(void);
#endif
