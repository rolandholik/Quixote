/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SSLDuct_HEADER
#define NAAAIM_SSLDuct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SSLDuct * SSLDuct;

typedef struct NAAAIM_SSLDuct_State * SSLDuct_State;

/**
 * External SSLDuct object representation.
 */
struct NAAAIM_SSLDuct
{
	/* External methods. */
	_Bool (*init_server)(const SSLDuct);
	_Bool (*init_client)(const SSLDuct);
	_Bool (*load_credentials)(const SSLDuct, const char *, const char *);
	_Bool (*load_certificates)(const SSLDuct, const char *);
	_Bool (*init_port)(const SSLDuct, const char *, int);
	_Bool (*accept_connection)(const SSLDuct);
	_Bool (*init_connection)(const SSLDuct);
	_Bool (*send_Buffer)(const SSLDuct, const Buffer);
	_Bool (*receive_Buffer)(const SSLDuct, const Buffer);
	char * (*get_client)(const SSLDuct);
	_Bool (*reset)(const SSLDuct);
	_Bool (*whack_connection)(const SSLDuct);
	void (*whack)(const SSLDuct);

	/* Private state. */
	SSLDuct_State state;
};


/* SSLDuct constructor call. */
extern SSLDuct NAAAIM_SSLDuct_Init(void);

#endif
