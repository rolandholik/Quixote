/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef SSL_Duct_HEADER
#define SSL_Duct_HEADER


/* Object type definitions. */
typedef struct SSL_Duct * SSLduct;

typedef struct SSL_Duct_State * SSLduct_State;

/**
 * External Duct object representation.
 */
struct SSL_Duct
{
	/* External methods. */
	_Bool (*init_server)(const SSLduct);
	_Bool (*init_client)(const SSLduct);
	_Bool (*load_credentials)(const SSLduct, const char *, const char *);
	_Bool (*load_certificates)(const SSLduct, const char *);
	_Bool (*init_port)(const SSLduct, const char *, int);
	_Bool (*accept_connection)(const SSLduct);
	_Bool (*init_connection)(const SSLduct);
	_Bool (*send_Buffer)(const SSLduct, const Buffer);
	_Bool (*receive_Buffer)(const SSLduct, const Buffer);
	char * (*get_client)(const SSLduct);
	_Bool (*reset)(const SSLduct);
	_Bool (*whack_connection)(const SSLduct);
	void (*whack)(const SSLduct);

	/* Private state. */
	SSLduct_State state;
};


/* Duct constructor call. */
extern HCLINK SSLduct SSLduct_Init(void);
#endif
