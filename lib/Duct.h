/** \file
 * This file contains the header definitions for the Duct object
 * which implements basic network docket communication primitives.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Duct_HEADER
#define NAAAIM_Duct_HEADER


/**
 * Enumeration type which defines the method type whose userspace
 * implementation is being requested.
 */
enum Duct_ocalls {
	Duct_init,

	Duct_init_server,
	Duct_init_client,
	Duct_set_server,
	Duct_init_port,
	Duct_accept_connection,
	Duct_init_connection,
	Duct_send_buffer,
	Duct_receive_buffer,

	Duct_get_ipv4,
	Duct_get_client,

	Duct_do_reverse,
	Duct_eof,
	Duct_reset,
	Duct_whack,

	Duct_END
};


/**
 * Structure which marshalls the data for the call into and out of
 * the Duct manager.
 */
struct Duct_ocall {
	_Bool retn;
	enum Duct_ocalls ocall;
	unsigned int instance;

	_Bool eof;
	_Bool mode;
	uint32_t addr;
	int port;
	char *hostname;

	size_t size;
	unsigned char *bufr;

	unsigned char arena[];
};


/* Object type definitions. */
typedef struct NAAAIM_Duct * Duct;

typedef struct NAAAIM_Duct_State * Duct_State;

/**
 * External SSLDuct object representation.
 */
struct NAAAIM_Duct
{
	/* External methods. */
	_Bool (*init_server)(const Duct);
	_Bool (*init_client)(const Duct);
	_Bool (*set_server)(const Duct, const char *);
	_Bool (*init_port)(const Duct, const char *, int);
	_Bool (*accept_connection)(const Duct);
	_Bool (*init_connection)(const Duct);
	_Bool (*send_Buffer)(const Duct, const Buffer);
	_Bool (*receive_Buffer)(const Duct, const Buffer);

	struct in_addr * (*get_ipv4)(const Duct);
	char * (*get_client)(const Duct);

	void (*do_reverse)(const Duct, const _Bool);
	_Bool (*eof)(const Duct);
	void (*reset)(const Duct);
	_Bool (*whack_connection)(const Duct);
	void (*whack)(const Duct);

	/* Private state. */
	Duct_State state;
};


/* Duct constructor call. */
extern HCLINK Duct NAAAIM_Duct_Init(void);

/* Definition for entry point for Duct SGX manager. */
extern int Duct_mgr(struct Duct_ocall *ocp);
#endif
