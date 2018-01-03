/** \file
 * This file contains definitions for an object which the management
 * of a Software Guard Extension (SGX) enclave.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXenclave_HEADER
#define NAAAIM_SGXenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXenclave * SGXenclave;

typedef struct NAAAIM_SGXenclave_State * SGXenclave_State;

/**
 * External SGXenclave object representation.
 */
struct NAAAIM_SGXenclave
{
	/* External methods. */
	_Bool (*open_enclave)(const SGXenclave, const char *, const char *, \
			      _Bool);
	_Bool (*open_enclave_memory)(const SGXenclave, const char *, \
				     const char *, size_t, _Bool);

	_Bool (*create_enclave)(const SGXenclave);
	_Bool (*load_enclave)(const SGXenclave);

	_Bool (*init_enclave)(const SGXenclave, struct SGX_einittoken *);
	_Bool (*init_launch_enclave)(const SGXenclave);

	_Bool (*add_page)(const SGXenclave, const uint8_t *, \
			  struct SGX_secinfo *, const uint8_t);
	_Bool (*add_hole)(const SGXenclave);
	unsigned long int (*get_address)(const SGXenclave);

	_Bool (*add_thread)(const SGXenclave);
	_Bool (*get_thread)(const SGXenclave, unsigned long int *);

	_Bool (*boot_slot)(const SGXenclave, int, const void *, void *, int *);
	int (*boot_ocall)(const SGXenclave, const int, const void *, \
			  const void *);

	_Bool (*get_attributes)(const SGXenclave, sgx_attributes_t *);
	void (*get_secs)(const SGXenclave, struct SGX_secs *);

	void (*debug)(const SGXenclave, const _Bool);
	void (*whack)(const SGXenclave);

	/* Private state. */
	SGXenclave_State state;
};


/* Sgxmetadata constructor call. */
extern SGXenclave NAAAIM_SGXenclave_Init(void);

#endif
