/** \file
 * This file contains definitions for an object which the management
 * of a Software Guard Extension (SGX) enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEenclave_HEADER
#define NAAAIM_SRDEenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEenclave * SRDEenclave;

typedef struct NAAAIM_SRDEenclave_State * SRDEenclave_State;

/**
 * External SRDEenclave object representation.
 */
struct NAAAIM_SRDEenclave
{
	/* External methods. */
	_Bool (*setup)(const SRDEenclave, const char *, const char *, _Bool);

	_Bool (*open_enclave)(const SRDEenclave, const char *, const char *, \
			      _Bool);
	_Bool (*open_enclave_memory)(const SRDEenclave, const char *, \
				     const char *, size_t, _Bool);

	_Bool (*create_enclave)(const SRDEenclave);
	_Bool (*load_enclave)(const SRDEenclave);

	_Bool (*init_enclave)(const SRDEenclave, struct SGX_einittoken *);
	_Bool (*init_launch_enclave)(const SRDEenclave);

	_Bool (*add_page)(const SRDEenclave, const uint8_t *, \
			  struct SGX_secinfo *, const uint8_t);
	_Bool (*add_hole)(const SRDEenclave);
	unsigned long int (*get_address)(const SRDEenclave);

	_Bool (*add_thread)(const SRDEenclave);
	_Bool (*get_thread)(const SRDEenclave, unsigned long int *);

	_Bool (*boot_slot)(const SRDEenclave, int, const struct OCALL_api *, \
			   void *, int *);
	int (*boot_ocall)(const SRDEenclave, const int, const void *, \
			  const void *);

	void (*get_target_info)(const SRDEenclave, struct SGX_targetinfo *);
	_Bool (*get_attributes)(const SRDEenclave, sgx_attributes_t *);
	void (*get_secs)(const SRDEenclave, struct SGX_secs *);
	void (*get_psvn)(const SRDEenclave, struct SGX_psvn *);

	void (*debug)(const SRDEenclave, const _Bool);
	void (*whack)(const SRDEenclave);

	/* Private state. */
	SRDEenclave_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEenclave NAAAIM_SRDEenclave_Init(void);
#endif
