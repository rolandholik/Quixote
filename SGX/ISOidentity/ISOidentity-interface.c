#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sgx_trts.h>
#include <sgx_edger8r.h>

#include <HurdLib.h>

#include <NAAAIM.h>
#include "ISOidentity-interface.h"


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


/* Prototype definitions for enclave functions. */
extern _Bool init_model(void);
extern _Bool update_model(char *, _Bool *);
extern void seal_model(void);
extern void dump_model(void);
extern size_t get_size(int);
extern _Bool set_aggregate(uint8_t *, size_t);
extern _Bool get_measurement(unsigned char *);
extern _Bool get_pid(pid_t *);
extern void rewind(int);
extern _Bool get_event(int, char *, size_t);


/* ECALL 0 interface function. */
static sgx_status_t sgx_init_model(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct ISOidentity_ecall0_interface *ms = \
		(struct ISOidentity_ecall0_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall0_interface));


	/* Call enclave function and return result. */
	ms->retn = init_model();

	return retn;
}


/* ECALL1 interface function. */
static sgx_status_t sgx_update_model(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	char *update,
	     *enclave_update = NULL;

	size_t update_len = 0;

	struct ISOidentity_ecall1_interface *ms = \
		(struct ISOidentity_ecall1_interface *) pms;


	/* Verify arguements. */
	update	   = ms->update;
	update_len = strlen(update) + 1;

	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall0_interface));
	CHECK_UNIQUE_POINTER(update, update_len);


	/*
	 * Convert arguements in interface structure to enclave
	 * local values.
	 */
	if ( update != NULL ) {
		if ( (enclave_update = malloc(update_len)) == NULL ) {
			retn = SGX_ERROR_OUT_OF_MEMORY;
			goto done;
		}

		memset(enclave_update, '\0', update_len);
		memcpy(enclave_update, update, update_len - 1);
	}


	/* Call enclave function with local arguement. */
	ms->retn = update_model(enclave_update, &ms->discipline);


 done:
	if ( enclave_update != NULL )
		free(enclave_update);

	return retn;
}


/* ECALL2 interface function. */
static sgx_status_t sgx_seal_model(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;


	if ( pms != NULL )
		return SGX_ERROR_INVALID_PARAMETER;
	seal_model();


	return retn;
}


/* ECALL3 interface function. */
static sgx_status_t sgx_dump_model(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;


	if ( pms != NULL )
		return SGX_ERROR_INVALID_PARAMETER;
	dump_model();


	return retn;
}


/* ECALL4 interface function. */
static sgx_status_t sgx_get_size(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct ISOidentity_ecall4_interface *ms = \
		(struct ISOidentity_ecall4_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall4_interface));

	ms->size = get_size(ms->type);


	return retn;
}


/* ECALL5 interface function. */
static sgx_status_t sgx_set_aggregate(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	unsigned char *aggregate,
		      *e_aggregate = NULL;

	size_t aggregate_len = 0;

	struct ISOidentity_ecall5_interface *ms = \
		(struct ISOidentity_ecall5_interface *) pms;


	/* Verify arguements. */
	aggregate     = ms->aggregate;
	aggregate_len = ms->aggregate_length;

	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall5_interface));
	CHECK_UNIQUE_POINTER(aggregate, aggregate_len);


	/*
	 * Convert arguements in interface structure to enclave
	 * local values.
	 */
	if ( aggregate != NULL ) {
		if ( (e_aggregate = malloc(aggregate_len)) == NULL ) {
			retn = SGX_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		memcpy(e_aggregate, aggregate, aggregate_len);
	}


	/* Call enclave function with local arguement. */
	ms->retn = set_aggregate(e_aggregate, aggregate_len);


 done:
	if ( e_aggregate != NULL )
		free(e_aggregate);

	return retn;
}


/* ECALL6 interface function. */
static sgx_status_t sgx_get_measurement(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	unsigned char *e_measurement;

	struct ISOidentity_ecall6_interface *ms = \
		(struct ISOidentity_ecall6_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall6_interface));


	/*
	 * Convert measurement value in interface structure to enclave
	 * local value
	 */
	if ( (e_measurement = malloc(NAAAIM_IDSIZE)) == NULL ) {
		retn = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}


	/* Call enclave function with local arguement. */
	ms->retn = get_measurement(e_measurement);
	memcpy(ms->measurement, e_measurement, NAAAIM_IDSIZE);


 done:
	if ( e_measurement != NULL )
		free(e_measurement);

	return retn;
}


/* ECALL7 interface function. */
static sgx_status_t sgx_get_pid(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	pid_t pid;

	struct ISOidentity_ecall7_interface *ms = \
		(struct ISOidentity_ecall7_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall7_interface));


	/* Call enclave function with local arguement. */
	ms->retn = get_pid(&pid);
	ms->pid  = pid;

	return retn;
}


/* ECALL8 interface function. */
static sgx_status_t sgx_rewind(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct ISOidentity_ecall8_interface *ms = \
		(struct ISOidentity_ecall8_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall8_interface));

	rewind(ms->type);


	return retn;
}


/* ECALL9 interface function. */
static sgx_status_t sgx_get_event(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct ISOidentity_ecall9_interface *ms = \
		(struct ISOidentity_ecall9_interface *) pms;


	/* Verify arguements. */
	CHECK_REF_POINTER(pms, sizeof(struct ISOidentity_ecall9_interface));


	/* Call enclave function with local arguement. */
	ms->retn = get_event(ms->type, ms->event, sizeof(ms->event)) ;


	return retn;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)sgx_init_model, 0},
		{(void*)(uintptr_t)sgx_update_model, 0},
		{(void*)(uintptr_t)sgx_seal_model, 0},
		{(void*)(uintptr_t)sgx_dump_model, 0},
		{(void*)(uintptr_t)sgx_get_size, 0},
		{(void*)(uintptr_t)sgx_set_aggregate, 0},
		{(void*)(uintptr_t)sgx_get_measurement, 0},
		{(void*)(uintptr_t)sgx_get_pid, 0},
		{(void*)(uintptr_t)sgx_rewind, 0},
		{(void*)(uintptr_t)sgx_get_event, 0}
	}
};


/* OCALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
};
