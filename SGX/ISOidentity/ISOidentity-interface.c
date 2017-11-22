#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sgx_trts.h>

#include "ISOidentity-interface.h"


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


/* ecall0 interface function. */
static sgx_status_t sgx_update_model(void *pms)

{
	sgx_status_t retn = SGX_SUCCESS;

	char *update,
	     *enclave_update = NULL;

	size_t update_len = 0;

	struct ecall0_interface *ms = (struct ecall0_interface *) pms;


	/* Verify arguements. */
	update	   = ms->update;
	update_len = strlen(update) + 1;

	CHECK_REF_POINTER(pms, sizeof(struct ecall0_interface));
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
	update_model(enclave_update);


 done:
	if ( enclave_update != NULL )
		free(enclave_update);

	return retn;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_update_model, 0},
	}
};


/* OCALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};
