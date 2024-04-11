/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdbool.h>
#include <string.h>

#include <sgx_trts.h>

#include "test-Duct-interface.h"


static _Bool SGXidf_untrusted_region(void *ptr, size_t size)

{
	_Bool retn = false;

	if ( ptr == NULL )
		goto done;
	if ( sgx_is_within_enclave(ptr, size) )
		goto done;
	retn = true;
 done:
	return retn;
}


/* ecall0 interface function. */
static sgx_status_t sgx_test_server(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct Duct_ecall0 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Duct_ecall0)) )
		goto done;
	ms = (struct Duct_ecall0 *) pms;
	__builtin_ia32_lfence();


	/* Call the trused function. */
	ms->retn = test_server(ms->port);
	status = SGX_SUCCESS;


 done:
	return status;
}


/* ecall1 interface function. */
static sgx_status_t sgx_test_client(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	char *hostname = NULL;

	int port;

	struct Duct_ecall1 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Duct_ecall1)) )
		goto done;
	ms = (struct Duct_ecall1 *) pms;

	port = ms->port;

	if ( !SGXidf_untrusted_region(ms->hostname, ms->hostname_size) )
		goto done;
	if ( (hostname = malloc(ms->hostname_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(hostname, ms->hostname, ms->hostname_size);
	__builtin_ia32_lfence();


	/* Call trusted function. */
	ms->retn = test_client(hostname, port);
	status = SGX_SUCCESS;


 done:
	if ( hostname != NULL )
		free(hostname);

	return status;
}


/* ECALL interface table. */
const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void *)(uintptr_t)sgx_test_server, 0},
		{(void *)(uintptr_t)sgx_test_client, 0}
	}
};


/* OCALL interface table. */
const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}
	}
};
