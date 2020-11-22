/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <sgx_trts.h>

#include <HurdLib.h>

#include "test-Possum2-interface.h"


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

	struct Possum2_ecall0 *ms,
			      ecall0;


	/* Setup enclave based marshalling structure. */
	memset(&ecall0, '\0', sizeof(struct Possum2_ecall0));
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum2_ecall0)) )
		goto done;
	ms = (struct Possum2_ecall0 *) pms;

	ecall0.debug_mode   = ms->debug_mode;
	ecall0.current_time = ms->current_time;
	ecall0.port	    = ms->port;

	ecall0.spid_size = ms->spid_size;


	/* Copy the SPID into enclave space. */
	if ( !SGXidf_untrusted_region(ms->spid, ms->spid_size) )
		goto done;
	if ( (ecall0.spid = malloc(ecall0.spid_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(ecall0.spid, ms->spid, ms->spid_size);

	__builtin_ia32_lfence();


	/* Call the trused function. */
	ms->retn = test_server(&ecall0);
	status = SGX_SUCCESS;


 done:
	memset(ecall0.spid, '\0', ecall0.spid_size);
	free(ecall0.spid);

	memset(&ecall0, '\0', sizeof(ecall0));

	return status;
}


/* ecall1 interface function. */
static sgx_status_t sgx_test_client(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct Possum2_ecall1 *ms,
			      ecall1;


	/* Setup enclave based marshalling structure. */
	memset(&ecall1, '\0', sizeof(struct Possum2_ecall1));
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum2_ecall1)) )
		goto done;
	ms = (struct Possum2_ecall1 *) pms;

	ecall1.debug_mode   = ms->debug_mode;
	ecall1.current_time = ms->current_time;
	ecall1.port	    = ms->port;

	ecall1.hostname_size = ms->hostname_size;
	ecall1.key_size	     = ms->key_size;


	/* Replicate the hostname. */
	if ( !SGXidf_untrusted_region(ms->hostname, ecall1.hostname_size) )
		goto done;
	if ( (ecall1.hostname = malloc(ecall1.hostname_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(ecall1.hostname, ms->hostname, ecall1.hostname_size);


	/* Replicate the key. */
	if ( !SGXidf_untrusted_region(ms->hostname, ecall1.key_size) )
		goto done;
	if ( (ecall1.key = malloc(ecall1.key_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(ecall1.key, ms->key, ecall1.key_size);


	/* Call trusted function. */
	__builtin_ia32_lfence();

	ms->retn = test_client(&ecall1);
	status = SGX_SUCCESS;


 done:
	memset(ecall1.hostname, '\0', ecall1.hostname_size);
	free(ecall1.hostname);

	memset(ecall1.key, '\0', ecall1.key_size);
	free(ecall1.key);

	memset(&ecall1, '\0', sizeof(ecall1));

	return status;
}


/* ECALL 2 interface function */
static sgx_status_t sgx_add_verifier(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct Possum2_ecall2 *ms,
			     ecall2;


	/* Verify marshalled arguements and setup parameters. */
	memset(&ecall2, '\0', sizeof(struct Possum2_ecall2));

	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum2_ecall2)) )
		goto done;
	ms = (struct Possum2_ecall2 *) pms;

	ecall2.key_size = ms->key_size;


	/* Replicate the key. */
	if ( !SGXidf_untrusted_region(ms->key, ecall2.key_size) )
		goto done;

	if ( (ecall2.key = malloc(ecall2.key_size)) == NULL )
		goto done;
	memcpy(ecall2.key, ms->key, ecall2.key_size);


	/* Call the trusted function. */
	__builtin_ia32_lfence();

	ms->retn = add_verifier(&ecall2);
	status = SGX_SUCCESS;


 done:
	memset(ecall2.key, '\0', ecall2.key_size);
	free(ecall2.key);

	memset(&ecall2, '\0', sizeof(ecall2));

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
		{(void *)(uintptr_t)sgx_test_client, 0},
		{(void *)(uintptr_t)sgx_add_verifier, 0}
	}
};


/* OCALL interface table. */
const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0, 0, 0},
		{0, 0, 0},
		{0, 0, 0},
		{0, 0, 0},
		{0, 0, 0},
		{0, 0, 0}
	}
};
