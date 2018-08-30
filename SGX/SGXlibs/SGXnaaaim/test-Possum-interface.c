#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <sgx_trts.h>

#include <HurdLib.h>

#include "test-Possum-interface.h"


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

	char *spid = NULL;

	unsigned char *identity = NULL,
		      *verifier = NULL;

	size_t identity_size = 0,
	       verifier_size = 0;

	struct Possum_ecall0 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum_ecall0)) )
		goto done;
	ms = (struct Possum_ecall0 *) pms;

	if ( !SGXidf_untrusted_region(ms->spid, ms->spid_size) )
		goto done;
	if ( (spid = malloc(ms->spid_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(spid, ms->spid, ms->spid_size);

	if ( !SGXidf_untrusted_region(ms->identity, ms->identity_size) )
		goto done;
	if ( (identity = malloc(ms->identity_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	identity_size = ms->identity_size;
	memcpy(identity, ms->identity, identity_size);

	if ( ms->verifier_size != 0 ) {
		if ( !SGXidf_untrusted_region(ms->verifier, \
					      ms->verifier_size) )
			goto done;
		if ( (verifier = malloc(ms->verifier_size)) == NULL ) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		verifier_size = ms->verifier_size;
		memcpy(verifier, ms->verifier, verifier_size);
	}

	__builtin_ia32_lfence();


	/* Call the trused function. */
	ms->retn = test_server(ms->debug_mode, ms->port, ms->current_time,   \
			       spid, identity_size, identity, verifier_size, \
			       verifier);
	status = SGX_SUCCESS;


 done:
	free(spid);
	free(identity);
	free(verifier);

	return status;
}


/* ecall1 interface function. */
static sgx_status_t sgx_test_client(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	char *hostname = NULL,
	     *spid     = NULL;

	unsigned char *identity = NULL,
		      *verifier = NULL;

	time_t current_time = 0;

	size_t identity_size = 0,
	       verifier_size = 0;

	int port;

	struct Possum_ecall1 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum_ecall1)) )
		goto done;
	ms = (struct Possum_ecall1 *) pms;

	port	     = ms->port;
	current_time = ms->current_time;

	if ( !SGXidf_untrusted_region(ms->hostname, ms->hostname_size) )
		goto done;
	if ( (hostname = malloc(ms->hostname_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(hostname, ms->hostname, ms->hostname_size);

	if ( !SGXidf_untrusted_region(ms->spid, ms->spid_size) )
		goto done;
	if ( (spid = malloc(ms->spid_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memcpy(spid, ms->spid, ms->spid_size);

	if ( !SGXidf_untrusted_region(ms->identity, ms->identity_size) )
		goto done;
	if ( (identity = malloc(ms->identity_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	identity_size = ms->identity_size;
	memcpy(identity, ms->identity, identity_size);

	if ( ms->verifier_size != 0 ) {
		if ( !SGXidf_untrusted_region(ms->verifier, \
					      ms->verifier_size) )
			goto done;
		if ( (verifier = malloc(ms->verifier_size)) == NULL ) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		verifier_size = ms->verifier_size;
		memcpy(verifier, ms->verifier, verifier_size);
	}

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ms->retn = test_client(ms->debug_mode, hostname, port, current_time, \
			       spid, identity_size, identity, verifier_size, \
			       verifier);
	status = SGX_SUCCESS;


 done:
	free(hostname);
	free(spid);
	free(identity);
	free(verifier);

	return status;
}


static sgx_status_t sgx_generate_identity(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	uint8_t *id = NULL;

	struct Possum_ecall2 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum_ecall2)) )
		goto done;
	ms = (struct Possum_ecall2 *) pms;

	if ( !SGXidf_untrusted_region(ms->id, 32) )
		goto done;
	if ( (id = malloc(32)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ms->retn = generate_identity(id);
	status = SGX_SUCCESS;

	if ( ms->retn )
		memcpy(ms->id, id, 32);


 done:
	free(id);

	return status;
}


/* ECALL 3 interface function */
static sgx_status_t sgx_add_verifier(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct Possum_ecall3 *ms,
			     ecall3;


	/* Verify marshalled arguements and setup parameters. */
	memset(&ecall3, '\0', sizeof(struct Possum_ecall3));

	if ( !SGXidf_untrusted_region(pms, sizeof(struct Possum_ecall3)) )
		goto done;
	ms = (struct Possum_ecall3 *) pms;


	/* Replicate the identifier verifier. */
	ecall3.verifier_size = ms->verifier_size;

	if ( !SGXidf_untrusted_region(ms->verifier, ecall3.verifier_size) )
		goto done;

	if ( (ecall3.verifier = malloc(ecall3.verifier_size)) == NULL )
		goto done;
	memcpy(ecall3.verifier, ms->verifier, ecall3.verifier_size);

	__builtin_ia32_lfence();


	/* Call the trusted function. */
	ms->retn = add_verifier(&ecall3);
	status = SGX_SUCCESS;


 done:
	memset(ecall3.verifier, '\0', ecall3.verifier_size);
	free(ecall3.verifier);

	memset(&ecall3, '\0', sizeof(struct Possum_ecall3));

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
		{(void *)(uintptr_t)sgx_generate_identity, 0},
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
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0}
	}
};
