#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sgx_trts.h>
#include <sgx_edger8r.h>

#include <HurdLib.h>

#include <NAAAIM.h>
#include "ISOmanager-interface.h"


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


/* Prototype definitions for enclave functions. */
extern _Bool connect(_Bool, char *, int, time_t, char *, size_t, \
		     unsigned char *,  size_t, unsigned char *);
extern _Bool generate_identity(uint8_t *);


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


/* ECALL 0 interface function. */
static sgx_status_t sgx_connect(void *pms)

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

	struct ISOmanager_ecall0 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct ISOmanager_ecall0)) )
		goto done;
	ms = (struct ISOmanager_ecall0 *) pms;

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

	if ( !SGXidf_untrusted_region(ms->verifier, ms->verifier_size) )
		goto done;
	if ( (verifier = malloc(ms->verifier_size)) == NULL ) {
		status = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	verifier_size = ms->verifier_size;
	memcpy(verifier, ms->verifier, verifier_size);

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ms->retn = connect(ms->debug_mode, hostname, port, current_time, \
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


/* ECALL 1 interface function. */
static sgx_status_t sgx_generate_identity(void *pms)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	uint8_t *id = NULL;

	struct ISOmanager_ecall1 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(pms, sizeof(struct ISOmanager_ecall1)) )
		goto done;
	ms = (struct ISOmanager_ecall1 *) pms;

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


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)sgx_connect, 0},
		{(void*)(uintptr_t)sgx_generate_identity, 0}
	}
};


/* OCALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}
	}
};
