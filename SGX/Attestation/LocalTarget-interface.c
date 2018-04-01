#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <sgx_trts.h>
#include <sgx_edger8r.h>

#include "../SGX.h"
#include "LocalTarget-interface.h"


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


/* Prototype definitions for enclave functions. */
extern _Bool get_report(unsigned int, struct SGX_targetinfo *, \
			struct SGX_report *);
extern _Bool test_attestation(char *, char *, char *, char *);


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
static sgx_status_t sgx_get_report(void *args)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct LocalTarget_ecall0_interface *ms = \
		(struct LocalTarget_ecall0_interface *) args;

	struct SGX_targetinfo target;

	struct SGX_report __attribute__((aligned(512))) report;


	/* Verify arguements. */
	CHECK_REF_POINTER(args, sizeof(struct LocalTarget_ecall0_interface));
	CHECK_UNIQUE_POINTER(ms->target, sizeof(struct SGX_targetinfo));
	CHECK_UNIQUE_POINTER(ms->report, sizeof(struct SGX_report));


	/* Call enclave function and return result. */
	target = *ms->target;
	report = *ms->report;
	ms->retn = get_report(ms->mode, &target, &report);
	*ms->target = target;
	*ms->report = report;

	return retn;
}


/* ECALL 1 interface function. */
static sgx_status_t sgx_test_attestation(void *arg)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	char *qe_token  = NULL,
	     *pce_token = NULL,
	     *epid_blob = NULL,
	     *spid	= NULL;

	struct LocalTarget_ecall1 *ms;


	/* Verify marshalled arguements and setup parameters. */
	if ( !SGXidf_untrusted_region(arg, sizeof(struct LocalTarget_ecall1)) )
		goto done;
	ms = (struct LocalTarget_ecall1 *) arg;

	if ( !SGXidf_untrusted_region(ms->qe_token, ms->qe_token_size) )
		goto done;
	if ( (qe_token = malloc(ms->qe_token_size)) == NULL )
		goto done;
	memcpy(qe_token, ms->qe_token, ms->qe_token_size);

	if ( !SGXidf_untrusted_region(ms->pce_token, ms->pce_token_size) )
		goto done;
	if ( (pce_token = malloc(ms->pce_token_size)) == NULL )
		goto done;
	memcpy(pce_token, ms->pce_token, ms->pce_token_size);

	if ( !SGXidf_untrusted_region(ms->epid_blob, ms->epid_blob_size) )
		goto done;
	if ( (epid_blob = malloc(ms->epid_blob_size)) == NULL )
		goto done;
	memcpy(epid_blob, ms->epid_blob, ms->epid_blob_size);

	if ( !SGXidf_untrusted_region(ms->spid, ms->spid_size) )
		goto done;
	if ( (spid = malloc(ms->spid_size)) == NULL )
		goto done;
	memcpy(spid, ms->spid, ms->spid_size);

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ms->retn = test_attestation(qe_token, pce_token, epid_blob, spid);
	status = SGX_SUCCESS;


 done:
	if ( qe_token != NULL )
		free(qe_token);
	if ( pce_token != NULL )
		free(pce_token);
	if ( epid_blob != NULL )
		free(epid_blob);

	return status;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)sgx_get_report, 0},
		{(void*)(uintptr_t)sgx_test_attestation, 0}
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
		{0, 0}
	}
};
