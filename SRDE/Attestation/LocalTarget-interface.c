/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */

/* Number of enclave interfaces. */
#define ECALL_NUMBER 4
#define OCALL_NUMBER SRDENAAAIM_MAX_OCALL+1


/* Include files. */
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <sgx_trts.h>
#include <sgx_edger8r.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <SRDE.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>
#include <SRDEpipe.h>

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
extern _Bool test_attestation(struct LocalTarget_ecall1 *);
extern _Bool test_pipe(struct SRDEpipe_ecall *);
extern _Bool test_attestation_service(struct LocalTarget_ecall3 *);


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
static sgx_status_t sgx_test_attestation(void *ifp)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct LocalTarget_ecall1 *ip,
				  *ep,
				  ecall1;


	/* Verify interface structure pointer. */
	if ( !SGXidf_untrusted_region(ifp, sizeof(struct LocalTarget_ecall1)) )
		goto done;
	ip = (struct LocalTarget_ecall1 *) ifp;
	ep = &ecall1;
	memset(&ecall1, '\0', sizeof(struct LocalTarget_ecall1));

	ep->apikey	   = ip->apikey;
	ep->development	   = ip->development;
	ep->nonce	   = ip->nonce;
	ep->full_report	   = ip->full_report;

	ep->qe_token_size  = ip->qe_token_size;
	ep->pce_token_size = ip->pce_token_size;
	ep->epid_blob_size = ip->epid_blob_size;
	ep->spid_size	   = ip->spid_size;

	if ( ip->qe_token != NULL ) {
		if ( !SGXidf_untrusted_region(ip->qe_token, \
					      ep->qe_token_size) )
			goto done;
		if ( (ep->qe_token = malloc(ep->qe_token_size)) == NULL )
			goto done;
		memcpy(ep->qe_token, ip->qe_token, ep->qe_token_size);
	}

	if ( ip->pce_token != NULL ) {
		if ( !SGXidf_untrusted_region(ip->pce_token, \
					      ep->pce_token_size) )
			goto done;
		if ( (ep->pce_token = malloc(ep->pce_token_size)) == NULL )
			goto done;
		memcpy(ep->pce_token, ip->pce_token, ep->pce_token_size);
	}

	if ( ip->epid_blob != NULL ) {
		if ( !SGXidf_untrusted_region(ip->epid_blob, \
					      ep->epid_blob_size) )
			goto done;
		if ( (ep->epid_blob = malloc(ep->epid_blob_size)) == NULL )
			goto done;
		memcpy(ep->epid_blob, ip->epid_blob, ep->epid_blob_size);
	}

	if ( !SGXidf_untrusted_region(ip->spid, ep->spid_size) )
		goto done;
	if ( (ep->spid = malloc(ep->spid_size)) == NULL )
		ERR(goto done);
	memcpy(ep->spid, ip->spid, ep->spid_size);

	memcpy(ep->key, ip->key, sizeof(ep->key));

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ip->retn = test_attestation(ep);
	status = SGX_SUCCESS;


 done:
	memset(ep->qe_token, '\0', ep->qe_token_size);
	free(ep->qe_token);

	memset(ep->pce_token, '\0', ep->pce_token_size);
	free(ep->pce_token);

	memset(ep->epid_blob, '\0', ep->epid_blob_size);
	free(ep->epid_blob);

	memset(ep->spid, '\0', ep->spid_size);
	free(ep->spid);

	memset(ep, '\0', sizeof(struct LocalTarget_ecall1));

	return status;
}


static sgx_status_t sgx_test_pipe(void *ifp)

{
	sgx_status_t retn = SGX_ERROR_INVALID_PARAMETER;

	struct SRDEpipe_ecall *ip,
			      *ep,
			      ecall2;


	/* Verify interface structure pointer. */
	if ( !SGXidf_untrusted_region(ifp, sizeof(struct SRDEpipe_ecall)) )
		goto done;
	ip = (struct SRDEpipe_ecall *) ifp;
	ep = &ecall2;

	memset(ep, '\0', sizeof(struct SRDEpipe_ecall));
	ep->target    = ip->target;
	ep->report    = ip->report;
	ep->bufr_size = ip->bufr_size;

	/* Clone buffer to enclave context. */
	if ( ep->bufr_size > 0 ) {
		if ( !SGXidf_untrusted_region(ip->bufr, ep->bufr_size) )
			goto done;
		if ( (ep->bufr = malloc(ep->bufr_size)) == NULL ) {
			retn = SGX_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		memcpy(ep->bufr, ip->bufr, ep->bufr_size);
	}

	/* Call trusted function. */
	__builtin_ia32_lfence();

	ip->retn = test_pipe(ep);
	if ( ip->retn ) {
		retn = SGX_SUCCESS;
		ip->target    = ep->target;
		ip->report    = ep->report;
		ip->needed    = ep->needed;
		ip->bufr_size = ep->bufr_size;
		if ( ep->bufr_size > 0 )
			memcpy(ip->bufr, ep->bufr, ep->bufr_size);
	}


 done:
	if ( ep->bufr != NULL )
		memset(ep->bufr, '\0', ep->bufr_size);
	free(ep->bufr);

	memset(ep, '\0', sizeof(struct SRDEpipe_ecall));

	return retn;
}


/* ECALL 3 interface function. */
static sgx_status_t sgx_test_attestation_service(void *ifp)

{
	sgx_status_t retn = SGX_ERROR_INVALID_PARAMETER;

	struct LocalTarget_ecall3 *ip,
				  ecall;


	memset(&ecall, '\0', sizeof(struct LocalTarget_ecall3));

	if ( !SGXidf_untrusted_region(ifp, sizeof(struct LocalTarget_ecall3)) )
		goto done;
	ip = (struct LocalTarget_ecall3 *) ifp;

	__builtin_ia32_lfence();


	/* Call the trusted function. */
	ip->retn = test_attestation_service(&ecall);
	retn = SGX_SUCCESS;


 done:
	memset(&ecall, '\0', sizeof(struct LocalTarget_ecall3));

	return retn;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)sgx_get_report, 0},
		{(void*)(uintptr_t)sgx_test_attestation, 0},
		{(void *) sgx_test_pipe, 0},
		{(void *) sgx_test_attestation_service, 0}
	}
};


/* OCALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0}
	}
};
