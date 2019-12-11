/** \file
 * This file contains the ECALL interface routines for the SRDE
 * attestation service provider enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

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

#include "Attestation-interface.h"


/* Prototype definitions for enclave functions. */
extern _Bool provision_credentials(struct Attestation_ecall0 *);
extern _Bool generate_report(struct SRDEpipe_ecall *);


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
static sgx_status_t iface0_provision_credentials(void *ifp)

{
	sgx_status_t retn = SGX_ERROR_INVALID_PARAMETER;

	struct Attestation_ecall0 *ip,
				  *ep,
				  ecall0;


	/* Verify interface structure pointer. */
	if ( !SGXidf_untrusted_region(ifp, sizeof(struct Attestation_ecall0)) )
		goto done;

	memset(&ecall0, '\0', sizeof(struct Attestation_ecall0));
	ip = (struct Attestation_ecall0 *) ifp;
	ep = &ecall0;

	ep->current_time = ip->current_time;
	ep->key_size	 = ip->key_size;


	/* Clone key to enclave context. */
	if ( !SGXidf_untrusted_region(ip->key, ep->key_size) )
		goto done;
	if ( (ep->key = malloc(ep->key_size)) == NULL ) {
		retn = SGX_ERROR_OUT_OF_MEMORY;
		goto done;
	}
	memset(ep->key, '\0', ep->key_size);
	memcpy(ep->key, ip->key, ep->key_size);

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ip->retn = provision_credentials(ep);
	retn = SGX_SUCCESS;


 done:
	memset(ep->key, '\0', ep->key_size);
	memset(ep, '\0', sizeof(struct Attestation_ecall0));

	return retn;
}


/* ECALL 1 interface function. */
static sgx_status_t iface1_generate_report(void *ifp)

{
	sgx_status_t status = SGX_ERROR_INVALID_PARAMETER;

	struct SRDEpipe_ecall *ip,
			      *ep,
			      ecall;


	/* Verify interface structure pointer. */
	if ( !SGXidf_untrusted_region(ifp, sizeof(struct SRDEpipe_ecall)) )
		goto done;
	ip = (struct SRDEpipe_ecall *) ifp;
	ep = &ecall;
	memset(&ecall, '\0', sizeof(struct SRDEpipe_ecall));

	__builtin_ia32_lfence();


	/* Call trusted function. */
	ip->retn = generate_report(ep);
	status = SGX_SUCCESS;


 done:
	memset(ep, '\0', sizeof(struct SRDEpipe_ecall));

	return status;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)iface0_provision_credentials, 0},
		{(void*)(uintptr_t)iface1_generate_report, 0}
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
		{0, 0},
		{0, 0},
		{0, 0}
	}
};
