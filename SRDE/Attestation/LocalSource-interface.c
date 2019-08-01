/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Number of enclave interfaces. */
#define ECALL_NUMBER 1
#define OCALL_NUMBER 1


#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sgx_trts.h>
#include <sgx_edger8r.h>

#include <HurdLib.h>

#include "../SGX.h"
#include "LocalSource-interface.h"


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


/* Prototype definitions for enclave functions. */
extern _Bool verify_report(unsigned int, struct SGX_targetinfo *, \
			   struct SGX_report *);


/* ECALL 0 interface function. */
static sgx_status_t sgx_verify_report(void *args)

{
	sgx_status_t retn = SGX_SUCCESS;

	struct LocalSource_ecall0_interface *ms = \
		(struct LocalSource_ecall0_interface *) args;

	struct SGX_targetinfo target;

	struct SGX_report __attribute__((aligned(512))) report;


	/* Verify arguements. */
	CHECK_REF_POINTER(args, sizeof(struct LocalSource_ecall0_interface));
	CHECK_UNIQUE_POINTER(ms->target, sizeof(struct SGX_targetinfo));
	CHECK_UNIQUE_POINTER(ms->report, sizeof(struct SGX_report));


	/* Call enclave function and return result. */
	target = *ms->target;
	report = *ms->report;
	ms->retn = verify_report(ms->mode, &target, &report);
	*ms->target = target;
	*ms->report = report;

	return retn;
}


/* ECALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[ECALL_NUMBER];
} g_ecall_table = {
	ECALL_NUMBER,
	{
		{(void*)(uintptr_t)sgx_verify_report, 0}
	}
};


/* OCALL interface table. */
SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[OCALL_NUMBER][ECALL_NUMBER];
} g_dyn_entry_table = {
	OCALL_NUMBER,
	{
		{0},
	}
};
