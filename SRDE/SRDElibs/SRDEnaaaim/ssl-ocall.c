/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <sgx_edger8r.h>
#include <sgx_trts.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>


#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;

	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	struct SRDEnaaaim_ocall0_interface *ms = NULL;

	size_t ocalloc_size = sizeof(struct SRDEnaaaim_ocall0_interface);

	void *__tmp = NULL;


	ocalloc_size += (cpuinfo != NULL && \
			 sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? \
		_len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	ms = (struct SRDEnaaaim_ocall0_interface *) __tmp;
	__tmp = (void *)((size_t)__tmp + \
			 sizeof(struct SRDEnaaaim_ocall0_interface));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ms->leaf    = leaf;
	ms->subleaf = subleaf;
	status = sgx_ocall(SRDENAAAIM_OCALL0, ms);

	if (cpuinfo)
		memcpy((void*) cpuinfo, ms->cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}
