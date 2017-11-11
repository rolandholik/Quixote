#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>

#include <sgx_edger8r.h>

#define SGX_CAST(type, item) ((type)(item))


/* ECALL interface definitions. */
struct ecall0_interface {
	char *update;
};

void update_model(char *);


/* OCALL interface definitions. */
#if 0
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
#endif

#endif
