#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>

#include <sgx_edger8r.h>


/* Number of interfaces. */
#define ECALL_NUMBER 5
#define OCALL_NUMBER 1


/* ECALL0 interface definitions. */
struct ecall0_interface {
	_Bool retn;
};

_Bool init_model(void);


/* ECALL1 interface definitions. */
struct ecall1_interface {
	_Bool retn;
	char *update;
};

_Bool update_model(char *);


/* ECALL2 interface definition. */
void seal_model(void);


/* ECALL3 interface definitions. */
void dump_model(void);


/* ECALL4 interface to return model size. */
size_t get_size(int);

struct ecall4_interface {
	int type;
	size_t size;
};


/* OCALL interface definitions. */
#if 0
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
#endif
