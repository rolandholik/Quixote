#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>


/* Number of enclave interfaces. */
#define ECALL_NUMBER 2
#define OCALL_NUMBER 4


/* ECALL interface definitions. */
struct Possum_ecall0 {
	_Bool retn;

	int port;

	char *spid;
	size_t spid_size;
};

struct Possum_ecall1 {
	_Bool retn;

	int port;

	char *hostname;
	size_t hostname_size;

	char *spid;
	size_t spid_size;
};


_Bool test_server(unsigned int, char *);
_Bool test_client(char *, int port, char *);
#endif
