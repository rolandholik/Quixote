#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>


/* Number of enclave interfaces. */
#define ECALL_NUMBER 4
#define OCALL_NUMBER 5


/* ECALL interface definitions. */
struct Possum_ecall0 {
	_Bool retn;
	_Bool debug_mode;

	time_t current_time;

	int port;

	char *spid;
	size_t spid_size;

	unsigned char *identity;
	size_t identity_size;

	unsigned char *verifier;
	size_t verifier_size;
};

struct Possum_ecall1 {
	_Bool retn;
	_Bool debug_mode;

	time_t current_time;

	int port;

	char *hostname;
	size_t hostname_size;

	char *spid;
	size_t spid_size;

	unsigned char *identity;
	size_t identity_size;

	unsigned char *verifier;
	size_t verifier_size;
};

struct Possum_ecall2 {
	_Bool retn;

	uint8_t id[32];
};

struct Possum_ecall3 {
	_Bool retn;

	uint8_t *verifier;
	size_t verifier_size;
};


_Bool test_server(_Bool, unsigned int, time_t, char *, size_t, \
		  unsigned char *, size_t, unsigned char *);
_Bool test_client(_Bool, char *, int port, time_t, char *, size_t, \
		  unsigned char *, size_t, unsigned char *);
_Bool generate_identity(uint8_t *);
_Bool add_verifier(struct Possum_ecall3 *);
#endif
