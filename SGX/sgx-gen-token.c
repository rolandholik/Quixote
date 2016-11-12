#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "SGX.h"
#include "SGXenclave.h"
#include "SGXmetadata.h"


/* Prototype for SGX bootstrap function. */
#define enter_enclave __morestack

extern int enter_enclave(struct SGX_tcs *, long fn, const void *, \
			 void *, void *);


/**
 * The following array is an encoding of the Intel certificate white
 * list.  This white list is a requirement for operation of the Launch
 * Enclave.
 */
static uint8_t LE_white_list[] = {
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	0x65, 0x88, 0x08, 0x83, 0x92, 0xe7, 0x3d, 0x04, \
	0x9d, 0xf6, 0xce, 0xd6, 0xf2, 0xe6, 0x96, 0x31, \
	0x45, 0xe1, 0x89, 0xc0, 0x03, 0xfb, 0x3a, 0x74, \
	0x87, 0x0b, 0x20, 0xd3, 0x2a, 0xa8, 0xa4, 0xa1, \
	0x32, 0xcf, 0x58, 0x63, 0x6a, 0x63, 0xaf, 0xd6, \
	0x4b, 0xf9, 0x5c, 0x60, 0x77, 0x06, 0x9b, 0x62, \
	0x8c, 0x39, 0x75, 0xb6, 0x0d, 0x12, 0xe5, 0x5a, \
	0xd3, 0x3d, 0x9b, 0x99, 0x59, 0x90, 0xca, 0x6d, \
	0xb3, 0x28, 0x22, 0x71, 0xd3, 0x1e, 0xd1, 0x75, \
	0x28, 0xa6, 0xed, 0x89, 0x2f, 0x7a, 0xe7, 0x3a, \
	0x5c, 0xa1, 0xe1, 0xbd, 0xd1, 0xc9, 0xfc, 0xe9, \
	0xa0, 0xd3, 0x9d, 0x59, 0xc7, 0x01, 0x57, 0xe2, \
	0x8c, 0x96, 0x81, 0x98, 0x5e, 0x1e, 0x6d, 0x79, \
	0xeb, 0x00, 0x68, 0x4b, 0x20, 0x6b, 0xeb, 0x8a, \
	0x2f, 0xa2, 0xc4, 0x45, 0x20, 0xd5, 0xa8, 0xdf, \
	0x3e, 0x8e, 0x1f, 0x2e, 0x8f, 0x92, 0x98, 0xb6, \
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, \
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, \
	0xec, 0x15, 0xb1, 0x07, 0x87, 0xd2, 0xf8, 0x46, \
	0x67, 0xce, 0xb0, 0xb5, 0x98, 0xff, 0xc4, 0x4a, \
	0x1f, 0x1c, 0xb8, 0x0f, 0x67, 0x0a, 0xae, 0x5d, \
	0xf9, 0xe8, 0xfa, 0x9f, 0x63, 0x76, 0xe1, 0xf8, \
	0x4b, 0xe2, 0xaf, 0x03, 0x63, 0x66, 0xeb, 0xc4, \
	0x17, 0x6e, 0x70, 0xa5, 0x39, 0xf0, 0x04, 0x45, \
	0xd9, 0x05, 0x7d, 0x96, 0x04, 0xf8, 0xea, 0xd3, \
	0xe3, 0x23, 0xf3, 0x80, 0x4a, 0x11, 0xf9, 0xac, \
	0xf8, 0x7f, 0xd5, 0x6b, 0x93, 0x52, 0x93, 0xa1, \
	0xf4, 0x47, 0xfe, 0x58, 0x3d, 0x7b, 0x59, 0xbc, \
	0x46, 0xfe, 0xc2, 0xfb, 0xc2, 0x16, 0x3c, 0x51, \
	0x8f, 0x84, 0xa2, 0x74, 0x0f, 0x99, 0x3f, 0x52, \
	0xd0, 0xbe, 0x9a, 0x63, 0xbf, 0x39, 0xb3, 0x55, \
	0x81, 0x5d, 0xc2, 0xaa, 0x78, 0xfd, 0x3c, 0x75, \
	0x5b, 0xec, 0x1c, 0x3e, 0xfe, 0x04, 0x5a, 0xab, \
	0xbd, 0x0d, 0x66, 0x36, 0x37, 0x03, 0x45, 0x50  \
};


/**
 * The following defines an empty OCALL table since the Launch Enclave
 * does not support any outgoing calls.
 */
static const struct {
	size_t nr_ocall;
	void *table[1];
} LE_ocall_table = { 0, {NULL}};


/**
 * The following structure defines the API for the ECALL which carries
 * out the generation of an EINITTOKEN.
 */
static struct LE_ecall0_table {
	int ms_retval;
	sgx_measurement_t *ms_mrenclave;
	sgx_measurement_t *ms_mrsigner;
	sgx_attributes_t *ms_se_attributes;
	struct SGX_einittoken *ms_lictoken;
} ecall0_table;


/**
 * The following structure defines the API definition for the ECALL
 * which implements loading of the certificate white list.
 */
static struct LE_ecall1_table {
	uint32_t ms_retval;
	uint8_t *ms_wl_cert_chain;
	uint32_t ms_wl_cert_chain_size;
} ecall1_table;


static _Bool init_ecall0(char *enclave,
			 struct LE_ecall0_table *ecall,	\
			 sgx_attributes_t *attributes,	\
			 sgx_measurement_t *mrenclave,	\
			 sgx_measurement_t *mrsigner,	\
			 struct SGX_einittoken *token)

{
	_Bool retn = false;

	struct SGX_sigstruct sigstruct;

	SGXmetadata init_enclave = NULL;

	Buffer bufr = NULL;

	SHA256 sha256 = NULL;


	/* Buffer object for utility support. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));


	/* Get the attributes for an enclave to be signed. */
	INIT(NAAAIM, SGXmetadata, init_enclave, ERR(goto done));
	if ( !init_enclave->load(init_enclave, enclave) )
		ERR(goto done);
	if ( !init_enclave->compute_attributes(init_enclave, true) )
		ERR(goto done);
	if ( !init_enclave->get_attributes(init_enclave, attributes) )
		ERR(goto done);

	if ( !init_enclave->get_sigstruct(init_enclave, &sigstruct) )
		ERR(goto done);
	memcpy(mrenclave, sigstruct.enclave_hash, SGX_HASH_SIZE);


	/* Compute the hash of the signature modulus. */
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

	if ( !bufr->add(bufr, (unsigned char *) sigstruct.modulus, \
			sizeof(sigstruct.modulus)) )
		ERR(goto done);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	memcpy(mrsigner, sha256->get(sha256), SGX_HASH_SIZE);

	memset(token, '\0', sizeof(struct SGX_einittoken));

	ecall->ms_retval	  = 0;
	ecall->ms_mrenclave	  = mrenclave;
	ecall->ms_mrsigner	  = mrsigner;
	ecall->ms_se_attributes	  = attributes;
	ecall->ms_lictoken	  = token;

	retn = true;


 done:
	WHACK(bufr);
	WHACK(sha256);
	WHACK(init_enclave);

	return retn;
}


static void save_fp_state(uint8_t *save_area)

{
	uint8_t *save;

	uint32_t eax,
		 ebx,
		 ecx,
		 edx;

	uint64_t hardware_xfrm;


	/* Obtain the platform XFRM status. */
	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=R" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x0), "r" (0x1)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	if ( (ecx & (1UL << 26)) || (ecx & (1U << 27)) ) {
		/* Have XSAVE variant. */
		__asm("movl %2, %%ecx\n\t"
		      "xgetbv\n\t"
		      "movl %%eax, %0\n\t"
		      "movl %%edx, %1\n\t"
		      /* Output. */
		      : "=r" (ecx), "=r" (edx)
		      /* Input. */
		      : "r" (0x0)
		      /* Clobbers. */
		      : "eax", "ecx", "edx");
		hardware_xfrm = ((uint64_t) edx << 32ULL) | eax;
	}
	else
		hardware_xfrm = 0x3ULL;


	/* Flush floating point exceptions. */
	__asm("fwait");


	/* Save the floating point status in the supplied buffer. */
	save = (uint8_t *) (((size_t) save_area + (16-1)) & ~(16-1));
	__asm("fxsaveq (%0)\n\t"
	      /* Output. */
	      :
	      /* Input. */
	      : "r" (save)
	      /* Clobbers. */
	      : "memory");


	/* Clear the YMM registers if needed. */
	if ( hardware_xfrm & 0x4 )
		__asm("vzeroupper\n\t");

	return;
}


static void restore_fp_state(uint8_t *save_area)

{
	uint8_t *sp = (uint8_t *) (((size_t) save_area + (16-1)) & ~(16-1));


	__asm("fxsaveq (%0)\n\t"
	      /* Output. */
	      :
	      /* Input. */
	      : "r" (sp));

	return;
}


void push_ocall_frame(unsigned int *frame_ptr)

{
	return;
}


void pop_ocall_frame()

{
	return;
}

int sgx_ocall(unsigned int ocall_slot, void *ocall_table, void *ocall_data, \
	      void *thread)

{
	fprintf(stdout, "Ocall: %i\n", ocall_slot);
	return 0;
}

void thread_manager(void)

{
	fputs("Thread manager.\n", stdout);
	return;
}


static _Bool load_white_list(struct SGX_tcs *tcs)

{
	_Bool retn = true;

	uint8_t xsave_buffer[528];

	int rc;


	/* Save the floating point processor state. */
	save_fp_state(xsave_buffer);

	/* Call the enclave white list loader. */
	memset(&ecall1_table, '\0', sizeof(ecall1_table));
	ecall1_table.ms_wl_cert_chain	   = LE_white_list;
	ecall1_table.ms_wl_cert_chain_size = sizeof(LE_white_list);

	rc = enter_enclave(tcs, 1, &LE_ocall_table, &ecall1_table, \
			   thread_manager);
	if ( (rc != 0) || (ecall1_table.ms_retval != 0) )
		retn = false;

	/* Restore the floating point state. */
	restore_fp_state(xsave_buffer);

	return retn;
}

static uint64_t _cpu_info(void)

{
	uint32_t eax,
		 ebx,
		 ecx,
		 edx;

	uint64_t cpu_info = 0x00000001ULL;


	/* Determine if this is an Intel CPU. */
	__asm("movl %4, %%eax\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x0)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");
	if ( eax == 0 )
		return cpu_info;
	if ( !((ebx == 0x756e6547) && (ecx == 0x6c65746e) && \
	       (edx == 0x49656e69)) )
		return cpu_info;


	/*
	 * If this is an Intel processor and an enclave has been loaded
	 * assume a basic Skylake feature set.
	 */
	return 0xe9fffff;
}


static _Bool init_enclave(struct SGX_tcs *tcs)

{
	_Bool retn = true;

	int rc;

	uint8_t xsave_buffer[528];


	struct sgx_sdk_info {
		uint64_t cpu_features;
		int version;
	} info;


	/*
	 * Setup the CPU features which the enclave will assume.  An SGX
	 * version of 0 indicates conformance with the SGX 1.5.
	 */
	info.version	  = 0;
	info.cpu_features = _cpu_info();

	/* Save the floating point processor state. */
	save_fp_state(xsave_buffer);

	/* Call the enclave initialization slot. */
	rc = enter_enclave(tcs, -1, NULL, &info, thread_manager);
	if ( rc != 0 )
		retn = false;

	/* Restore the floating point state. */
	restore_fp_state(xsave_buffer);

	return retn;
}


extern int main(int argc, char *argv[])

{
	int rc,
	    retn = 1;

	uint8_t xsave_buffer[528];

	struct SGX_tcs *tcs = NULL;

	sgx_attributes_t attributes;

	sgx_measurement_t mrenclave,
			  mrsigner;

	struct SGX_einittoken token;

	SGXenclave enclave = NULL;


	if (argc != 4) {
		fprintf(stderr, "%s: Specify enclave device node, "
			"Launch Enclave and candidate enclave.\n", argv[0]);
		goto done;
	}


	/* Setup the Launch Enclave (LE) to generate an EINITTOKEN. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( !enclave->open_enclave(enclave, argv[1], argv[2], false) )
		ERR(goto done);
	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);
	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);
	if ( !enclave->init_launch_enclave(enclave) )
		ERR(goto done);


	/* Get the thread which will be executing the enclave. */
	if ( !enclave->get_thread(enclave, (unsigned long int *) &tcs) )
		ERR(goto done);

	/* Initialize the enclave for execution. */
	fputs("Initializing enclave.\n", stdout);
	if ( !init_enclave(tcs) )
		ERR(goto done);

	/* Load the white list. */
	fputs("Loading white list.\n", stdout);
	if ( !load_white_list(tcs) )
		ERR(goto done);

	/* Initialize the ecall table. */
	if ( !init_ecall0(argv[3], &ecall0_table, &attributes, &mrenclave, \
			  &mrsigner, &token) )
		ERR(goto done);

	/* Save the floating point processor state. */
	save_fp_state(xsave_buffer);

	fputs("Generating token.\n", stdout);
	rc = enter_enclave(tcs, 0, &LE_ocall_table, &ecall0_table, \
			   thread_manager);
	if ( (rc != 0) || (ecall0_table.ms_retval != 0) )
		retn = false;

	fputs("EINITTOKEN generated.\n", stdout);
	fprintf(stdout, "Token status: %u\n", token.valid);
	fputs("Attributes:\n", stdout);
	fprintf(stdout, "\tflags: 0x%lx\n", token.attributes.flags);
	fprintf(stdout, "\txfrm: 0x%lx\n", token.attributes.xfrm);
	fprintf(stdout, "isvsvnle: %u\n", token.isvsvnle);

	/* Restore the floating point state. */
	restore_fp_state(xsave_buffer);


 done:
	WHACK(enclave);

	return retn;
}
