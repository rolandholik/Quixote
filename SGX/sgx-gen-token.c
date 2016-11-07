#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"


/* Prototype for SGX bootstrap function. */
#define enter_enclave __morestack
extern int enter_enclave(struct SGX_tcs *, long fn, const void *, \
			 void *, void *);


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
static struct {
	int ms_retval;
	sgx_measurement_t *ms_mrenclave;
	sgx_measurement_t *ms_mrsigner;
	sgx_attributes_t *ms_se_attributes;
	struct SGX_einittoken *ms_lictoken;
} LE_ecall0_table;


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


	if (argc != 3) {
		fprintf(stderr, "%s: Specify enclave device node and "
			"Launch Enclave\n", argv[0]);
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


	/* Save the floating point processor state. */
	save_fp_state(xsave_buffer);

	/* Call into the enclave. */
	if ( !enclave->get_thread(enclave, (unsigned long int *) &tcs) )
		ERR(goto done);

	memset(&mrenclave, '\0', sizeof(sgx_measurement_t));
	memset(&mrsigner, '\0', sizeof(sgx_measurement_t));
	memset(&attributes, '\0', sizeof(sgx_attributes_t));
	memset(&token, '\0', sizeof(struct SGX_einittoken));

	LE_ecall0_table.ms_retval	 = 0;
	LE_ecall0_table.ms_mrenclave	 = &mrenclave;
	LE_ecall0_table.ms_mrsigner	 = &mrsigner;
	LE_ecall0_table.ms_se_attributes = &attributes;
	LE_ecall0_table.ms_lictoken	 = &token;

	rc = enter_enclave(tcs, 0, &LE_ocall_table, &LE_ecall0_table, \
			   thread_manager);
	fprintf(stdout, "Enclave returns: %d\n", rc);

	/* Restore the floating point state. */
	restore_fp_state(xsave_buffer);
	

 done:
	WHACK(enclave);

	return retn;
}
