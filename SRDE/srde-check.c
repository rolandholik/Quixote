/** \file
 * This file implements a utility to check a platform for its ability
 * to implement Intel SGX secure enclaves.
 *
 * It first of all checks to see if the processor supports SGX
 * instructions.
 *
 * If this proves in the affirmative the IA32_FEATURE_CONTROL register
 * is read to determine whether or not the BIOS has implemented the
 * necessary platform setup to allow SGX enclaves to be created.
 *
 * If the previous test indicates the platform has implemented SGX
 * functionality the SGX leaf instructions are queried and the SGX
 * platform capabilities are queried and printed.
 *
 * Since reading or writing of MSR registers is a privileged operation
 * this utility must be run with sufficient privileges to allow the
 * MSR character devices to be read.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions local to this file. */
#define PGM "srde-check"


#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>


/**
 * Internal function.
 *
 * This function is used to read and print out the value of the SGX
 * identity modulus signature on a platform with unlocked launch control
 * registers.
 *
 * \param fd	The file descriptor that is to be used to do I/O to
 *		the MSR registers.
 *
 * \return	No return value is defined.
 */

static void print_launch_registers(int fd)

{
	unsigned int lp,
		     index = 0,
		     reg   = 0x8c;

	uint8_t *bp;

	uint64_t msr;


	fputs("\t\t", stdout);
	while ( index < 4 ) {
		if ( lseek(fd, reg, SEEK_SET) == -1 ) {
			fprintf(stderr, "Error seeking to LC register: %x\n", \
				reg);
			return;
		}
		if ( read(fd, &msr, sizeof(msr)) != sizeof(msr) ) {
			fprintf(stderr, "Error reading LC register; %x\n", \
				reg);
			return;
		}

		bp = (uint8_t *) &msr;
		for (lp= 0; lp < sizeof(msr); ++lp)
			fprintf(stdout, "%02x ", *bp++);

		++index;
		if ( (index == 1) || (index == 3) )
			fputs(": ", stdout);
		if ( index == 2 )
			fputs("\n\t\t", stdout);

		++reg;
	}


	fputc('\n', stdout);
	return;
}


/**
 * Internal function.
 *
 * This function is used to print out the bit positions which are set
 * in the supplied value.
 *
 * \param value		The value whose bit positions are to be printed.
 *
 * \return	No return value is defined.
 */

static void dump_bits(uint32_t value)

{
	uint16_t lp;


	for (lp= 0; lp < 32; ++lp) {
		if ( value & (1 << lp) )
			fprintf(stdout, "B%d ", lp);
	}
	fputc('\n', stdout);

	return;
}


/**
 * Internal function.
 *
 * This function outputs descriptions of the values which were loaded
 * into registers by the SGX leaf instruction 0.
 *
 * \param eax	The value which was returned in the EAX register.
 *
 * \param ebx	The value which was returned in the EBX register.
 *
 * \param ecx	The value which was returned in the ECX register.
 *
 * \param edx	The value which was returned in the EDX register.
 *
 * \return	No return value is defined.
 */

static void output_leaf0(uint32_t eax, uint32_t ebx, uint32_t ecx, \
			 uint32_t edx)
{
	uint32_t tmp;


	fputs("\tEAX:\n", stdout);
	fprintf(stdout, "\t\tSGX1 instructions: %s\n", \
		(eax & (1 << 0)) ? "yes" : "no");
	fprintf(stdout, "\t\tSGX2 instructions: %s\n", \
		(eax & (1 << 1)) ? "yes" : "no");
	eax = eax >> 2;
	fprintf(stdout, "\t\tReserved bits clear: %s\n", \
		(eax == 0) ? "yes" : "no");

	fputc('\n', stdout);
	fputs("\tEBX:\n\t\tMISCSELECT bits: ", stdout);
	if ( ebx == 0 )
		fputs("No bits set.\n", stdout);
	else
		dump_bits(ebx);

	fputc('\n', stdout);
	fputs("\tECX:\n", stdout);
	if ( ecx == 0 )
		fputs("\t\tReserved: No bits set.\n", stdout);
	else
		dump_bits(ecx);


	fputc('\n', stdout);
	fputs("\tEDX:\n", stdout);
	tmp = edx & 0xff;
	fprintf(stdout, "\t\t32-bit enclave maximum size: 0x%x / %u\n", \
		2U << tmp, 2U << tmp);
	tmp = edx >> 8;
	fprintf(stdout, "\t\t64-bit enclave maximum size: 0x%llx / %llu\n", \
		2ULL << tmp, 2ULL << tmp);
	edx >>= 16;
	if ( ecx == 0 )
		fputs("\t\tNo reserved bits set.\n", stdout);
	else
		dump_bits(edx);


	return;
}


/**
 * Internal function.
 *
 * This function outputs descriptions of the values which were loaded
 * into registers by the SGX leaf instruction 1.
 *
 * \param eax	The value which was returned in the EAX register.
 *
 * \param ebx	The value which was returned in the EBX register.
 *
 * \param ecx	The value which was returned in the ECX register.
 *
 * \param edx	The value which was returned in the EDX register.
 *
 * \return	No return value is defined.
 */


static void output_leaf1(uint32_t eax, uint32_t ebx, uint32_t ecx, \
			 uint32_t edx)
{
	fputs("\tEAX:\n", stdout);
	fputs("\t\tSEC.ATTRIBUTES   0-31: ", stdout);
	if ( eax == 0 )
		fputs("Not set.\n", stdout);
	else
		dump_bits(eax);

	fputs("\t\tSEC.ATTRIBUTES  32-63: ", stdout);
	if ( ebx == 0 )
		fputs("Not set.\n", stdout);
	else
		dump_bits(ebx);

	fputs("\t\tSEC.ATTRIBUTES  64-95: ", stdout);
	if ( ecx == 0 )
		fputs("Not set.\n", stdout);
	else
		dump_bits(ecx);

	fputs("\t\tSEC.ATTRIBUTES 96-127: ", stdout);
	if ( edx == 0 )
		fputs("Not set.\n", stdout);
	else
		dump_bits(edx);

	return;
}


/**
 * Internal function.
 *
 * This function is a driver function for generating the execution of
 * SGX leaf instructions 0 and 1.
 *
 * \param leaf	The leaf instruction which is to be executedc.
 *
 * \return	No return value is defined.
 */

static void output_sgx_leaf(uint32_t leaf)

{
	uint32_t eax,
		 ebx,
		 ecx,
		 edx;


	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x12), "r" (leaf)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");


	fprintf(stdout, "\nCPUID 12 Leaf %u:\n", leaf);
	switch ( leaf ) {
		case 0:
			output_leaf0(eax, ebx, ecx, edx);
			break;
		case 1:
			output_leaf1(eax, ebx, ecx, edx);
			break;
	}


	return;
}


/**
 * Internal function.
 *
 * This function is a driver function for executing and decoding SGX
 * leaf instruction 2.  There can be multiple implementations of the
 * leaf 2 instruction depending on the number of Enclave Page Cache
 * regions which are defined by the hardware.
 *
 * \param leaf	The subordinate leaf 2 instruction which is to be called.
 *
 * \return	The EAX register returns 0 if a subordinate leaf 2
 *		region has not been defined.  If this condition is
 *		detected this function returns a false value.
 */

static _Bool output_leaf2(uint32_t leaf)

{
        unsigned long long int mem;

	uint32_t eax,
		 ebx,
		 ecx,
		 edx;


	__asm("movl %4, %%eax\n\t"
	      "movl %5, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      "movl %%edx, %3\n\t"
	      /* Output. */
	      : "=r" (eax), "=r" (ebx), "=r" (ecx), "=r" (edx)
	      /* Input. */
	      : "r" (0x12), "r" (leaf)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	if ( eax == 0 )
		return false;


	fputs("\tEAX:\n", stdout);
	mem  = eax & 0xfffffffe;
	mem |= ebx >> 19;
	fprintf(stdout, "\t\tEPC physical address: 0x%0llx / %llu\n", mem, \
		mem);

	fputc('\n', stdout);
	fputs("\tECX:\n", stdout);
	mem  = ecx & 0xfffffffe;
	mem |= edx >> 19;
	fprintf(stdout, "\t\tEPC section size: 0x%0llx / %llu\n", mem, mem);


	return true;
}


/**
 * External function.
 *
 * This is the main entry point for the program.  This program does
 * not expect any arguements and returns success, a value of zero, if
 * SGX is demonstrated to be active on this platform.
 */

extern int main(int argc, char *argv[])

{
	int retn = 1;

	uint32_t lp;

	uint32_t eax_output,
		 ebx_output,
		 ecx_output;

	uint64_t msr_output = 0;

	int fd = -1;


	fprintf(stdout, "%s: SGX platform capability tester.\n", PGM);
	fprintf(stdout, "%s: Copyright(C) IDfusion, LLC.\n", PGM);


	/* Check CPUID leaf 7 for processor support. */
	__asm("movl %3, %%eax\n\t"
	      "xorl %%ecx, %%ecx\n\t"
	      "cpuid\n\t"
	      "movl %%eax, %0\n\t"
	      "movl %%ebx, %1\n\t"
	      "movl %%ecx, %2\n\t"
	      /* Output. */
	      : "=r" (eax_output), "=r" (ebx_output), "=r" (ecx_output)
	      /* Input. */
	      : "r" (7)
	      /* Clobbers. */
	      : "eax", "ebx", "ecx", "edx");

	fputc('\n', stdout);
	fputs("CPUID leaf 7:\n", stdout);
	fputs("\tSGX CPU support: ", stdout);
	if ( ebx_output & (1 << 2) )
		fputs("yes\n", stdout);
	else {
		fputs("no\n", stdout);
		goto done;
	}
	fputs("\tSGX launch control: ", stdout);
	if ( ecx_output & (1 << 30) )
		fputs("yes\n", stdout);
	else
		fputs("no\n", stdout);


	/* Read feature control register to check for BIOS support. */
	if ( (fd = open("/dev/cpu/0/msr", O_RDONLY)) == -1 ) {
		fputs("\nCannot open MSR register file.\n", stderr);
		goto done;
	}
	if ( lseek(fd, 0x3a, SEEK_SET) == -1 ) {
		fputs("\nMSR seek failed.\n", stderr);
		goto done;
	}
	if ( read(fd, &msr_output, sizeof(msr_output)) !=	\
		  sizeof(msr_output) ) {
		fputs("\nMSR read failed.\n", stderr);
		goto done;
	}

	fputc('\n', stdout);
	fputs("MSR feature control:\n", stdout);
	fprintf(stdout, "\tMSR locked: %s\n", \
		(msr_output & (1ULL << 0)) ? "yes" : "no");

	fprintf(stdout, "\tSGX global enable: %s\n", \
		(msr_output & (1ULL << 18)) ? "yes" : "no");
	if ( !(msr_output & (1ULL << 18)) )
		goto done;

	fputs("\tSGX unlocked identity modulus: ", stdout);
	if ( msr_output & (1ULL << 17) ) {
		fputs("yes\n", stdout);
		print_launch_registers(fd);
	} else
		fputs("no\n", stdout);


	/* Output SGX configuration information. */
	for (lp= 0; lp <= 2; ++lp)
		output_sgx_leaf(lp);

	/* Output Enclave Page Cache memory locations. */
	for (lp= 2; lp <= UINT32_MAX; ++lp)
		if ( output_leaf2(lp) == false)
			break;
	retn = 0;


 done:
	if ( fd != -1 )
		close(fd);

	return retn;
}
