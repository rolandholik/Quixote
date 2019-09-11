/** \file
 * This file contains some of the implementations of the untrusted
 * OCALL functions that are used by the SRDEnaaaim enclave library.
 *
 * An external function is provided to that provides a method of
 * registering all of the available functions by an SRDEocall object.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include <HurdLib.h>

#include <NAAAIM.h>
#include <Buffer.h>
#include <String.h>
#include <Duct.h>

#include "SRDE.h"
#include "SRDEocall.h"
#include "SRDEquote.h"
#include "SRDEquote_mgr.h"
#include "SRDEnaaaim-ocall.h"


/**
 * Private subordinate function.
 *
 * This function is a helper function for the SRDEnaaaim_ocall0
 * function.  It providers a wrapper for the assembly call to
 * the CPUID function.
 *
 * \param eax	A pointer to the location that will be updated
 *		with the contents of the EAX register returned
 *		by the CPUID instruction.
 *
 * \param ebx	A pointer to the location that will be updated
 *		with the contents of the EBX register returned
 *		by the CPUID instruction.
 *
 * \param ecx	A pointer to the location that will be updated
 *		with the contents of the ECX register returned
 *		by the CPUID instruction.
 *
 * \param edx	A pointer to the location that will be updated
 *		with the contents of the EdX register returned
 *		by the CPUID instruction.
 */

static void _cpuid(int *eax, int *ebx, int *ecx, int *edx)

{
	__asm("cpuid\n\t"
	      /* Output. */
	      : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
	      /* Input. */
	      : "0" (*eax), "2" (*ecx));

	return;
}


/**
 * Private function.
 *
 * This function implements the SRDENAAAIM_OCALL0 that accepts a
 * structure containing a request for CPUID information from enclave
 * context and executes the appropriate leaf/sub-leaf calls in
 * order to fullfill the request that is returned to enclave
 * context
 *
 * \param ifp	A pointer to the OCALL interface structure.
 *
 * \return	A numeric value is returned to indicate the
 *		success or failure of the call.  A value of
 *		0 is used to indicate success which is the
 *		only currently defined value.
 */

int SRDEnaaaim_ocall0(struct SRDEnaaaim_ocall0_interface *ifp)

{
	struct SRDEnaaaim_ocall0_interface *ms = \
		(struct SRDEnaaaim_ocall0_interface *) ifp;


	ms->cpuinfo[0] = ms->leaf;
	ms->cpuinfo[2] = ms->subleaf;

	_cpuid(&ms->cpuinfo[0], &ms->cpuinfo[1], &ms->cpuinfo[2], \
	       &ms->cpuinfo[3]);

	return 0;
}


/**
 * Null terminated table of SRDEnaaaim ocall pointers.
 */
const void *SRDEnaaaim_ocall_table[4] = {
	SRDEnaaaim_ocall0,
	Duct_mgr,
	SRDEquote_mgr,
	NULL
};
