/** \file
 * This file contains interface definitions for the OCALL's that
 * are used by the SRDEnaaaim enclave library.
 *
 * This file is designed to be included by code from both untrusted
 * and enclave space.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Definitions of the OCALL function slots. */

/* CPUID interrogation. */
#define SRDENAAAIM_OCALL0	SRDEFUSION_MAX_OCALL+1

/* Duct manager. */
#define SRDENAAAIM_OCALL1	SRDENAAAIM_OCALL0+1

/* SRDEquote manager. */
#define SRDENAAAIM_OCALL2	SRDENAAAIM_OCALL1+1

#define SRDENAAAIM_MAX_OCALL	SRDENAAAIM_OCALL2


/**
 * This structure defines the interface used by SRDENAAAIM_OCALL0 to
 * convey a request for CPUI information to untrusted space with
 * conveyance of the information back into enclave context.
 */

struct SRDEnaaaim_ocall0_interface {
	int leaf;
	int subleaf;
	int *cpuinfo;
};


/**
 * Declaration for the function to populate SRDEnaaaim OCALL's.
 */
extern const void *SRDEnaaaim_ocall_table[];