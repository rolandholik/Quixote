/** \file
 * This file contains interface definitions for the LocalTarget enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 1
#define OCALL_NUMBER 1


/* ECALL interface definitions. */
struct LocalSource_ecall0_interface {
	_Bool retn;
	struct SGX_report *report;
};
