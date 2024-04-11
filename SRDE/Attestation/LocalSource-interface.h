/** \file
 * This file contains interface definitions for the LocalTarget enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* ECALL interface definitions. */
struct LocalSource_ecall0_interface {
	_Bool retn;
	unsigned int mode;
	struct SGX_targetinfo *target;
	struct SGX_report *report;
};

struct LocalSource_ecall1 {
	_Bool retn;
};
