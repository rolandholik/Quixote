/** \file
 * This file contains header definitions for the non-object code
 * implemented in the SGXfusion enclave library.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Prototype for the ENCLU[EREPORT] wrapper function. */
extern void enclu_ereport(struct SGX_targetinfo *, struct SGX_report *, \
			  char *);
