/** \file
 * This file contains header definitions for the non-object code
 * implemented in the SGXfusion enclave library.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Prototype for the ENCLU[EREPORT] wrapper function. */
extern void enclu_ereport(struct SGX_targetinfo *, struct SGX_report *, \
			  char *);
extern int enclu_egetkey(struct SGX_keyrequest *, uint8_t *);
