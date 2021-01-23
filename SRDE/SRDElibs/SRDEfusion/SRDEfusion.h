/** \file
 * This file contains header definitions for the non-object code
 * implemented in the SRDEfusion enclave library.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Prototype for the ENCLU[EREPORT] wrapper function. */
extern void enclu_ereport(struct SGX_targetinfo *, struct SGX_report *, \
			  char *);
extern int enclu_egetkey(struct SGX_keyrequest *, uint8_t *);


/* External definitions for IDfusion debug and production keys. */
extern const uint8_t Debug_key[32];
extern const uint8_t Production_key[32];
