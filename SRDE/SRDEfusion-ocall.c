/** \file
 * This file contains the implementation of the untrusted OCALL
 * functions that are used by the SRDEfusion enclave library.
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

#include "SRDE.h"
#include "SRDEocall.h"
#include "SRDEfusion-ocall.h"


/**
 * Private function.
 *
 * This function implements the SRDEFUSION_OCALL0 that passes a
 * formatted character buffer to untrusted space for printing.
 *
 * \param ifp	A pointer to the OCALL interface structure.
 *
 * \return	A numeric value is returned to indicate the
 *		success or failure of the call.  A value of
 *		0 is used to indicate success which is the
 *		only currently defined value.
 */

static int SRDEfusion_ocall0(struct SRDEfusion_ocall0_interface *ifp)

{
	fprintf(stdout, "%s", ifp->buffer);
	fflush(stdout);
	return 0;
}


/**
 * Private function.
 *
 * This function implements the SRDEFUSION_OCALL1 that reads input
 * from untrusted space into a buffer that is returned to enclave
 * context for processing.
 *
 * \param ifp	A pointer to the OCALL interface structure.
 *
 * \return	A numeric value is returned to indicate the
 *		success or failure of the call.  A value of
 *		0 is used to indicate the buffer was successfully
 *		filled while a non-zero return code indicates
 *		that the returned buffer is not valid.
 */

static int SRDEfusion_ocall1(struct SRDEfusion_ocall1_interface *ifp)

{
	FILE *instream = NULL;


	/* Verify that standard input is the stream specification. */
	if ( ifp->stream == 3 )
		instream = stdin;
	else {
		fprintf(stderr, "%s: Bad stream number: %d", __func__, \
			ifp->stream);
		return 1;
	}


	/* Read the buffer contents. */
	if ( fgets(ifp->bufr, ifp->bufr_size, instream) != NULL )
		ifp->retn = true;

	return 0;
}


/**
 * Null terminated table of SRDEfusion ocall pointers.
 */
const void *SRDEfusion_ocall_table[3] = {
	SRDEfusion_ocall0,
	SRDEfusion_ocall1,
	NULL
};
