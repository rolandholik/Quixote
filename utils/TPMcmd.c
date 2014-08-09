/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <tss/tspi.h>

#include "NAAAIM.h"
#include "TPMcmd.h"

/* Object state extraction macro. */
#define STATE(var) CO(TPMcmd_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TPMcmd_OBJID)
#error Object identifier not defined.
#endif


/** TPMcmd private state information. */
struct NAAAIM_TPMcmd_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* TSPI api context. */
	TSS_HCONTEXT context;

	/* TPM context. */
	TSS_HTPM tpm;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TPMcmd_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TPMcmd_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TPMcmd_OBJID;

	S->poisoned = false;

	S->context  = 0;
	S->tpm	    = 0;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for setting up a TSPI and TPM context state.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static _Bool _init_tpm_state(CO(TPMcmd_State, S)) {

	_Bool retn = false;

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TPMcmd_OBJID;


	if ( Tspi_Context_Create(&S->context) != TSS_SUCCESS )
		goto done;
	if ( Tspi_Context_Connect(S->context, NULL) != TSS_SUCCESS )
		goto done;
	if ( Tspi_Context_GetTpmObject(S->context, &S->tpm) != TSS_SUCCESS)
		goto done;

	retn = true;

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements reading of a single platform configuration
 * register.
 *
 * \param this	A pointer to the object whose PCR is to be read.
 *
 * \param index	The index number of the register to be read.
 *
 * \param bufr	The Buffer object which the value of the register is
 *		to be loaded into.
 *
 * \return	If an error is encountered while reading the PCR
 *		register a false value is returned.  If a successful
 *		read occurs a true value is returned.
 */

static _Bool pcr_read(CO(TPMcmd, this), const uint32_t index, CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	unsigned char *output;


	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( Tspi_TPM_PcrRead(S->tpm, index, &length, &output) != TSS_SUCCESS )
		goto done;
	if ( !bufr->add(bufr, output, length) )
		goto done;

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS )
		goto done;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements extending the contents of a single platform
 * configuration register.
 *
 * \param this	A pointer to the object whose PCR is to be extended.
 *
 * \param index	The index number of the register to be extended.
 *
 * \param bufr	A Buffer object whose contents will be used to extend
 *		the register.
 *
 * \return	If an error is encountered while extending the PCR
 *		register a false value is returned.  If a successful
 *		read occurs a true value is returned.
 */

static _Bool pcr_extend(CO(TPMcmd, this), const uint32_t index, \
			CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	unsigned char *output;


	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( Tspi_TPM_PcrExtend(S->tpm, index, bufr->size(bufr), \
				bufr->get(bufr), NULL, &length,  \
				&output) != TSS_SUCCESS )
		goto done;

	bufr->reset(bufr);
	if ( !bufr->add(bufr, output, length) )
		goto done;

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS )
		goto done;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TPMcmd object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TPMcmd, this))

{
	STATE(S);

	Tspi_Context_FreeMemory(S->context, NULL);
	if ( S->context != 0 )
		Tspi_Context_Close(S->context);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a TPMcmd object.
 *
 * \return	A pointer to the initialized TPMcmd.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TPMcmd NAAAIM_TPMcmd_Init(void)

{
	auto Origin root;

	auto TPMcmd this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TPMcmd);
	retn.state_size   = sizeof(struct NAAAIM_TPMcmd_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TPMcmd_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize a TPM context. */
	_init_tpm_state(this->state);

	/* Method initialization. */
	this->pcr_read	 = pcr_read;
	this->pcr_extend = pcr_extend;

	this->whack = whack;

	return this;
}
