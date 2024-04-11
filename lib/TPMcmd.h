/** \file
 * This file contains the definitions for an object which executes
 * TPM commands and returns their results.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_TPMcmd_HEADER
#define NAAAIM_TPMcmd_HEADER


/* Object type definitions. */
typedef struct NAAAIM_TPMcmd * TPMcmd;

typedef struct NAAAIM_TPMcmd_State * TPMcmd_State;

/**
 * External TPMcmd object representation.
 */
struct NAAAIM_TPMcmd
{
	/* External methods. */
	_Bool (*pcr_read)(const TPMcmd, uint32_t, Buffer);
	_Bool (*pcr_extend)(const TPMcmd, uint32_t, Buffer);

	_Bool (*hash)(const TPMcmd, Buffer);

	_Bool (*nv_read)(const TPMcmd, uint32_t, Buffer);
	_Bool (*nv_write)(const TPMcmd, uint32_t, Buffer, _Bool, Buffer);
	_Bool (*nv_remove)(const TPMcmd, uint32_t, _Bool, Buffer);

	_Bool (*quote)(const TPMcmd, const Buffer, const Buffer);
	_Bool (*verify)(const TPMcmd, const Buffer, const Buffer, \
			const Buffer, const Buffer);
	_Bool (*generate_quote)(const TPMcmd, const Buffer, const Buffer);

	_Bool (*generate_identity)(const TPMcmd, _Bool, const Buffer, \
				   const Buffer, const Buffer, const Buffer);

	_Bool (*pcrmask)(const TPMcmd, ...);

	_Bool (*get_pubkey)(const TPMcmd, const Buffer, const Buffer);
	void (*list_keys)(const TPMcmd);

	void (*whack)(const TPMcmd);

	/* Private state. */
	TPMcmd_State state;
};


/* TPMcmd constructor call. */
extern HCLINK TPMcmd NAAAIM_TPMcmd_Init(void);
#endif
