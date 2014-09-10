/** \file
 * This file contains the definitions for an object which executes
 * TPM commands and returns their results.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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

	void (*whack)(const TPMcmd);

	/* Private state. */
	TPMcmd_State state;
};


/* TPMcmd constructor call. */
extern TPMcmd NAAAIM_TPMcmd_Init(void);

#endif
