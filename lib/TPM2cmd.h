/** \file
 * This file contains the definitions for an object which executes
 * TPM2 commands and returns their results.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_TPM2cmd_HEADER
#define NAAAIM_TPM2cmd_HEADER


/* Object type definitions. */
typedef struct NAAAIM_TPM2cmd * TPM2cmd;

typedef struct NAAAIM_TPM2cmd_State * TPM2cmd_State;


/* Enumerated types to select hash algorithm type. */
typedef enum {
	TPM2cmd_sha1,
	TPM2cmd_sha256
} TPM2cmd_hash_type;


/**
 * External TPM2cmd object representation.
 */
struct NAAAIM_TPM2cmd
{
	/* External methods. */
	_Bool (*hash)(const TPM2cmd, Buffer);

	_Bool (*pcr_read)(const TPM2cmd, uint32_t, Buffer);
	_Bool (*pcr_extend)(const TPM2cmd, uint32_t, Buffer);

	_Bool (*nv_define)(const TPM2cmd, uint32_t, uint32_t, uint32_t, \
			   Buffer, Buffer);
	_Bool (*nv_read)(const TPM2cmd, uint32_t, Buffer);
	_Bool (*nv_write)(const TPM2cmd, uint32_t, Buffer, Buffer);

	_Bool (*nv_remove)(const TPM2cmd, uint32_t, Buffer);


#if 0
	_Bool (*quote)(const TPM2cmd, const Buffer, const Buffer);
	_Bool (*verify)(const TPM2cmd, const Buffer, const Buffer, \
			const Buffer, const Buffer);
	_Bool (*generate_quote)(const TPM2cmd, const Buffer, const Buffer);

	_Bool (*generate_identity)(const TPM2cmd, _Bool, const Buffer, \
				   const Buffer, const Buffer, const Buffer);

	_Bool (*pcrmask)(const TPM2cmd, ...);

	_Bool (*get_pubkey)(const TPM2cmd, const Buffer, const Buffer);
	void (*list_keys)(const TPM2cmd);
#endif
	_Bool (*get_time)(const TPM2cmd, uint64_t *, uint64_t *, uint32_t *, \
			  uint32_t *, _Bool *);

	_Bool (*set_hash)(const TPM2cmd, const TPM2cmd_hash_type);
	void (*get_error)(const TPM2cmd, uint32_t error);

	void (*whack)(const TPM2cmd);

	/* Private state. */
	TPM2cmd_State state;
};


/* TPM2cmd constructor call. */
extern HCLINK TPM2cmd NAAAIM_TPM2cmd_Init(void);
#endif
