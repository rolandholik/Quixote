/** \file
 * This file contains the API definitions for an object which implements
 * encryption and decryption of Buffer objects using 256-bit AES
 * encryption using CBC mode.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_AES256_CBC_HEADER
#define NAAAIM_AES256_CBC_HEADER


/* Object type definitions. */
typedef struct NAAAIM_AES256_cbc * AES256_cbc;

typedef struct NAAAIM_AES256_cbc_State * AES256_cbc_State;

/**
 * External AES256_CBC object representation.
 */
struct NAAAIM_AES256_cbc
{
	/* External methods. */
	Buffer (*encrypt)(const AES256_cbc, const Buffer);
	Buffer (*decrypt)(const AES256_cbc, const Buffer);
	Buffer (*get_Buffer)(const AES256_cbc);
	void (*whack)(const AES256_cbc);

	/* Private state. */
	AES256_cbc_State state;
};


/* AES256_CBC constructor call. */
extern AES256_cbc NAAAIM_AES256_cbc_Init(void);
extern AES256_cbc NAAAIM_AES256_cbc_Init_encrypt(const Buffer, const Buffer);
extern AES256_cbc NAAAIM_AES256_cbc_Init_decrypt(const Buffer, const Buffer);
#endif