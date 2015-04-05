/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2009, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_RSAkey_HEADER
#define NAAAIM_RSAkey_HEADER


/* Object type definitions. */
typedef struct NAAAIM_RSAkey * RSAkey;

typedef struct NAAAIM_RSAkey_State * RSAkey_State;

/**
 * External RSAkey object representation.
 */
struct NAAAIM_RSAkey
{
	/* External methods. */
	_Bool (*load_public_key)(const RSAkey, const char *);
	_Bool (*load_private_key)(const RSAkey, const char *);
	_Bool (*encrypt)(const RSAkey, Buffer);
	_Bool (*decrypt)(const RSAkey, Buffer);
	int (*size)(const RSAkey);
	void (*print)(const RSAkey);
	void (*whack)(const RSAkey);

	/* Private state. */
	RSAkey_State state;
};


/* RSAkey constructor call. */
extern RSAkey NAAAIM_RSAkey_Init(void);

#endif
