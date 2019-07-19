/** \file
 * This file contains the API definitions for an object which generates
 * keyed digests based on SHA-256 message digesting.  It should be
 * included by an file which creates or manipulates these objects.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#ifndef NAAAIM_SHA256_hmac_HEADER
#define NAAAIM_SHA256_hmac_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SHA256_hmac * SHA256_hmac;

typedef struct NAAAIM_SHA256_hmac_State * SHA256_hmac_State;

/**
 * External SHA256_hmac object representation.
 */
struct NAAAIM_SHA256_hmac
{
	/* External methods. */
	_Bool (*add)(const SHA256_hmac, const unsigned char *, size_t);
	_Bool (*add_Buffer)(const SHA256_hmac, const Buffer);

	_Bool (*compute)(const SHA256_hmac);
	void (*reset)(const SHA256_hmac);

	unsigned char * (*get)(const SHA256_hmac);
	Buffer (*get_Buffer)(const SHA256_hmac);

	void (*print)(const SHA256_hmac);
	void (*whack)(const SHA256_hmac);

	/* Private state. */
	SHA256_hmac_State state;
};


/* SHA256_hmac constructor call. */
extern HCLINK SHA256_hmac NAAAIM_SHA256_hmac_Init(const Buffer);
#endif
