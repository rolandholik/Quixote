/** \file
 * This file implements the API definitions for an object that
 * generates enclave specific sealing keys.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SEALkey_HEADER
#define NAAAIM_SEALkey_HEADER


/** Definition for the SEALkey object. */
typedef struct NAAAIM_SEALkey * SEALkey;

/** Definition for the SEALkey object state. */
typedef struct NAAAIM_SEALkey_State * SEALkey_State;

/**
 * External SEALkey object representation.
 */
struct NAAAIM_SEALkey
{
	/* External methods. */
	_Bool (*generate_mrsigner)(const SEALkey);
	_Bool (*generate_mrenclave)(const SEALkey);
	_Bool (*generate_static_key)(const SEALkey, int, Buffer);

	_Bool (*get_iv_key)(const SEALkey, const Buffer, const Buffer);

	_Bool (*get_request)(const SEALkey, const Buffer);
	_Bool (*set_request)(const SEALkey, const Buffer);

	void (*print)(const SEALkey);
	void (*reset)(const SEALkey);
	void (*whack)(const SEALkey);

	/* Private state. */
	SEALkey_State state;
};


/* SEALkey constructor call. */
extern HCLINK SEALkey NAAAIM_SEALkey_Init(void);

#endif
