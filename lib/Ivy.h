/** \file
 * This file contains method and interface definitions for an object
 * which manages the management of an identity verification object.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Ivy_HEADER
#define NAAAIM_Ivy_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Ivy * Ivy;

typedef struct NAAAIM_Ivy_State * Ivy_State;

typedef enum {
	Ivy_id,
	Ivy_pubkey,
	Ivy_software,
	Ivy_reference
} Ivy_element;


/**
 * External Ivy object representation.
 */
struct NAAAIM_Ivy
{
	/* External methods. */
	Buffer (*get_element)(const Ivy, const Ivy_element);
	_Bool (*set_element)(const Ivy, Ivy_element, const Buffer);
	_Bool (*set_identity)(const Ivy, const IDtoken);

	_Bool (*encode)(const Ivy, const Buffer);
	_Bool (*decode)(const Ivy, const Buffer);

	void (*print)(const Ivy);
	void (*reset)(const Ivy);
	void (*whack)(const Ivy);

	/* Private state. */
	Ivy_State state;
};


/* Ivy constructor call. */
extern HCLINK Ivy NAAAIM_Ivy_Init(void);
#endif
