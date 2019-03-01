/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Authenticator_HEADER
#define NAAAIM_Authenticator_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Authenticator * Authenticator;

typedef struct NAAAIM_Authenticator_State * Authenticator_State;

/**
 * External Authenticator object representation.
 */
struct NAAAIM_Authenticator
{
	/* External methods. */
	_Bool (*add_identity)(const Authenticator, const IDtoken);
	_Bool (*get_identity)(const Authenticator, const IDtoken);
	_Bool (*add_element)(const Authenticator, const Buffer);
	_Bool (*get_element)(const Authenticator, const Buffer);
	_Bool (*encrypt)(const Authenticator, const char *);
	_Bool (*decrypt)(const Authenticator, const char *);
	_Bool (*encode)(const Authenticator, const Buffer);
	_Bool (*decode)(const Authenticator, const Buffer);
	void (*print)(const Authenticator);
	void (*reset)(const Authenticator);
	void (*whack)(const Authenticator);

	/* Private state. */
	Authenticator_State state;
};


/* Authenticator constructor call. */
extern Authenticator NAAAIM_Authenticator_Init(void);

#endif
