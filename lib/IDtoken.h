/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_IDtoken_HEADER
#define NAAAIM_IDtoken_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IDtoken * IDtoken;

typedef struct NAAAIM_IDtoken_State * IDtoken_State;

typedef enum {
	IDtoken_orgkey,
	IDtoken_orgid,
	IDtoken_id,
	IDtoken_key
} IDtoken_element;


/**
 * External IDtoken object representation.
 */
struct NAAAIM_IDtoken
{
	/* External methods. */
	Buffer (*get_element)(const IDtoken, IDtoken_element);
	_Bool (*set_element)(const IDtoken, IDtoken_element, const Buffer);

	_Bool (*encode)(const IDtoken, const Buffer);
	_Bool (*decode)(const IDtoken, const Buffer);

	_Bool (*to_verifier)(const IDtoken);

	_Bool (*parse)(const IDtoken, FILE *);
	_Bool (*matches)(const IDtoken, const Buffer);
	void (*print)(const IDtoken);

	void (*reset)(const IDtoken);
	void (*whack)(const IDtoken);

	/* Private state. */
	IDtoken_State state;
};


/* IDtoken constructor call. */
extern IDtoken NAAAIM_IDtoken_Init(void);

#endif
