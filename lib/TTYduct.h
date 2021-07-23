/** \file
 * This file contains the header definitions for the TTYduct object
 * which implements a packet based interface for I/O over a serial
 * tty device.
 */

#ifndef NAAAIM_TTYduct_HEADER
#define NAAAIM_TTYduct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_TTYduct * TTYduct;

typedef struct NAAAIM_TTYduct_State * TTYduct_State;

/**
 * External LocalDuct object representation.
 */
struct NAAAIM_TTYduct
{
	/* External methods. */
	_Bool (*init_device)(const TTYduct, const char *);
	_Bool (*accept_connection)(const TTYduct);

	_Bool (*send_Buffer)(const TTYduct, const Buffer);
	_Bool (*receive_Buffer)(const TTYduct, const Buffer);

	_Bool (*terminal)(const TTYduct);

	void (*whack)(const TTYduct);

	/* Private state. */
	TTYduct_State state;
};


/* LocalDuct constructor call. */
extern HCLINK TTYduct NAAAIM_TTYduct_Init(void);
#endif
