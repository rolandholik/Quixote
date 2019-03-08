/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_IPsec_HEADER
#define NAAAIM_IPsec_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IPsec * IPsec;

typedef struct NAAAIM_IPsec_State * IPsec_State;

/**
 * External IPsec object representation.
 */
struct NAAAIM_IPsec
{
	/* External methods. */
	_Bool (*setup_sa)(const IPsec, const char *, const char *, int spi, \
			  const char *, const Buffer, const char *,	    \
			  const Buffer);
	_Bool (*setup_spd)(const IPsec, const char *, const char *, \
			   const char *, const char *, const char *);

	_Bool (*have_spi)(const IPsec, const uint32_t);
	_Bool (*poisoned)(const IPsec);
	void (*whack)(const IPsec);

	/* Private state. */
	IPsec_State state;
};


/* IPsec constructor call. */
extern IPsec NAAAIM_IPsec_Init(void);

#endif
