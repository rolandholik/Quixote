/** \file
 * This file contains definitions for an object which implements
 * management of provisioning enclaves.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_PVEenclave_HEADER
#define NAAAIM_PVEenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PVEenclave * PVEenclave;

typedef struct NAAAIM_PVEenclave_State * PVEenclave_State;

/**
 * External PVEenclave object representation.
 */
struct NAAAIM_PVEenclave
{
	/* External methods. */
	_Bool (*open)(const PVEenclave, const char *);

	_Bool (*get_message1)(const PVEenclave, struct SGX_pek *pek, \
			   struct SGX_targetinfo *tgt, struct SGX_report *rpt);
	_Bool (*get_message3)(const PVEenclave, const SGXmessage,	 \
			      struct SGX_pek *, struct SGX_targetinfo *, \
			      const Buffer, struct SGX_platform_info *,	 \
			      struct SGX_message3 *);
	_Bool (*get_epid)(const PVEenclave, const SGXmessage, const SRDEepid);

	_Bool (*get_endpoint)(const PVEenclave);
	_Bool (*generate_endpoint_message)(const PVEenclave, const SGXmessage);

	void (*whack)(const PVEenclave);


	/* Private state. */
	PVEenclave_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK PVEenclave NAAAIM_PVEenclave_Init(void);
#endif
