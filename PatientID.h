/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_PatientID_HEADER
#define NAAAIM_PatientID_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PatientID * PatientID;

typedef struct NAAAIM_PatientID_State * PatientID_State;

/**
 * External PatientId object representation.
 */
struct NAAAIM_PatientID
{
	/* External methods. */
	_Bool (*create)(const PatientID, const OrgID, const char *, \
			const char *);
	Buffer (*get_Buffer)(const PatientID);
	void (*print)(const PatientID);
	void (*whack)(const PatientID);

	/* Private state. */
	PatientID_State state;
};


/* PatientId constructor call. */
extern PatientID NAAAIM_PatientID_Init(void);

#endif
