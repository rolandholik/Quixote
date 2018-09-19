/** \file
 * This file contains interface definitions for the ISOidentity
 * modelling enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Model selector definitions. */
#define ISO_IDENTITY_EVENT     	0
#define ISO_IDENTITY_FORENSICS	1
#define ISO_IDENTITY_CONTOURS	2


/* Number of enclave interfaces. */
#define ECALL_NUMBER 15
#define OCALL_NUMBER 6


/* ECALL interface definitions. */
struct ISOidentity_ecall0_interface {
	_Bool retn;
};

struct ISOidentity_ecall1_interface {
	_Bool retn;
	_Bool debug;

	_Bool discipline;
	char *update;
};

struct ISOidentity_ecall4_interface {
	int type;
	size_t size;
};

struct ISOidentity_ecall5_interface {
	_Bool retn;
	unsigned char *aggregate;
	size_t aggregate_length;
};

struct ISOidentity_ecall6_interface {
	_Bool retn;
	unsigned char measurement[NAAAIM_IDSIZE];
};

struct ISOidentity_ecall7_interface {
	_Bool retn;
	pid_t pid;
};

struct ISOidentity_ecall8_interface {
	int type;
};

struct ISOidentity_ecall9_interface {
	_Bool retn;
	int type;
	char event[512];
};

struct ISOidentity_ecall10_interface {
	_Bool retn;
	_Bool debug;

	time_t current_time;

	int port;

	char *spid;
	size_t spid_size;

	unsigned char *identity;
	size_t identity_size;
};

struct ISOidentity_ecall11_interface {
	_Bool retn;

	uint8_t id[32];
};

struct ISOidentity_ecall12_interface {
	_Bool retn;

	uint8_t point[32];
};

struct ISOidentity_ecall13 {
	_Bool retn;

	uint8_t *verifier;
	size_t verifier_size;
};

struct ISOidentity_ecall14 {
	_Bool retn;

	uint8_t *ai_event;
	size_t ai_event_size;
};
