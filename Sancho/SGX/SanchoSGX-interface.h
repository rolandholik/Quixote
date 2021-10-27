/** \file
 * This file contains interface definitions for the ISOidentity
 * modelling enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Model selector definitions. */
#define ISO_IDENTITY_EVENT     	0
#define ISO_IDENTITY_FORENSICS	1
#define DOMAIN_POINTS		2
#define TE_EVENTS		3


/* Security state measurement definitions. */
#define DOMAIN_MEASUREMENT 0
#define DOMAIN_STATE	   1


/* Number of enclave interfaces. */
#define ECALL_NUMBER 16
#define OCALL_NUMBER 3 + 5 + 1


/* ECALL interface definitions. */
struct ISOidentity_ecall0_interface {
	_Bool retn;
	_Bool init;
};

struct ISOidentity_ecall1_interface {
	_Bool retn;
	_Bool debug;

	_Bool discipline;
	_Bool sealed;
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
	int type;
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

struct SanchoSGX_ecall15 {
	_Bool retn;

	uint8_t point[NAAAIM_IDSIZE];
};


/**
 * Enumeration type which defines the userspace action being requested.
 */
enum SanchoSGX_ocalls {
	SanchoSGX_discipline,
	SanchoSGX_END
};


/**
 * Structure which marshalls the data for the call into and out of
 * the the SanchoSGX ocall.
 */
struct SanchoSGX_ocall {
	_Bool retn;
	_Bool debug;

	enum SanchoSGX_ocalls ocall;

	pid_t pid;
	_Bool discipline;
};
