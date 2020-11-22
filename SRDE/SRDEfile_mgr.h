/** \file
 * This file contains header definitions for the object manager that
 * maintains one copy of the standard userspace File object for
 * each instance of an object in an enclave.
 *
 * Unlike other manager objects this header file contains definitions
 * for the enumerated definitions of the OCALL's along with the
 * structure used to marshall arguements for the OCALL.  This is
 * secondary to the fact that currently the File object is a HurdLib
 * object rather then an NAAAIM object.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/**
 * Enumeration type which defines the method type whose userspace
 * implementation is being requested.
 */
enum File_ocalls {
	File_init,

	File_open_ro,
	File_open_rw,
	File_open_wo,

	File_read_Buffer,
	File_slurp,
	File_read_String,
	File_write_Buffer,

	File_seek,
	File_poisoned,
	File_whack,

	File_END
};


/**
 * Structure which marshalls the data for the OCALL from the enclave
 * to standard userspace that implements the desired File object
 * function.
 */
struct File_ocall {
	_Bool retn;

	enum File_ocalls ocall;
	unsigned int instance;

	off_t offset;

	size_t filename_size;
	char *filename;

	size_t bufr_size;
	uint8_t *bufr;

	uint8_t arena[];
};


extern int SRDEfile_mgr(struct File_ocall *);
