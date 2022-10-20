/** \file
 * This file contains definitions for the TSEM security events and
 * characteristics.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

enum tsem_event_type {
	TSEM_UNDEFINED=0,
	TSEM_FILE_OPEN,
	TSEM_MMAP_FILE,
	TSEM_BPRM_SET_CREDS,
	TSEM_SOCKET_CREATE,
	TSEM_SOCKET_CONNECT,
	TSEM_SOCKET_BIND
};
